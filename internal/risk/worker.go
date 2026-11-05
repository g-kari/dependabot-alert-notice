package risk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/scoring"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// SettingsSource supplies detached snapshots and a short commit-time guard.
type SettingsSource interface {
	Snapshot() (config.Snapshot, error)
	WithRevision(uint64, func() error) error
	Changes() <-chan struct{}
}

// Worker coordinates local recalculation without external communication.
type Worker struct {
	Store    *store.Store
	Settings SettingsSource
	Now      func() time.Time
	mu       sync.Mutex
	cache    map[string]cachedEvaluation
	Interval time.Duration
	runMu    sync.Mutex
}

type cachedEvaluation struct{ repo, advisory, hash string }
type groupedEvaluation struct {
	repo, advisory string
	input          model.ScoreInput
	result         model.ScoreResult
	members        []string
}

// NewWorker binds the recalculation worker to persisted inputs and settings.
func NewWorker(s *store.Store, settings SettingsSource) *Worker {
	return &Worker{Store: s, Settings: settings, Now: time.Now}
}

// RefreshOnce recalculates a frozen generation and awaits persistence.
func (w *Worker) RefreshOnce(ctx context.Context) error {
	return w.refresh(ctx, store.RiskScope{All: true})
}

// Run processes startup, input changes and expiry checks until cancellation.
func (w *Worker) Run(ctx context.Context) error {
	if !w.runMu.TryLock() {
		return fmt.Errorf("緊急度ワーカーは実行中です")
	}
	defer w.runMu.Unlock()
	changes, unsubscribe := w.Store.SubscribeRiskChanges()
	defer unsubscribe()
	settingsChanged := w.Settings.Changes()
	interval := w.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	retry := time.NewTimer(time.Hour)
	if !retry.Stop() {
		<-retry.C
	}
	defer retry.Stop()
	var retryC <-chan time.Time
	scope := store.RiskScope{All: true}
	for {
		// Drain and combine bursts before reading a frozen input generation.
	drain:
		for {
			select {
			case <-ctx.Done():
				return nil
			case change := <-changes:
				scope = mergeScope(scope, change)
			case <-settingsChanged:
				scope = store.RiskScope{All: true}
			default:
				break drain
			}
		}
		if err := w.refresh(ctx, scope); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, store.ErrRiskInputsChanged) {
				slog.Debug("緊急度入力変更のため再計算", "error", err)
			} else {
				slog.Error("緊急度再計算失敗", "error", err)
			}
			scope = store.RiskScope{All: true}
			retry.Reset(time.Second)
			retryC = retry.C
		} else {
			scope = store.RiskScope{}
			retryC = nil
			retry.Stop()
		}
		select {
		case <-ctx.Done():
			return nil
		case change := <-changes:
			scope = mergeScope(scope, change)
		case <-settingsChanged:
			scope = store.RiskScope{All: true}
		case <-ticker.C:
			scope = store.RiskScope{All: true}
		case <-retryC:
			scope = store.RiskScope{All: true}
		}
	}
}

func mergeScope(a, b store.RiskScope) store.RiskScope {
	if a.All || b.All {
		return store.RiskScope{All: true}
	}
	unique := func(a, b []string) []string {
		seen := map[string]bool{}
		out := make([]string, 0, len(a)+len(b))
		for _, value := range append(a, b...) {
			key := strings.ToLower(value)
			if !seen[key] {
				seen[key] = true
				out = append(out, value)
			}
		}
		return out
	}
	return store.RiskScope{Repos: unique(a.Repos, b.Repos), Advisories: unique(a.Advisories, b.Advisories)}
}

func (w *Worker) refresh(ctx context.Context, scope store.RiskScope) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("緊急度再計算取消: %w", err)
	}
	snapshot, err := w.Settings.Snapshot()
	if err != nil {
		return fmt.Errorf("緊急度設定取得: %w", err)
	}
	revision := w.Store.RiskRevision()
	clock := w.Now
	if clock == nil {
		clock = time.Now
	}
	at := clock().UTC()
	zone := snapshot.Config.BusinessCalendar.Timezone
	if zone == "" {
		zone = "Asia/Tokyo"
	}
	location, err := time.LoadLocation(zone)
	if err != nil {
		return fmt.Errorf("対応期限タイムゾーン: %w", err)
	}
	calendar := scoring.BusinessCalendar{Location: location, Holidays: map[string]bool{}}
	for _, date := range snapshot.Config.BusinessCalendar.Holidays {
		calendar.Holidays[date] = true
	}
	var profiles []model.ServiceProfile
	for _, profile := range snapshot.Config.ServiceProfiles {
		resolved, err := snapshot.Config.ResolveProfile(profile.ID)
		if err != nil {
			return fmt.Errorf("緊急度プロファイル解決: %w", err)
		}
		profiles = append(profiles, resolved)
	}
	groups := map[string]*groupedEvaluation{}
	profileRepositories := map[string]string{}
	for cursor := 0; ; {
		records, err := w.Store.ListRiskInputs(ctx, scope, cursor, 300)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			break
		}
		keys := make([]string, 0, len(records))
		for _, rec := range records {
			keys = append(keys, model.AdvisoryKey(rec.Alert))
		}
		threats, err := w.Store.ListThreatSnapshotsFor(ctx, keys)
		if err != nil {
			return fmt.Errorf("緊急度脅威情報取得: %w", err)
		}
		for _, rec := range records {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("緊急度集約取消: %w", err)
			}
			cursor = rec.Alert.ID
			if !policy.IsMonitored(snapshot.Config.Targets, rec.Alert.Owner, rec.Alert.Repo) {
				continue
			}
			repo := strings.ToLower(rec.Alert.Owner + "/" + rec.Alert.Repo)
			advisory := model.AdvisoryKey(rec.Alert)
			var matching []model.ServiceProfile
			for _, profile := range profiles {
				if strings.EqualFold(profile.Owner, rec.Alert.Owner) && (profile.Repo == "" || strings.EqualFold(profile.Repo, rec.Alert.Repo)) {
					matching = append(matching, profile)
				}
			}
			if len(matching) == 0 {
				matching = append(matching, model.ServiceProfile{ID: "unconfigured:" + repo, Owner: rec.Alert.Owner, Repo: rec.Alert.Repo})
			}
			for _, profile := range matching {
				input := InputForAlert(profile, snapshot.Config.Assessments, threats, rec, at)
				if previous, ok := profileRepositories[input.Profile.ID]; ok && previous != repo {
					return fmt.Errorf("実効プロファイルIDが複数リポジトリへ衝突: %s", input.Profile.ID)
				}
				profileRepositories[input.Profile.ID] = repo
				result, err := scoring.Calculate(input)
				if err != nil {
					return fmt.Errorf("緊急度算出 (%s/%s): %w", repo, profile.ID, err)
				}
				key := repo + "\x00" + advisory + "\x00" + profile.ID
				group := groups[key]
				if group == nil {
					group = &groupedEvaluation{repo: repo, advisory: advisory, input: input, result: result}
					groups[key] = group
				} else if worse(result, group.result) {
					group.input, group.result = input, result
				}
				group.members = append(group.members, fmt.Sprintf("%d:%s", rec.Alert.ID, rec.NotifiedAt.UTC().Format(time.RFC3339Nano)))
			}
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	nextCache := make(map[string]cachedEvaluation, len(w.cache)+len(groups))
	for key, cached := range w.cache {
		if !scopeMatches(scope, cached) {
			nextCache[key] = cached
		}
	}
	for _, key := range keys {
		group := groups[key]
		hash, err := semanticHash(group.input, group.result)
		if err != nil {
			return err
		}
		// Membership detects a close/reopen even when the score is unchanged.
		body, err := json.Marshal(struct {
			Hash     string
			Members  []string
			Calendar config.BusinessCalendar
		}{hash, group.members, snapshot.Config.BusinessCalendar})
		if err != nil {
			return fmt.Errorf("緊急度キャッシュ作成: %w", err)
		}
		sum := sha256.Sum256(body)
		cacheHash := hex.EncodeToString(sum[:])
		if previous, ok := w.cache[key]; !ok || previous.hash != cacheHash {
			due := scoring.Deadline(nil, group.result, at, calendar)
			if err := w.Settings.WithRevision(snapshot.Revision, func() error {
				_, err := w.Store.SaveRiskEvaluationAtRevision(ctx, revision, group.input.Profile.ID, group.repo, group.advisory, hash, group.input, group.result, due, false)
				return err
			}); err != nil {
				return fmt.Errorf("緊急度評価保存: %w", err)
			}
		}
		nextCache[key] = cachedEvaluation{repo: group.repo, advisory: group.advisory, hash: cacheHash}
	}
	if err := w.Settings.WithRevision(snapshot.Revision, func() error { return w.Store.CheckRiskRevision(ctx, revision) }); err != nil {
		return fmt.Errorf("緊急度世代確認: %w", err)
	}
	w.cache = nextCache
	return nil
}

func scopeMatches(scope store.RiskScope, cached cachedEvaluation) bool {
	if scope.All {
		return true
	}
	for _, repo := range scope.Repos {
		if strings.EqualFold(repo, cached.repo) {
			return true
		}
	}
	for _, key := range scope.Advisories {
		if strings.EqualFold(key, cached.advisory) {
			return true
		}
	}
	return false
}

func worse(candidate, previous model.ScoreResult) bool {
	active := func(r model.ScoreResult) bool { return r.Status != "not_affected" && r.Status != "mitigated" }
	if active(candidate) != active(previous) {
		return active(candidate)
	}
	if candidate.Upper != previous.Upper {
		return candidate.Upper > previous.Upper
	}
	return candidate.Priority == "incident" && previous.Priority != "incident"
}

// InputForAlert constructs the same frozen scoring input for UI and workers.
func InputForAlert(profile model.ServiceProfile, assessments []model.CVEAssessment, threats map[string]model.ThreatSnapshot, rec *model.AlertRecord, at time.Time) model.ScoreInput {
	key := model.AdvisoryKey(rec.Alert)
	a := model.CVEAssessment{ProfileID: profile.ID, AdvisoryKey: key, Applicability: "unknown", Reachability: "unknown"}
	for _, candidate := range assessments {
		if candidate.ProfileID == profile.ID && strings.EqualFold(candidate.AdvisoryKey, key) && (candidate.Repo == "" || strings.EqualFold(candidate.Repo, rec.Alert.Owner+"/"+rec.Alert.Repo)) {
			a = candidate
			break
		}
	}
	// Legacy owner-wide profiles expand into repository-bound effective IDs.
	// Keep Assessment.ProfileID as provenance of the original configuration.
	if strings.TrimSpace(profile.Repo) == "" {
		profile.ID += "@" + strings.ToLower(rec.Alert.Owner+"/"+rec.Alert.Repo)
		profile.Repo = rec.Alert.Repo
	}
	threat := model.ThreatSnapshot{AdvisoryKey: key}
	if snap, ok := threats[key]; ok {
		threat = snap
	}
	known := rec.Alert.CVSSKnown || rec.Alert.CVSSScore > 0
	return model.ScoreInput{At: at, Profile: profile, Assessment: a, Threat: threat, Technical: scoring.NormalizeCVSS(rec.Alert.CVSSScore, known, rec.Alert.CVSSVersion, rec.Alert.CVSSVector), CVSS: rec.Alert.CVSSScore, CVSSKnown: known}
}
