package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// dashboardPageSize はダッシュボード1ページあたりの表示グループ数
const dashboardPageSize = 25

var errEvaluationBusy = errors.New("このアラートは評価中です")

// PaginationInfo はページネーション情報を保持する
type PaginationInfo struct {
	Page       int
	TotalPages int
	TotalItems int
	PageSize   int
}

// HasPrev は前のページが存在するか返す
func (p PaginationInfo) HasPrev() bool { return p.Page > 1 }

// HasNext は次のページが存在するか返す
func (p PaginationInfo) HasNext() bool { return p.Page < p.TotalPages }

// Prev は前ページ番号を返す
func (p PaginationInfo) Prev() int { return p.Page - 1 }

// Next は次ページ番号を返す
func (p PaginationInfo) Next() int { return p.Page + 1 }

// paginateCVE はCVEグループスライスをページ単位に切り出す
func paginateCVE(groups []CVEGroup, page int) ([]CVEGroup, PaginationInfo) {
	total := len(groups)
	totalPages := (total + dashboardPageSize - 1) / dashboardPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * dashboardPageSize
	end := start + dashboardPageSize
	if end > total {
		end = total
	}
	return groups[start:end], PaginationInfo{Page: page, TotalPages: totalPages, TotalItems: total, PageSize: dashboardPageSize}
}

// paginateRepo はRepoグループスライスをページ単位に切り出す
func paginateRepo(groups []RepoGroup, page int) ([]RepoGroup, PaginationInfo) {
	total := len(groups)
	totalPages := (total + dashboardPageSize - 1) / dashboardPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * dashboardPageSize
	end := start + dashboardPageSize
	if end > total {
		end = total
	}
	return groups[start:end], PaginationInfo{Page: page, TotalPages: totalPages, TotalItems: total, PageSize: dashboardPageSize}
}

// CVEGroup はCVE ID（またはGHSA ID）単位でアラートをまとめたグループ
type CVEGroup struct {
	CVEID       string
	GHSAID      string
	Summary     string
	Severity    model.Severity
	PackageName string
	CVSSScore   float64
	Records     []*model.AlertRecord
}

// RepoGroup はリポジトリ単位でアラートをまとめたグループ
type RepoGroup struct {
	Owner         string
	Repo          string
	DefaultBranch string
	MaxSeverity   model.Severity
	MaxCVSS       float64
	Records       []*model.AlertRecord
}

// groupByRepo はAlertRecordのリストをリポジトリ単位でグルーピングする。
// グループはMaxSeverity降順 → MaxCVSS降順でソートされる。
// グループ内のRecordsはCreatedAt降順でソートされる。
func groupByRepo(records []*model.AlertRecord) []RepoGroup {
	if len(records) == 0 {
		return []RepoGroup{}
	}

	type groupKey = string
	groupMap := make(map[groupKey]*RepoGroup)
	var keys []string

	for _, r := range records {
		key := r.Alert.Owner + "/" + r.Alert.Repo
		if g, ok := groupMap[key]; ok {
			g.Records = append(g.Records, r)
			if severityOrder[r.Alert.Severity] > severityOrder[g.MaxSeverity] {
				g.MaxSeverity = r.Alert.Severity
				g.MaxCVSS = r.Alert.CVSSScore
			} else if r.Alert.Severity == g.MaxSeverity && r.Alert.CVSSScore > g.MaxCVSS {
				g.MaxCVSS = r.Alert.CVSSScore
			}
		} else {
			groupMap[key] = &RepoGroup{
				Owner:         r.Alert.Owner,
				Repo:          r.Alert.Repo,
				DefaultBranch: r.Alert.DefaultBranch,
				MaxSeverity:   r.Alert.Severity,
				MaxCVSS:       r.Alert.CVSSScore,
				Records:       []*model.AlertRecord{r},
			}
			keys = append(keys, key)
		}
	}

	groups := make([]RepoGroup, 0, len(keys))
	for _, k := range keys {
		g := groupMap[k]
		sort.Slice(g.Records, func(i, j int) bool {
			return g.Records[i].Alert.CreatedAt.After(g.Records[j].Alert.CreatedAt)
		})
		groups = append(groups, *g)
	}

	sort.Slice(groups, func(i, j int) bool {
		si, sj := severityOrder[groups[i].MaxSeverity], severityOrder[groups[j].MaxSeverity]
		if si != sj {
			return si > sj
		}
		return groups[i].MaxCVSS > groups[j].MaxCVSS
	})

	return groups
}

// severityOrder はSeverity降順ソート用の優先度マップ
var severityOrder = map[model.Severity]int{
	model.SeverityCritical: 4,
	model.SeverityHigh:     3,
	model.SeverityMedium:   2,
	model.SeverityLow:      1,
}

// groupByCVE はAlertRecordのリストをCVE ID単位でグルーピングする。
// CVE IDが空のアラートはアラートIDをキーに個別グループとして扱う。
// グループはSeverity降順 → CVSS降順でソートされる。
// グループ内のRecordsはCreatedAt降順でソートされる。
func groupByCVE(records []*model.AlertRecord) []CVEGroup {
	if len(records) == 0 {
		return []CVEGroup{}
	}

	groupMap := make(map[string]*CVEGroup)
	// 挿入順を保持するためキーを追跡
	var keys []string

	for _, r := range records {
		key := r.Alert.CVEID
		if key == "" {
			if r.Alert.GHSAID != "" {
				key = "ghsa:" + r.Alert.GHSAID
			} else {
				key = fmt.Sprintf("__noAdvisory_%d", r.Alert.ID)
			}
		}

		if g, ok := groupMap[key]; ok {
			g.Records = append(g.Records, r)
			// グループ内で最も深刻なSeverity/CVSSを保持
			if severityOrder[r.Alert.Severity] > severityOrder[g.Severity] {
				g.Severity = r.Alert.Severity
				g.CVSSScore = r.Alert.CVSSScore
				g.PackageName = r.Alert.PackageName
				g.Summary = r.Alert.Summary
			} else if r.Alert.Severity == g.Severity && r.Alert.CVSSScore > g.CVSSScore {
				g.CVSSScore = r.Alert.CVSSScore
			}
		} else {
			groupMap[key] = &CVEGroup{
				CVEID:       r.Alert.CVEID,
				GHSAID:      r.Alert.GHSAID,
				Summary:     r.Alert.Summary,
				Severity:    r.Alert.Severity,
				PackageName: r.Alert.PackageName,
				CVSSScore:   r.Alert.CVSSScore,
				Records:     []*model.AlertRecord{r},
			}
			keys = append(keys, key)
		}
	}

	groups := make([]CVEGroup, 0, len(keys))
	for _, k := range keys {
		g := groupMap[k]
		// グループ内のRecordsをCreatedAt降順でソート
		sort.Slice(g.Records, func(i, j int) bool {
			return g.Records[i].Alert.CreatedAt.After(g.Records[j].Alert.CreatedAt)
		})
		groups = append(groups, *g)
	}

	// グループをSeverity降順 → CVSS降順でソート
	sort.Slice(groups, func(i, j int) bool {
		si, sj := severityOrder[groups[i].Severity], severityOrder[groups[j].Severity]
		if si != sj {
			return si > sj
		}
		return groups[i].CVSSScore > groups[j].CVSSScore
	})

	return groups
}

// filterBySearch はクエリ文字列でAlertRecordを絞り込む。
// Repo・Owner・PackageName・CVEID・GHSAID・Summary に case-insensitive 部分一致。
// query が空の場合は全件返却する。
func filterBySearch(records []*model.AlertRecord, query string) []*model.AlertRecord {
	if query == "" {
		return records
	}
	q := strings.ToLower(query)
	var result []*model.AlertRecord
	for _, r := range records {
		a := r.Alert
		if strings.Contains(strings.ToLower(a.Repo), q) ||
			strings.Contains(strings.ToLower(a.Owner), q) ||
			strings.Contains(strings.ToLower(a.PackageName), q) ||
			strings.Contains(strings.ToLower(a.CVEID), q) ||
			strings.Contains(strings.ToLower(a.GHSAID), q) ||
			strings.Contains(strings.ToLower(a.Summary), q) {
			result = append(result, r)
		}
	}
	return result
}

// filterByConfig は現在の監視設定に含まれる未解決レコードだけを返す。
func filterByConfig(records []*model.AlertRecord, cfg *config.Config) []*model.AlertRecord {
	if cfg == nil {
		return nil
	}
	var filtered []*model.AlertRecord
	for _, r := range records {
		if r != nil && r.ResolvedAt == nil && policy.IsMonitored(cfg.Targets, r.Alert.Owner, r.Alert.Repo) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.ConfigurationSnapshot()
	if err != nil {
		http.Error(w, "設定読み込み失敗", http.StatusInternalServerError)
		return
	}
	cfg := &snapshot.Config

	s.pollingMu.Lock()
	polling := s.isPolling
	s.pollingMu.Unlock()

	records := filterByConfig(s.store.List(), cfg)

	searchQuery := r.URL.Query().Get("q")
	if searchQuery != "" {
		records = filterBySearch(records, searchQuery)
	}

	hasEvaluating := false
	for _, rec := range records {
		if rec.EvalStatus == model.EvalStatusEvaluating {
			hasEvaluating = true
			break
		}
	}

	viewMode := r.URL.Query().Get("view")
	if viewMode != "repo" {
		viewMode = "cve"
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	allCVE := groupByCVE(records)
	allRepo := groupByRepo(records)
	pagedCVE, cvePagination := paginateCVE(allCVE, page)
	pagedRepo, repoPagination := paginateRepo(allRepo, page)

	pagination := cvePagination
	if viewMode == "repo" {
		pagination = repoPagination
	}

	s.render(w, "dashboard.html", struct {
		CVEGroups       []CVEGroup
		RepoGroups      []RepoGroup
		ViewMode        string
		SearchQuery     string
		IsPolling       bool
		HasEvaluating   bool
		Pagination      PaginationInfo
		DisableApproval bool
	}{
		CVEGroups:       pagedCVE,
		RepoGroups:      pagedRepo,
		ViewMode:        viewMode,
		SearchQuery:     searchQuery,
		IsPolling:       polling,
		HasEvaluating:   hasEvaluating,
		DisableApproval: cfg.DisableApproval,
		Pagination:      pagination,
	})
}

// handlePoll はWebUIから手動でDependabotアラートのポーリングをトリガーする
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	if s.pollFn == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	s.pollingMu.Lock()
	if s.isPolling {
		s.pollingMu.Unlock()
		http.Error(w, "ポーリング実行中です", http.StatusConflict)
		return
	}
	s.isPolling = true
	s.pollingMu.Unlock()

	go func() {
		defer func() {
			s.pollingMu.Lock()
			s.isPolling = false
			s.pollingMu.Unlock()
		}()
		s.pollFn()
	}()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handlePollRepo はowner/repoを指定してFetchJobをエンキューする（ダッシュボードリポジトリ別表示から使用）
func (s *Server) handlePollRepo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}
	owner := r.FormValue("owner")
	repo := r.FormValue("repo")
	if owner == "" || repo == "" {
		http.Error(w, "owner/repoが必要です", http.StatusBadRequest)
		return
	}
	err := s.repositoryPolicy.WithAllowed(r.Context(), owner, repo, func(config.Snapshot) error {
		if s.jobQueue != nil {
			if !s.jobQueue.TryEnqueue(queue.Job{
				Type:    queue.JobFetchAlerts,
				Payload: config.Target{Owner: owner, Repo: repo},
			}) {
				return fmt.Errorf("取得キューが利用できません")
			}
		}
		return nil
	})
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, policy.ErrNotMonitored) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	http.Redirect(w, r, "/?view=repo", http.StatusSeeOther)
}

// handlePollTarget はWebUIから特定ターゲット1件のFetchJobをエンキューする
func (s *Server) handlePollTarget(w http.ResponseWriter, r *http.Request) {
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}
	snapshot, snapshotErr := s.ConfigurationSnapshot()
	if snapshotErr != nil {
		http.Error(w, "設定読み込み失敗", http.StatusInternalServerError)
		return
	}
	targets := snapshot.Config.Targets
	if i < 0 || i >= len(targets) {
		http.Error(w, "インデックスが範囲外です", http.StatusBadRequest)
		return
	}
	if s.jobQueue != nil {
		if !s.jobQueue.TryEnqueue(queue.Job{
			Type:    queue.JobFetchAlerts,
			Payload: targets[i],
		}) {
			http.Error(w, "取得キューが利用できません", http.StatusServiceUnavailable)
			return
		}
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// handleEnqueueEvaluate は指定アラートのAI評価をJobQueueに積む
func (s *Server) handleEnqueueEvaluate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "不正なID", http.StatusBadRequest)
		return
	}
	record, getErr := s.store.Get(id)
	if getErr != nil {
		http.Error(w, "アラートが見つかりません", http.StatusNotFound)
		return
	}
	if !s.isMonitoredRecord(record) {
		http.Error(w, "監視対象外リポジトリです", http.StatusConflict)
		return
	}

	if s.jobQueue == nil {
		http.Error(w, "JobQueueが設定されていません", http.StatusServiceUnavailable)
		return
	}

	err = s.repositoryPolicy.WithAllowed(r.Context(), record.Alert.Owner, record.Alert.Repo, func(config.Snapshot) error {
		claimed, err := s.store.ClaimEvaluation(r.Context(), id, true)
		if err != nil {
			return err
		}
		if !claimed {
			return errEvaluationBusy
		}
		if !s.jobQueue.TryEnqueue(queue.Job{Type: queue.JobEvaluateAlert, Payload: queue.EvaluationRequest{AlertID: id, Force: true}}) {
			if err := s.store.UpdateEvalStatus(id, record.EvalStatus); err != nil {
				return err
			}
			return fmt.Errorf("評価キューが利用できません")
		}
		return nil
	})
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, policy.ErrNotMonitored) || errors.Is(err, errEvaluationBusy) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}

	if ref := r.Referer(); ref != "" {
		http.Redirect(w, r, ref, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "不正なID", http.StatusBadRequest)
		return
	}

	record, err := s.store.Get(id)
	if err != nil {
		http.Error(w, "アラートが見つかりません", http.StatusNotFound)
		return
	}

	snapshot, snapshotErr := s.ConfigurationSnapshot()
	if snapshotErr != nil {
		http.Error(w, "設定読み込み失敗", http.StatusInternalServerError)
		return
	}
	cfg := snapshot.Config
	timeline, err := s.store.LoadRiskTimeline(r.Context(), record.Alert.Owner+"/"+record.Alert.Repo, model.AdvisoryKey(record.Alert), 20)
	if err != nil {
		slog.Error("詳細の評価履歴取得失敗", "alertID", id, "error", err)
		http.Error(w, "評価履歴取得失敗", http.StatusInternalServerError)
		return
	}
	threats, err := s.store.ListThreatSnapshotsFor(r.Context(), []string{model.AdvisoryKey(record.Alert)})
	if err != nil {
		slog.Error("詳細の脅威情報取得失敗", "alertID", id, "error", err)
		http.Error(w, "脅威情報取得失敗", http.StatusInternalServerError)
		return
	}
	score := scoreAlertWithThreat(cfg.ServiceProfiles, cfg.Assessments, threats, record)
	if record.ResolvedAt != nil && len(timeline.History) > 0 {
		score = timeline.History[0].Result
	}
	s.render(w, "detail.html", struct {
		*model.AlertRecord
		DisableApproval bool
		Monitored       bool
		Risk            model.ScoreResult
		Timeline        store.RiskTimeline
		Now             time.Time
	}{record, cfg.DisableApproval || !s.isMonitoredRecord(record), s.isMonitoredRecord(record), score, timeline, time.Now().UTC()})
}

func (s *Server) isMonitoredRecord(record *model.AlertRecord) bool {
	if record == nil || record.ResolvedAt != nil {
		return false
	}
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return policy.IsMonitored(s.cfg.Targets, record.Alert.Owner, record.Alert.Repo)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	snapshot, snapshotErr := s.ConfigurationSnapshot()
	if snapshotErr != nil {
		http.Error(w, "設定読み込み失敗", http.StatusInternalServerError)
		return
	}
	if snapshot.Config.DisableApproval {
		http.Error(w, "承認機能は無効化されています", http.StatusForbidden)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "不正なID", http.StatusBadRequest)
		return
	}
	if record, getErr := s.store.Get(id); getErr == nil && !s.isMonitoredRecord(record) {
		http.Error(w, "監視対象外リポジトリです", http.StatusConflict)
		return
	}

	if err := s.merger.Approve(r.Context(), id); err != nil {
		slog.Error("マージ承認失敗", "alertID", id, "error", err)
		status := http.StatusInternalServerError
		if errors.Is(err, policy.ErrNotMonitored) {
			status = http.StatusConflict
		}
		if errors.Is(err, merger.ErrApprovalDisabled) {
			status = http.StatusForbidden
		}
		http.Error(w, "マージ失敗: "+err.Error(), status)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	snapshot, snapshotErr := s.ConfigurationSnapshot()
	if snapshotErr != nil {
		http.Error(w, "設定読み込み失敗", http.StatusInternalServerError)
		return
	}
	if snapshot.Config.DisableApproval {
		http.Error(w, "却下機能は無効化されています", http.StatusForbidden)
		return
	}

	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "不正なID", http.StatusBadRequest)
		return
	}
	if record, getErr := s.store.Get(id); getErr == nil && !s.isMonitoredRecord(record) {
		http.Error(w, "監視対象外リポジトリです", http.StatusConflict)
		return
	}

	if err := s.merger.Reject(id); err != nil {
		slog.Error("却下失敗", "alertID", id, "error", err)
		status := http.StatusInternalServerError
		if errors.Is(err, policy.ErrNotMonitored) {
			status = http.StatusConflict
		}
		if errors.Is(err, merger.ErrApprovalDisabled) {
			status = http.StatusForbidden
		}
		http.Error(w, "却下失敗: "+err.Error(), status)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	logs := s.store.ListLogs()

	// 新しい順に表示
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Timestamp.After(logs[j].Timestamp)
	})

	s.render(w, "logs.html", struct {
		Logs []model.LogEntry
	}{Logs: logs})
}

// --- 設定 ---

type settingsData struct {
	Config            *config.Config
	Flash             string // 保存成功メッセージ
	Error             string
	EnvBotToken       bool   // SLACK_BOT_TOKEN が環境変数で設定されているか
	EnvAppToken       bool   // SLACK_APP_TOKEN が環境変数で設定されているか
	EnvDiscordWebhook bool   // DISCORD_WEBHOOK_URL が環境変数で設定されているか
	AllowedUserIDsStr string // Config.Slack.AllowedUserIDs のカンマ区切り文字列（テンプレート表示用）
	Repositories      []repositoryStatus
	Revision          uint64
	CSRFToken         string
}

type repositoryStatus struct {
	Owner, Repo string
	Configured  bool
	Excluded    bool
	AlertCount  int
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	snapshot, snapshotErr := s.ConfigurationSnapshot()
	if snapshotErr != nil {
		http.Error(w, "設定読み込み失敗", http.StatusInternalServerError)
		return
	}
	cfg := &snapshot.Config
	summaries, err := s.store.QueryRepositories(r.Context())
	if err != nil {
		slog.Error("設定画面リポジトリ集計失敗", "error", err)
		http.Error(w, "リポジトリ一覧取得失敗", http.StatusInternalServerError)
		return
	}
	repos := make([]repositoryStatus, 0, len(summaries))
	for _, summary := range summaries {
		v := repositoryStatus{Owner: summary.Owner, Repo: summary.Repo, AlertCount: summary.AlertCount}
		for _, target := range cfg.Targets {
			if policy.Matches(target, v.Owner, v.Repo) {
				v.Configured = true
				if target.IsExcluded(v.Repo) {
					v.Excluded = true
				}
			}
		}
		repos = append(repos, v)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].Owner+"/"+repos[i].Repo < repos[j].Owner+"/"+repos[j].Repo })

	s.render(w, "settings.html", settingsData{
		Config:            cfg,
		EnvBotToken:       os.Getenv("SLACK_BOT_TOKEN") != "",
		EnvAppToken:       os.Getenv("SLACK_APP_TOKEN") != "",
		EnvDiscordWebhook: os.Getenv("DISCORD_WEBHOOK_URL") != "",
		AllowedUserIDsStr: strings.Join(cfg.Slack.AllowedUserIDs, ","),
		Repositories:      repos,
		Revision:          cfg.ConfigRevision,
		CSRFToken:         issueCSRF(w, r),
	})
}

func (s *Server) updateRepositoryExclude(w http.ResponseWriter, r *http.Request, exclude bool) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}
	owner, repo := strings.TrimSpace(r.FormValue("owner")), strings.TrimSpace(r.FormValue("repo"))
	if owner == "" || repo == "" {
		http.Error(w, "owner/repoが必要です", http.StatusBadRequest)
		return
	}
	unlock, lockErr := s.repositoryPolicy.LockUpdate(r.Context())
	if lockErr != nil {
		http.Error(w, "設定変更の待機を中止しました", http.StatusRequestTimeout)
		return
	}
	defer unlock()
	s.cfgMu.RLock()
	currentRevision := s.cfg.ConfigRevision
	baseCfg := *s.cfg
	s.cfgMu.RUnlock()
	if raw := strings.TrimSpace(r.FormValue("revision")); raw != "" {
		if revision, err := strconv.ParseUint(raw, 10, 64); err != nil {
			http.Error(w, "revisionが不正です", http.StatusBadRequest)
			return
		} else if revision != currentRevision {
			http.Error(w, "設定が更新されています", http.StatusConflict)
			return
		}
	}
	knownRepo := false
	for _, target := range baseCfg.Targets {
		if !strings.EqualFold(target.Owner, owner) {
			continue
		}
		if target.Repo == "" || strings.EqualFold(target.Repo, repo) {
			knownRepo = true
			break
		}
	}
	if !knownRepo {
		for _, existing := range s.store.ListReposByOwner(owner) {
			if strings.EqualFold(existing, repo) {
				knownRepo = true
				break
			}
		}
	}
	if !knownRepo {
		http.Error(w, "監視対象として取得済みのリポジトリではありません", http.StatusNotFound)
		return
	}
	s.cfgMu.Lock()
	if s.cfg.ConfigRevision != currentRevision {
		s.cfgMu.Unlock()
		http.Error(w, "設定が更新されています", http.StatusConflict)
		return
	}
	next := *s.cfg
	next.Targets = append([]config.Target(nil), s.cfg.Targets...)
	for i := range next.Targets {
		next.Targets[i].Excludes = append([]string(nil), next.Targets[i].Excludes...)
	}
	found := false
	for i := range next.Targets {
		if !policy.Matches(next.Targets[i], owner, repo) {
			continue
		}
		found = true
		ex := next.Targets[i].Excludes
		if exclude {
			exists := false
			for _, v := range ex {
				if strings.EqualFold(v, repo) {
					exists = true
					break
				}
			}
			if !exists {
				next.Targets[i].Excludes = append(ex, repo)
			}
		} else {
			kept := ex[:0]
			for _, v := range ex {
				if !strings.EqualFold(v, repo) {
					kept = append(kept, v)
				}
			}
			next.Targets[i].Excludes = kept
		}
	}
	if !found {
		s.cfgMu.Unlock()
		http.Error(w, "対象ownerの監視設定がありません", http.StatusUnprocessableEntity)
		return
	}
	next.ConfigRevision = currentRevision + 1
	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, &next); err != nil {
			s.cfgMu.Unlock()
			http.Error(w, "設定保存失敗", http.StatusInternalServerError)
			return
		}
	}
	*s.cfg = next
	s.notifyRiskConfigChanged()
	s.cfgMu.Unlock()
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleRepositoryExclude(w http.ResponseWriter, r *http.Request) {
	s.updateRepositoryExclude(w, r, true)
}
func (s *Server) handleRepositoryInclude(w http.ResponseWriter, r *http.Request) {
	s.updateRepositoryExclude(w, r, false)
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}

	unlock, lockErr := s.repositoryPolicy.LockUpdate(r.Context())
	if lockErr != nil {
		http.Error(w, "設定変更の待機を中止しました", http.StatusRequestTimeout)
		return
	}
	defer unlock()
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	original, cloneErr := config.Clone(*s.cfg)
	if cloneErr != nil {
		http.Error(w, "設定の読み込みに失敗しました", http.StatusInternalServerError)
		return
	}
	if raw := r.FormValue("notification_interval"); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil || interval < 0 {
			http.Error(w, "通知をまとめる間隔は0以上の時間で指定してください", http.StatusBadRequest)
			return
		}
		s.cfg.NotificationInterval = interval
	}

	// poll_interval
	if v := r.FormValue("poll_interval"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			s.cfg.PollInterval = d
		}
	}

	// log_level
	if v := r.FormValue("log_level"); v != "" {
		s.cfg.LogLevel = v
	}

	// claude_path / gh_path
	if v := r.FormValue("claude_path"); v != "" {
		s.cfg.ClaudePath = v
	}
	if v := r.FormValue("codex_path"); v != "" {
		s.cfg.CodexPath = v
	}
	if v := r.FormValue("gh_path"); v != "" {
		s.cfg.GhPath = v
	}

	// slack（トークンは環境変数未設定時のみYAML保存）
	s.cfg.Slack.ChannelID = r.FormValue("slack_channel_id")

	// slack承認許可ユーザー（カンマ区切り → スライス）
	if v := r.FormValue("slack_allowed_user_ids"); v != "" {
		parts := strings.Split(v, ",")
		var ids []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				ids = append(ids, p)
			}
		}
		s.cfg.Slack.AllowedUserIDs = ids
	} else {
		s.cfg.Slack.AllowedUserIDs = nil // 空=全員許可
	}
	if os.Getenv("SLACK_BOT_TOKEN") == "" {
		if v := r.FormValue("slack_bot_token"); v != "" {
			s.cfg.Slack.BotToken = v
		}
	}
	if os.Getenv("SLACK_APP_TOKEN") == "" {
		if v := r.FormValue("slack_app_token"); v != "" {
			s.cfg.Slack.AppToken = v
		}
	}

	// discord.webhook_url（環境変数未設定時のみYAML保存）
	if os.Getenv("DISCORD_WEBHOOK_URL") == "" {
		s.cfg.Discord.WebhookURL = r.FormValue("discord_webhook_url")
	}

	// 承認/却下機能の有効・無効
	s.cfg.DisableApproval = r.FormValue("disable_approval") == "true"

	// 取得最低重要度（空=全件取得）
	if v := r.FormValue("fetch_min_severity"); v == "critical" || v == "high" || v == "medium" || v == "low" || v == "" {
		s.cfg.FetchMinSeverity = v
	}

	// 通知最低重要度
	if v := r.FormValue("notify_min_severity"); v == "critical" || v == "high" || v == "medium" || v == "low" {
		s.cfg.NotifyMinSeverity = v
	}

	// 直近活動フィルタ（Nか月以内にpushがあったリポのみ対象）
	if v := r.FormValue("active_months"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			s.cfg.ActiveMonths = n
		}
	}

	// AI自動評価ON/OFF
	s.cfg.Evaluator.AutoEval = r.FormValue("auto_eval") == "true"
	if v := r.FormValue("eval_provider"); v != "" {
		s.cfg.Evaluator.Provider = v
	}
	if r.Form.Has("eval_codex_model") {
		s.cfg.Evaluator.CodexModel = strings.TrimSpace(r.FormValue("eval_codex_model"))
	}
	if r.Form.Has("eval_claude_model") {
		s.cfg.Evaluator.ClaudeModel = strings.TrimSpace(r.FormValue("eval_claude_model"))
	}
	if r.Form.Has("eval_hermes_model") {
		s.cfg.Evaluator.HermesModel = strings.TrimSpace(r.FormValue("eval_hermes_model"))
	}
	if r.Form.Has("eval_hermes_base_url") {
		s.cfg.Evaluator.HermesBaseURL = strings.TrimSpace(r.FormValue("eval_hermes_base_url"))
	}

	// AI評価最低重要度
	if v := r.FormValue("eval_min_severity"); v == "critical" || v == "high" || v == "medium" || v == "low" {
		s.cfg.Evaluator.MinSeverity = v
	}

	// evaluator sandbox
	if r.Form.Has("sandbox_enabled") {
		s.cfg.Evaluator.Sandbox.Enabled = r.FormValue("sandbox_enabled") == "true"
	}
	if v := r.FormValue("sandbox_runtime"); v != "" {
		s.cfg.Evaluator.Sandbox.Runtime = v
	}
	if v := r.FormValue("sandbox_image"); v != "" {
		s.cfg.Evaluator.Sandbox.Image = v
	}
	if v := r.FormValue("sandbox_codex_image"); v != "" {
		s.cfg.Evaluator.Sandbox.CodexImage = v
	}
	if v := r.FormValue("sandbox_memory"); v != "" {
		s.cfg.Evaluator.Sandbox.MemoryLimit = v
	}
	if v := r.FormValue("sandbox_cpu"); v != "" {
		s.cfg.Evaluator.Sandbox.CPULimit = v
	}
	if v := r.FormValue("sandbox_timeout"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			s.cfg.Evaluator.Sandbox.Timeout = d
		}
	}

	if err := s.cfg.Validate(); err != nil {
		*s.cfg = original
		http.Error(w, "設定が不正です: "+err.Error(), http.StatusBadRequest)
		return
	}
	// 保存
	s.cfg.ConfigRevision++
	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, s.cfg); err != nil {
			*s.cfg = original
			slog.Error("設定保存失敗", "error", err)
			s.render(w, "settings.html", settingsData{
				Config: s.cfg,
				Error:  "設定の保存に失敗しました: " + err.Error(),
			})
			return
		}
	}
	if s.onEvaluatorConfigChanged != nil {
		s.onEvaluatorConfigChanged(*s.cfg)
	}
	s.notifyRiskConfigChanged()

	slog.Info("設定を保存しました")
	s.store.AddLog(model.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "設定を保存しました",
	})

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) handleTargetAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}

	owner := r.FormValue("owner")
	repo := r.FormValue("repo")
	if owner == "" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	if !s.updateMonitoringSettings(r.Context(), w, func(cfg *config.Config) { cfg.Targets = append(cfg.Targets, config.Target{Owner: owner, Repo: repo}) }) {
		return
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleTargetDelete(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("i"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}

	if !s.updateMonitoringSettings(r.Context(), w, func(cfg *config.Config) {
		if idx >= 0 && idx < len(cfg.Targets) {
			cfg.Targets = append(cfg.Targets[:idx], cfg.Targets[idx+1:]...)
		}
	}) {
		return
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleExcludeAdd(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("i"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}
	repo := r.FormValue("repo")
	if repo == "" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	if !s.updateMonitoringSettings(r.Context(), w, func(cfg *config.Config) {
		if idx >= 0 && idx < len(cfg.Targets) {
			t := &cfg.Targets[idx]
			// 重複チェック
			exists := false
			for _, ex := range t.Excludes {
				if strings.EqualFold(ex, repo) {
					exists = true
					break
				}
			}
			if !exists {
				t.Excludes = append(t.Excludes, repo)
			}
		}
	}) {
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleExcludeDelete(w http.ResponseWriter, r *http.Request) {
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}
	j, err := strconv.Atoi(r.PathValue("j"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}

	if !s.updateMonitoringSettings(r.Context(), w, func(cfg *config.Config) {
		if i >= 0 && i < len(cfg.Targets) {
			t := &cfg.Targets[i]
			if j >= 0 && j < len(t.Excludes) {
				t.Excludes = append(t.Excludes[:j], t.Excludes[j+1:]...)
			}
		}
	}) {
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
