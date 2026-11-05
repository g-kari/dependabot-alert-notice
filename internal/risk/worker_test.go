package risk

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type workerSettings struct {
	cfg     config.Config
	before  func()
	changed chan struct{}
}

func (s *workerSettings) Snapshot() (config.Snapshot, error) {
	cfg, err := config.Clone(s.cfg)
	return config.Snapshot{Revision: s.cfg.ConfigRevision, Config: cfg}, err
}
func (s *workerSettings) WithRevision(rev uint64, save func() error) error {
	if s.before != nil {
		before := s.before
		s.before = nil
		before()
	}
	if rev != s.cfg.ConfigRevision {
		return store.ErrRiskInputsChanged
	}
	return save()
}
func (s *workerSettings) Changes() <-chan struct{} { return s.changed }

func newWorkerFixture(t *testing.T) (*Worker, *store.Store, *workerSettings, time.Time) {
	t.Helper()
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2000, 1, 1, 12, 0, 0, 0, time.UTC)
	settings := &workerSettings{cfg: config.Config{Targets: []config.Target{{Owner: "ORG"}}}, changed: make(chan struct{}, 1)}
	for _, id := range []string{"production", "staging"} {
		settings.cfg.ServiceProfiles = append(settings.cfg.ServiceProfiles, model.ServiceProfile{ID: id, Owner: "org", Repo: "api", Environment: model.EnvironmentProduction, Exposure: model.ExposureInternet, Authentication: model.AuthNone, BusinessCriticality: model.RiskCritical, MaxOutageMinutes: 60, DataClassification: model.RiskRestricted, IntegrityImpact: model.RiskCritical, PrivilegeScope: model.PrivilegeSharedControl})
		settings.cfg.Assessments = append(settings.cfg.Assessments, model.CVEAssessment{ProfileID: id, AdvisoryKey: "cve:CVE-2026-1234", Applicability: "affected", Reachability: "reachable", Facts: map[string]string{"required_privilege": "none"}})
	}
	for _, number := range []int{1, 2} {
		s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: number, CVEID: "CVE-2026-1234", CVSSKnown: true, CVSSScore: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, NotifiedAt: at})
	}
	epss := .001
	if err := s.UpsertThreat(context.Background(), "epss", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-1234", EPSS: &epss, KEVKnown: true, FetchedAt: at}}); err != nil {
		t.Fatal(err)
	}
	w := NewWorker(s, settings)
	w.Now = func() time.Time { return at }
	return w, s, settings, at
}

func TestWorkerAggregatesDuplicateAlertsAllProfilesAndExpiry(t *testing.T) {
	w, s, _, at := newWorkerFixture(t)
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeline, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(timeline.History) != 2 || len(timeline.Deadlines) != 2 {
		t.Fatalf("profile evaluations=%+v err=%v", timeline, err)
	}
	w.Now = func() time.Time { return at.Add(time.Minute) }
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeline, err = s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(timeline.History) != 2 {
		t.Fatalf("unchanged inputs duplicated: %+v err=%v", timeline, err)
	}
	w.Now = func() time.Time { return at.Add(73 * time.Hour) }
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeline, err = s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(timeline.History) != 4 || timeline.History[0].Result.Status != "provisional" {
		t.Fatalf("expiry wasn't persisted: %+v err=%v", timeline, err)
	}
}

func TestWorkerDiscardsConfigAndThreatGenerationConflicts(t *testing.T) {
	for _, kind := range []string{"config", "threat"} {
		t.Run(kind, func(t *testing.T) {
			w, s, settings, at := newWorkerFixture(t)
			settings.before = func() {
				if kind == "config" {
					settings.cfg.Targets[0].Excludes = []string{"api"}
					settings.cfg.ConfigRevision++
				} else {
					if err := s.UpsertThreat(context.Background(), "kev", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-1234", KEV: true, FetchedAt: at}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := w.RefreshOnce(context.Background()); !errors.Is(err, store.ErrRiskInputsChanged) {
				t.Fatalf("conflict error=%v", err)
			}
			timeline, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
			if err != nil || len(timeline.History) != 0 {
				t.Fatalf("stale result saved: %+v err=%v", timeline, err)
			}
		})
	}
}

func TestWorkerRunStartsRecalculatesAndStops(t *testing.T) {
	w, s, _, at := newWorkerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	waitHistory := func(count int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			timeline, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
			if err != nil {
				t.Fatal(err)
			}
			if len(timeline.History) == count {
				return
			}
			select {
			case err := <-done:
				t.Fatalf("worker stopped before history=%d: %v", count, err)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("history never reached %d", count)
	}
	waitHistory(2)
	if err := s.UpsertThreat(ctx, "kev", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-1234", KEV: true, FetchedAt: at}}); err != nil {
		t.Fatal(err)
	}
	waitHistory(4)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop")
	}
}

func TestWorkerExclusionRetentionAndReopenedEpisode(t *testing.T) {
	w, s, settings, at := newWorkerFixture(t)
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	settings.cfg.Targets = append([]config.Target{{Owner: "org", Repo: "api"}}, config.Target{Owner: "org", Excludes: []string{"api"}})
	settings.cfg.ConfigRevision++
	if err := s.UpsertThreat(context.Background(), "kev", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-1234", KEV: true, FetchedAt: at}}); err != nil {
		t.Fatal(err)
	}
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeline, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(timeline.History) != 2 || timeline.Deadlines[0].ClosedAt != nil {
		t.Fatalf("exclusion erased/changed history: %+v %v", timeline, err)
	}
	settings.cfg.Targets[1].Excludes = nil
	settings.cfg.ConfigRevision++
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeline, err = s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(timeline.History) != 4 {
		t.Fatalf("include did not resume: %+v %v", timeline, err)
	}
	if _, err := s.ResolveMissingAlerts(context.Background(), "org", "api", nil, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	w.Now = func() time.Time { return at.Add(2 * time.Hour) }
	// Reopening between sweeps must not be hidden by the unchanged-input cache.
	rec, err := s.Get(1)
	if err != nil {
		t.Fatal(err)
	}
	rec.NotifiedAt = at.Add(2 * time.Hour)
	s.SaveObserved(rec)
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeline, err = s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(timeline.Deadlines) != 4 {
		t.Fatalf("reopen episodes: %+v %v", timeline, err)
	}
}

func TestWorkerNoConfiguredTargetsDoesNotMonitorStoredAlerts(t *testing.T) {
	w, s, settings, _ := newWorkerFixture(t)
	settings.cfg.Targets = nil
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	timeline, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(timeline.History) != 0 || len(timeline.Deadlines) != 0 {
		t.Fatalf("unconfigured repositories monitored: %+v %v", timeline, err)
	}
}

func TestWorkerOwnerWideProfilesHaveRepositorySpecificEpisodes(t *testing.T) {
	w, s, settings, at := newWorkerFixture(t)
	for i := range settings.cfg.ServiceProfiles {
		settings.cfg.ServiceProfiles[i].Repo = ""
	}
	s.SaveObserved(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "sdk", Number: 3, CVEID: "CVE-2026-1234"}, NotifiedAt: at})
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	api, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := s.LoadRiskTimeline(context.Background(), "org/sdk", "cve:CVE-2026-1234", 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range api.History {
		for _, b := range sdk.History {
			if a.ProfileID == b.ProfileID {
				t.Fatalf("different repos share episode identity %q", a.ProfileID)
			}
		}
	}
	if _, err := s.ResolveMissingAlerts(context.Background(), "org", "api", nil, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	sdk, err = s.LoadRiskTimeline(context.Background(), "org/sdk", "cve:CVE-2026-1234", 20)
	if err != nil || len(sdk.Deadlines) != 2 {
		t.Fatalf("sdk deadlines=%+v %v", sdk, err)
	}
	for _, episode := range sdk.Deadlines {
		if episode.ClosedAt != nil {
			t.Fatal("resolving api closed sdk episode")
		}
	}
}

func TestWorkerPeriodicExpiryAndRestartPreserveDeadline(t *testing.T) {
	w, s, settings, at := newWorkerFixture(t)
	if err := w.RefreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewWorker(s, settings)
	var clock atomic.Int64
	clock.Store(at.Add(time.Minute).Unix())
	restarted.Now = func() time.Time { return time.Unix(clock.Load(), 0) }
	restarted.Interval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- restarted.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("periodic worker did not stop")
		}
	})
	started := false
	startupLimit := time.Now().Add(3 * time.Second)
	for time.Now().Before(startupLimit) {
		restarted.mu.Lock()
		started = len(restarted.cache) == 2
		restarted.mu.Unlock()
		if started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !started {
		t.Fatal("restart startup sweep did not finish")
	}
	initial, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
	if err != nil || len(initial.History) != 2 || !initial.Deadlines[0].DueAt.Equal(before.Deadlines[0].DueAt) {
		t.Fatalf("restart duplicated or extended: %+v %v", initial, err)
	}
	clock.Store(at.Add(73 * time.Hour).Unix())
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		after, err := s.LoadRiskTimeline(context.Background(), "org/api", "cve:CVE-2026-1234", 20)
		if err != nil {
			t.Fatal(err)
		}
		if len(after.History) == 4 {
			if len(after.Deadlines) != 2 || !after.Deadlines[0].DueAt.Equal(before.Deadlines[0].DueAt) {
				t.Fatalf("restart/expiry extended deadline: %+v", after)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("periodic expiry was not persisted")
}
