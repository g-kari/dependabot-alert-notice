package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/discord"
	"github.com/g-kari/dependabot-alert-notice/internal/evaluator"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestEvaluationNeverReusesUnattributedAdvisoryResult(t *testing.T) {
	for _, difference := range []string{"same_input", "repo", "package", "fixed_version", "summary", "ghsa_only"} {
		t.Run(difference, func(t *testing.T) {
			s := store.New()
			t.Cleanup(func() { _ = s.Close() })
			alert := model.Alert{Owner: "org", Repo: "api", Number: 1, CVEID: "CVE-2026-1234", GHSAID: "GHSA-abcd", PackageName: "pkg", FixedIn: "2.0", Summary: "original", Severity: model.SeverityCritical}
			if difference == "ghsa_only" {
				alert.CVEID = ""
			}
			s.SaveObserved(&model.AlertRecord{Alert: alert, Evaluation: &model.Evaluation{Recommendation: "reject"}, EvalStatus: model.EvalStatusDone, NotifiedAt: time.Now()})
			alert.Number = 2
			switch difference {
			case "repo":
				alert.Repo = "worker"
			case "package":
				alert.PackageName = "other-package"
			case "fixed_version":
				alert.FixedIn = "3.0"
			case "summary":
				alert.Summary = "changed"
			}
			row := &model.AlertRecord{Alert: alert, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now()}
			s.SaveObserved(row)
			e := &resolutionEvaluator{}
			h := makeEvaluateHandler(&config.Config{Targets: []config.Target{{Owner: "org"}}}, e, s, nil, nil)
			if err := h(context.Background(), queue.Job{Payload: row.Alert.ID}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(row.Alert.ID)
			if err != nil || e.calls != 1 || got.Evaluation.Recommendation != "approve" {
				t.Fatalf("unattributed result reused: calls=%d row=%+v err=%v", e.calls, got, err)
			}
		})
	}
}

type attributedEvaluator struct {
	cfg    config.Config
	calls  int
	during func(model.Alert)
	err    error
	last   model.Alert
}

func fixtureEvaluator(selectedModel string) *attributedEvaluator {
	return &attributedEvaluator{cfg: config.Config{CodexPath: "fixture-codex", Evaluator: config.EvaluatorConfig{Provider: "codex", CodexModel: selectedModel}}}
}

func (e *attributedEvaluator) Identity(alert model.Alert) *model.EvaluationProvenance {
	return evaluator.Capture(evaluator.New(&e.cfg), alert).Provenance()
}

func (e *attributedEvaluator) Evaluate(_ context.Context, alert model.Alert) (*model.Evaluation, error) {
	e.calls++
	e.last = alert
	if e.during != nil {
		e.during(alert)
	}
	return &model.Evaluation{Recommendation: "manual-review", Impact: e.cfg.Evaluator.CodexModel, Provenance: &model.EvaluationProvenance{Provider: "spoofed"}}, e.err
}

func cachedRow(t *testing.T, s *store.Store, e *attributedEvaluator) *model.AlertRecord {
	t.Helper()
	r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1, CVEID: "CVE-2026-1234", GHSAID: "GHSA-abcd", PackageName: "pkg", Summary: "original", Severity: model.SeverityCritical}, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now().UTC()}
	s.SaveObserved(r)
	h := makeEvaluateHandler(&config.Config{Targets: []config.Target{{Owner: "org"}}}, e, s, nil, nil)
	if err := h(context.Background(), queue.Job{Payload: r.Alert.ID}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(r.Alert.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestEvaluationCacheReusesOnlySameModelAndInputUnlessForced(t *testing.T) {
	for _, scenario := range []string{"identical", "force", "repo", "package", "fixed", "summary", "ghsa", "model", "provider", "prompt_version", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			s := store.New()
			t.Cleanup(func() { _ = s.Close() })
			e := fixtureEvaluator("model-a")
			old := cachedRow(t, s, e)
			if old.Evaluation.Provenance == nil || old.Evaluation.Provenance.Provider != "codex" {
				t.Fatal("model supplied forged provenance")
			}
			alert := old.Alert
			alert.ID, alert.Number = 0, 2
			switch scenario {
			case "repo":
				alert.Repo = "worker"
			case "package":
				alert.PackageName = "other"
			case "fixed":
				alert.FixedIn = "3.0"
			case "summary":
				alert.Summary = "changed"
			case "ghsa":
				alert.GHSAID = "GHSA-efgh"
			case "model":
				e.cfg.Evaluator.CodexModel = "model-b"
			case "provider":
				e.cfg.Evaluator.Provider = "claude"
				e.cfg.Evaluator.ClaudeModel = "model-a"
			case "prompt_version":
				old.Evaluation.Provenance.PromptVersion = "old-version"
				old.Evaluation.Provenance.CacheKey = old.Evaluation.Provenance.Key()
				s.Save(old)
			case "expired":
				old.Evaluation.Provenance.EvaluatedAt = time.Now().Add(-25 * time.Hour)
				s.Save(old)
			}
			row := &model.AlertRecord{Alert: alert, EvalStatus: model.EvalStatusPending, NotifiedAt: time.Now().UTC()}
			s.SaveObserved(row)
			e.calls = 0
			h := makeEvaluateHandler(&config.Config{Targets: []config.Target{{Owner: "org"}}}, e, s, nil, nil)
			if err := h(context.Background(), queue.Job{Payload: queue.EvaluationRequest{AlertID: row.Alert.ID, Force: scenario == "force"}}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(row.Alert.ID)
			wantCalls := 1
			if scenario == "identical" {
				wantCalls = 0
			}
			if err != nil || got.Evaluation == nil || e.calls != wantCalls || got.Evaluation.Provenance.Reused != (scenario == "identical") {
				t.Fatalf("%s cache: calls=%d want=%d result=%+v err=%v", scenario, e.calls, wantCalls, got, err)
			}
			if scenario == "identical" && !got.Evaluation.Provenance.EvaluatedAt.Equal(old.Evaluation.Provenance.EvaluatedAt) {
				t.Fatal("reuse renewed inference timestamp")
			}
		})
	}
}

func TestModelChangeDuringInferenceRetriesWithoutNotifyingStaleResult(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run("generation", func(t *testing.T) {
			s := store.New()
			t.Cleanup(func() { _ = s.Close() })
			e := fixtureEvaluator("model-a")
			newProvider := fixtureEvaluator("model-b")
			switcher := evaluator.NewSwitcher(e)
			e.during = func(model.Alert) { switcher.Set(newProvider) }
			if failed {
				e.err = errors.New("obsolete provider failed")
			}
			row := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1, Severity: model.SeverityCritical}, EvalStatus: model.EvalStatusEvaluating, NotifiedAt: time.Now()}
			s.SaveObserved(row)
			var notifications atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				notifications.Add(1)
				_, _ = io.WriteString(w, `{"id":"fixture"}`)
			}))
			t.Cleanup(endpoint.Close)
			h := makeEvaluateHandler(&config.Config{Targets: []config.Target{{Owner: "org"}}, NotifyMinSeverity: "low"}, switcher, s, nil, discord.New(endpoint.URL))
			if err := h(context.Background(), queue.Job{Payload: queue.EvaluationRequest{AlertID: row.Alert.ID, Force: true}}); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(row.Alert.ID)
			if err != nil || e.calls != 1 || newProvider.calls != 1 || notifications.Load() != 1 || got.Evaluation.Provenance.Model != "model-b" || got.Evaluation.Impact != "model-b" {
				t.Fatalf("stale generation published: old=%d new=%d notifications=%d row=%+v err=%v", e.calls, newProvider.calls, notifications.Load(), got, err)
			}
		})
	}
}

func TestChangedInputRetriesButPreservesApprovalAndPriorEvaluationOnChurn(t *testing.T) {
	for _, churn := range []bool{false, true} {
		t.Run("input", func(t *testing.T) {
			s := store.New()
			t.Cleanup(func() { _ = s.Close() })
			e := fixtureEvaluator("model-a")
			row := cachedRow(t, s, e)
			e.calls = 0
			e.during = func(alert model.Alert) {
				if e.calls > 1 && !churn {
					return
				}
				alert.Summary += " changed"
				if err := s.UpdateAlertJSON(alert.Owner, alert.Repo, alert.Number, alert); err != nil {
					t.Fatal(err)
				}
				if err := s.UpdateState(alert.ID, model.AlertStateRejected); err != nil {
					t.Fatal(err)
				}
			}
			h := makeEvaluateHandler(&config.Config{Targets: []config.Target{{Owner: "org"}}}, e, s, nil, nil)
			err := h(context.Background(), queue.Job{Payload: queue.EvaluationRequest{AlertID: row.Alert.ID, Force: true}})
			got, getErr := s.Get(row.Alert.ID)
			if getErr != nil || got.State != model.AlertStateRejected {
				t.Fatalf("concurrent approval overwritten: %+v %v", got, getErr)
			}
			if churn {
				if err == nil || e.calls != 3 || got.EvalStatus != model.EvalStatusPending || !got.Evaluation.Provenance.EvaluatedAt.Equal(row.Evaluation.Provenance.EvaluatedAt) {
					t.Fatalf("unbounded churn/old result overwritten: calls=%d row=%+v err=%v", e.calls, got, err)
				}
			} else if err != nil || e.calls != 2 || e.last.Summary != "original changed" || got.EvalStatus != model.EvalStatusDone || got.Evaluation.Provenance.Reused {
				t.Fatalf("new input/force lost: calls=%d row=%+v err=%v", e.calls, got, err)
			}
		})
	}
}
