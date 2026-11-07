package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func secretScanningImportFixture(t *testing.T, state string, at time.Time, sequence int) (model.IngestRun, []model.SecurityFinding) {
	t.Helper()
	id := fmt.Sprintf("00000000-0000-8000-8000-%012d", sequence)
	run := model.IngestRun{ID: id, Connector: "github_secret_scanning", Scope: "example/repo", StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + strings.Repeat("a", 64)}
	resolution := ""
	if state != "open" {
		resolution = `,"resolution":"revoked"`
		if state == "suppressed" {
			resolution = `,"resolution":"false_positive"`
		}
		state = "resolved"
	}
	items, err := adapter.ParseSecretScanningJSON(strings.NewReader(`[{"number":42,"state":"`+state+`","secret_type":"synthetic_example"`+resolution+`}]`), adapter.SecretScanningOptions{Repository: run.Scope, RunID: id, ObservedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	return run, items
}
func TestSecretScanningImportLifecycleStaleReplayAndNoFalseClosure(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	firstRun, firstItems := secretScanningImportFixture(t, "open", at, 10)
	if _, err := s.ImportSecurityFindings(ctx, firstRun, firstItems); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ImportSecurityFindings(ctx, firstRun, firstItems); err != nil || !got.Replay {
		t.Fatalf("replay=%+v %v", got, err)
	}
	if _, err := s.db.Exec(`UPDATE findings SET triage_status='risk_accepted',body_json=json_set(body_json,'$.triage_status','risk_accepted') WHERE id=?`, firstItems[0].Finding.ID); err != nil {
		t.Fatal(err)
	}
	for i, state := range []string{"resolved", "suppressed", "open"} {
		run, items := secretScanningImportFixture(t, state, at.Add(time.Duration(i+1)*time.Hour), 11+i)
		if _, err := s.ImportSecurityFindings(ctx, run, items); err != nil {
			t.Fatal(err)
		}
	}
	staleRun, stale := secretScanningImportFixture(t, "resolved", at.Add(-time.Hour), 14)
	if _, err := s.ImportSecurityFindings(ctx, staleRun, stale); err != nil {
		t.Fatal(err)
	}
	emptyRun, _ := secretScanningImportFixture(t, "open", at.Add(4*time.Hour), 15)
	if _, err := s.ImportSecurityFindings(ctx, emptyRun, nil); err != nil {
		t.Fatal(err)
	}
	findings, err := s.QueryFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v %v", findings, err)
	}
	f := findings[0]
	if f.SourceStatus != model.SourceStatusActive || f.TriageStatus != model.TriageStatusRiskAccepted || !f.FirstSeen.Equal(at) || !f.LastSeen.Equal(at.Add(3*time.Hour)) || f.SecretType != "synthetic_example" {
		t.Fatalf("latest=%+v", f)
	}
	observations, err := s.QueryObservations(ctx, f.ID)
	if err != nil || len(observations) != 5 {
		t.Fatalf("observations=%d %v", len(observations), err)
	}
	events, err := s.QueryEvents(ctx, f.ID)
	if err != nil || len(events) != 4 {
		t.Fatalf("events=%d %v", len(events), err)
	}
	for _, query := range []string{"synthetic_example", "Secret Scanning"} {
		page, err := s.QueryFindingsPage(ctx, FindingQuery{Search: query, Source: "github_secret_scanning", Limit: 50})
		if err != nil || page.Total != 1 {
			t.Fatalf("search=%q %+v %v", query, page, err)
		}
	}
	if len(s.List()) != 0 {
		t.Fatal("legacy workflow modified")
	}
}
func TestSecretScanningImportRejectsScopeAndKeepsTrivyContract(t *testing.T) {
	at := time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	run, items := secretScanningImportFixture(t, "open", at, 20)
	for _, mutate := range []func(*model.SecurityFinding){func(x *model.SecurityFinding) { x.Asset.Account = "other" }, func(x *model.SecurityFinding) { x.Observation.Account = "other" }, func(x *model.SecurityFinding) { x.Asset.NativeID = "example/other" }, func(x *model.SecurityFinding) { x.Observation.Source = "trivy" }, func(x *model.SecurityFinding) { x.Finding.Category = "vulnerability" }, func(x *model.SecurityFinding) { x.Finding.SourceStatus = "unknown" }, func(x *model.SecurityFinding) { x.Finding.SecretType = "" },
		func(x *model.SecurityFinding) { x.Observation.SourceFindingID = "example/repo:invalid" },
		func(x *model.SecurityFinding) { x.Finding.SecretType = "invalid/type" },
		func(x *model.SecurityFinding) { x.Finding.SecretResolution = "revoked" },
		func(x *model.SecurityFinding) { x.Finding.Severity = model.SeverityCritical },
		func(x *model.SecurityFinding) { x.Finding.Title = "PRIVATE-SYNTHETIC-MARKER" },
		func(x *model.SecurityFinding) { x.Finding.CanonicalKey = "PRIVATE-SYNTHETIC-MARKER" },
		func(x *model.SecurityFinding) { x.Finding.FilePath = "private-path" },
		func(x *model.SecurityFinding) { x.Finding.RuleID = "unexpected" },
		func(x *model.SecurityFinding) { x.Finding.PackageName = "unexpected" },
		func(x *model.SecurityFinding) {
			x.Observation.RawRef = "https://github.com/other/repo/security/code-scanning/42"
		}} {
		changed := items[0]
		mutate(&changed)
		if err := ValidateSecurityImport(run, []model.SecurityFinding{changed}); err == nil {
			t.Fatalf("invalid source accepted: %+v", changed)
		}
	}
	invalidScope := run
	invalidScope.Scope = "not-a-repository"
	if err := ValidateSecurityImport(invalidScope, nil); err == nil {
		t.Fatal("empty snapshot bypassed scope validation")
	}
	trivyRun, trivyItem := importFixture()
	trivyItem.Finding.SourceStatus = model.SourceStatusResolved
	if err := ValidateSecurityImport(trivyRun, []model.SecurityFinding{trivyItem}); err == nil {
		t.Fatal("Trivy may now resolve detections")
	}
	trivyRun, trivyItem = importFixture()
	trivyItem.Finding.RuleID = "unexpected"
	if err := ValidateSecurityImport(trivyRun, []model.SecurityFinding{trivyItem}); err == nil {
		t.Fatal("source metadata crossed contracts")
	}
	for _, which := range []string{"trivy", "code_scanning"} {
		var oldRun model.IngestRun
		var oldItem model.SecurityFinding
		if which == "trivy" {
			oldRun, oldItem = importFixture()
		} else {
			var codeItems []model.SecurityFinding
			oldRun, codeItems = codeScanningImportFixture(t, "open", at, 21)
			oldItem = codeItems[0]
		}
		oldItem.Finding.SecretType = "synthetic_example"
		if err := ValidateSecurityImport(oldRun, []model.SecurityFinding{oldItem}); err == nil {
			t.Fatalf("secret metadata allowed on %s", which)
		}
	}
}
func TestSecretScanningImportRollsBackBatch(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	run, items := secretScanningImportFixture(t, "resolved", time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC), 30)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_secret_scanning BEFORE INSERT ON observations BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportSecurityFindings(ctx, run, items); err == nil {
		t.Fatal("injected failure accepted")
	}
	for _, table := range []string{"assets", "findings", "observations", "events", "ingest_runs"} {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("rollback %s=%d %v", table, n, err)
		}
	}
}
