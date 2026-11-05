package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func importFixture() (model.IngestRun, model.SecurityFinding) {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	run := model.IngestRun{ID: "00000000-0000-8000-8000-000000000001", Connector: "trivy", Scope: "demo", StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + strings.Repeat("a", 64)}
	item := model.SecurityFinding{Asset: model.Asset{ID: "00000000-0000-8000-8000-000000000002", Type: "filesystem", Provider: "trivy", Account: "demo", NativeID: "project"}, Finding: model.Finding{ID: "00000000-0000-8000-8000-000000000003", AssetID: "00000000-0000-8000-8000-000000000002", Category: "vulnerability", Title: "Example", VulnerabilityID: "CVE-2026-1234", PackageName: "example", InstalledVersion: "1.0.0", CanonicalKey: `["CVE-2026-1234","npm","example","package-lock.json"]`, Severity: model.SeverityHigh, TriageStatus: "new", SourceStatus: "active", FirstSeen: at, LastSeen: at}, Observation: model.Observation{ID: "00000000-0000-8000-8000-000000000004", Source: "trivy", Account: "demo", SourceFindingID: "native-example", FindingID: "00000000-0000-8000-8000-000000000003", IngestRunID: run.ID, ObservedAt: at, Fingerprint: strings.Repeat("b", 64)}}
	return run, item
}

func TestImportSecurityFindingsAtomicReplayAndConflict(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	run, item := importFixture()
	first, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item, item})
	if err != nil || first.Findings != 1 || first.Observations != 1 || first.Replay {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item})
	if err != nil || !second.Replay {
		t.Fatalf("replay=%+v err=%v", second, err)
	}
	changed := run
	changed.Cursor = "sha256:" + strings.Repeat("c", 64)
	if _, err := s.ImportSecurityFindings(ctx, changed, []model.SecurityFinding{item}); !errors.Is(err, ErrIngestConflict) {
		t.Fatalf("raw conflict=%v", err)
	}
	changedItem := item
	changedItem.Finding.Title = "changed but same supplied raw hash"
	if _, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{changedItem}); !errors.Is(err, ErrIngestConflict) {
		t.Fatalf("normalized conflict=%v", err)
	}
	findings, _ := s.QueryFindings(ctx)
	obs, _ := s.QueryObservations(ctx, item.Finding.ID)
	events, _ := s.QueryEvents(ctx, item.Finding.ID)
	runs, _ := s.QueryIngestRuns(ctx)
	if len(findings) != 1 || len(obs) != 1 || len(events) != 1 || len(runs) != 1 || events[0].Actor != "trivy" {
		t.Fatalf("writes duplicated or workflow changed f=%d o=%d e=%d r=%d", len(findings), len(obs), len(events), len(runs))
	}
	if !strings.Contains(runs[0].Cursor, run.Cursor) {
		t.Fatal("raw digest was not retained")
	}
	if records := s.List(); len(records) != 0 {
		t.Fatalf("legacy records changed: %d", len(records))
	}
}

func TestImportSecurityFindingsRollbackAndNoFalseClosure(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	run, item := importFixture()
	if _, err := s.db.Exec(`CREATE TRIGGER reject_import BEFORE INSERT ON observations BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item}); err == nil {
		t.Fatal("injected failure accepted")
	}
	for _, table := range []string{"assets", "findings", "observations", "events", "ingest_runs"} {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("rollback %s=%d %v", table, n, err)
		}
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_import`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item}); err != nil {
		t.Fatal(err)
	}
	empty := run
	empty.ID = "00000000-0000-8000-8000-000000000005"
	empty.Cursor = "sha256:" + strings.Repeat("d", 64)
	if _, err := s.ImportSecurityFindings(ctx, empty, nil); err != nil {
		t.Fatal(err)
	}
	findings, _ := s.QueryFindings(ctx)
	if len(findings) != 1 || findings[0].SourceStatus != "active" {
		t.Fatal("empty report closed unseen finding")
	}
	empty.ID = "00000000-0000-8000-8000-000000000006"
	empty.Result = "failed"
	if _, err := s.ImportSecurityFindings(ctx, empty, nil); err == nil {
		t.Fatal("failed import accepted as success")
	}
}

func TestImportSecurityFindingsScopeHistoryAndValidation(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	run, item := importFixture()
	rec := phase0Record()
	if !s.SaveObserved(rec) {
		t.Fatal("legacy save failed")
	}
	if _, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item}); err != nil {
		t.Fatal(err)
	}
	oldRun := run
	oldRun.ID = "00000000-0000-8000-8000-000000000007"
	oldAt := run.StartedAt.Add(-time.Hour)
	oldRun.StartedAt = oldAt
	oldRun.FinishedAt = &oldAt
	oldItem := item
	oldItem.Observation.ID = "00000000-0000-8000-8000-000000000008"
	oldItem.Observation.IngestRunID = oldRun.ID
	oldItem.Observation.ObservedAt = oldAt
	oldItem.Finding.FirstSeen = oldAt
	oldItem.Finding.LastSeen = oldAt
	oldItem.Finding.Severity = model.SeverityLow
	oldItem.Observation.Fingerprint = strings.Repeat("e", 64)
	if _, err := s.ImportSecurityFindings(ctx, oldRun, []model.SecurityFinding{oldItem}); err != nil {
		t.Fatal(err)
	}
	findings, _ := s.QueryFindings(ctx)
	if len(findings) != 2 {
		t.Fatal("independent source findings merged")
	}
	for _, f := range findings {
		if f.ID == item.Finding.ID && f.Severity != model.SeverityHigh {
			t.Fatal("stale observation overwrote current finding")
		}
	}
	obs, _ := s.QueryObservations(ctx, item.Finding.ID)
	if len(obs) != 2 {
		t.Fatal("stale evidence was not retained")
	}
	invalid := item
	invalid.Observation.Account = "other"
	newRun := run
	newRun.ID = "00000000-0000-8000-8000-000000000009"
	invalid.Observation.IngestRunID = newRun.ID
	if _, err := s.ImportSecurityFindings(ctx, newRun, []model.SecurityFinding{invalid}); err == nil {
		t.Fatal("cross-account observation accepted")
	}
	invalid = item
	invalid.Observation.IngestRunID = newRun.ID
	invalid.Observation.RawRef = "https://example.test/?token=secret"
	if _, err := s.ImportSecurityFindings(ctx, newRun, []model.SecurityFinding{invalid}); err == nil {
		t.Fatal("URL containing query accepted")
	}
}

func TestImportSecurityFindingsPreservesTriageAndRollsBackLaterItem(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	run, item := importFixture()
	later := item
	later.Finding.ID = "00000000-0000-8000-8000-000000000005"
	later.Observation.ID = "00000000-0000-8000-8000-000000000006"
	later.Observation.FindingID = later.Finding.ID
	later.Observation.SourceFindingID = "second-package"
	if _, err := s.db.Exec(`CREATE TRIGGER reject_second BEFORE INSERT ON observations WHEN NEW.source_finding_id='second-package' BEGIN SELECT RAISE(ABORT,'later item failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item, later}); err == nil {
		t.Fatal("later failure accepted")
	}
	for _, table := range []string{"assets", "findings", "observations", "events", "ingest_runs"} {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("partial batch leaked %s=%d %v", table, n, err)
		}
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_second`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE findings SET triage_status='risk_accepted',body_json=json_set(body_json,'$.triage_status','risk_accepted') WHERE id=?`, item.Finding.ID); err != nil {
		t.Fatal(err)
	}
	nextRun := run
	nextRun.ID = "00000000-0000-8000-8000-000000000007"
	nextAt := run.StartedAt.Add(time.Hour)
	nextRun.StartedAt = nextAt
	nextRun.FinishedAt = &nextAt
	next := item
	next.Observation.ID = "00000000-0000-8000-8000-000000000008"
	next.Observation.IngestRunID = nextRun.ID
	next.Observation.ObservedAt = nextAt
	next.Observation.Fingerprint = strings.Repeat("c", 64)
	next.Finding.FirstSeen = nextAt
	next.Finding.LastSeen = nextAt
	next.Finding.Title = "new evidence"
	if _, err := s.ImportSecurityFindings(ctx, nextRun, []model.SecurityFinding{next}); err != nil {
		t.Fatal(err)
	}
	findings, err := s.QueryFindings(ctx)
	if err != nil || len(findings) != 1 || findings[0].TriageStatus != "risk_accepted" || !findings[0].FirstSeen.Equal(item.Finding.FirstSeen) || !findings[0].LastSeen.Equal(nextAt) {
		t.Fatalf("local triage/history changed: %+v %v", findings, err)
	}
}
