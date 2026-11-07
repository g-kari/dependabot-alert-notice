package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

func enrichmentFixture(t *testing.T, id int, source string, published, observed time.Time) (model.IngestRun, model.SecurityEnrichmentFeed) {
	t.Helper()
	zero := 0.0
	feed := model.SecurityEnrichmentFeed{Source: source, Version: "2026-11-07", PublishedAt: published, ObservedAt: observed, SelectedCVEs: []string{"CVE-2026-1234"}, Entries: []model.SecurityEnrichmentEntry{{CVEID: "CVE-2026-1234", EPSS: &zero, Percentile: &zero}}}
	if source == "kev" {
		feed.Entries = []model.SecurityEnrichmentEntry{{CVEID: "CVE-2026-1234", KEV: true, KEVDateAdded: &published}}
	}
	scope, err := threat.OfflineSelectionScope(feed.SelectedCVEs)
	if err != nil {
		t.Fatal(err)
	}
	return model.IngestRun{ID: fmt.Sprintf("00000000-0000-8000-8000-%012d", id), Connector: source + "_offline", Scope: scope, StartedAt: observed, FinishedAt: &observed, Result: "success", Coverage: "partial", Cursor: "sha256:" + strings.Repeat("a", 64)}, feed
}
func mustEnrichment(t *testing.T, s *Store, run model.IngestRun, feed model.SecurityEnrichmentFeed) {
	t.Helper()
	if _, err := s.ImportSecurityEnrichment(context.Background(), run, feed); err != nil {
		t.Fatal(err)
	}
}
func TestSecurityEnrichmentReplayConflictAndRollback(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	run, feed := enrichmentFixture(t, 100, "epss", at, at)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_enrichment BEFORE INSERT ON security_enrichment_observations BEGIN SELECT RAISE(ABORT,'synthetic failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportSecurityEnrichment(ctx, run, feed); err == nil {
		t.Fatal("accepted injected failure")
	}
	for _, table := range []string{"ingest_runs", "security_enrichment_observations", "security_enrichment_runs"} {
		var n int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("rollback %s: %d %v", table, n, err)
		}
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_enrichment`); err != nil {
		t.Fatal(err)
	}
	mustEnrichment(t, s, run, feed)
	before := s.db.Stats()
	replay, err := s.ImportSecurityEnrichment(ctx, run, feed)
	if err != nil || !replay.Replay || replay.Entries != 1 {
		t.Fatalf("replay=%+v %v stats=%+v", replay, err, before)
	}
	for _, change := range []string{"digest", "selection", "observation", "version", "finish"} {
		t.Run(change, func(t *testing.T) {
			changedRun, changedFeed := run, feed
			switch change {
			case "digest":
				changedRun.Cursor = "sha256:" + strings.Repeat("b", 64)
			case "selection":
				changedFeed.SelectedCVEs = []string{"CVE-2026-1234", "CVE-2026-5678"}
				var err error
				changedRun.Scope, err = threat.OfflineSelectionScope(changedFeed.SelectedCVEs)
				if err != nil {
					t.Fatal(err)
				}
			case "observation":
				changedFeed.ObservedAt = at.Add(time.Hour)
				changedRun.StartedAt = changedFeed.ObservedAt
				changedRun.FinishedAt = &changedFeed.ObservedAt
			case "version":
				changedFeed.Version = "2026-11-08"
			case "finish":
				finish := at.Add(time.Hour)
				changedRun.FinishedAt = &finish
			}
			if _, err := s.ImportSecurityEnrichment(ctx, changedRun, changedFeed); !errors.Is(err, ErrIngestConflict) {
				t.Fatalf("expected conflict: %v", err)
			}
		})
	}
	other, changed := enrichmentFixture(t, 101, "epss", at, at.Add(time.Hour))
	value := 0.2
	changed.Entries[0].EPSS = &value
	if _, err := s.ImportSecurityEnrichment(ctx, other, changed); !errors.Is(err, ErrIngestConflict) {
		t.Fatalf("publication conflict: %v", err)
	}
	changed.Entries = feed.Entries
	changed.Version = "different"
	if _, err := s.ImportSecurityEnrichment(ctx, other, changed); !errors.Is(err, ErrIngestConflict) {
		t.Fatalf("version conflict: %v", err)
	}
	changed.Version = feed.Version
	mustEnrichment(t, s, other, changed)
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ingest_runs`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("runs %d %v", n, err)
	}
}

func TestSecurityEnrichmentOrderingFreshnessAndExactJoin(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	run, feed := enrichmentFixture(t, 100, "epss", now.Add(-time.Hour), now.Add(-time.Minute))
	mustEnrichment(t, s, run, feed)
	oldRun, oldFeed := enrichmentFixture(t, 101, "epss", now.Add(-96*time.Hour), now)
	value := 0.9
	oldFeed.Entries[0].EPSS = &value
	mustEnrichment(t, s, oldRun, oldFeed)
	kevRun, kevFeed := enrichmentFixture(t, 102, "kev", now.Add(-96*time.Hour), now)
	mustEnrichment(t, s, kevRun, kevFeed)
	emptyRun, emptyFeed := enrichmentFixture(t, 103, "kev", now, now)
	emptyFeed.Entries = nil
	mustEnrichment(t, s, emptyRun, emptyFeed)
	var source, version, published, observed, selection, digest string
	var entries int
	if err := s.db.QueryRow(`SELECT source,version,published_at,observed_at,selected_cves_json,entries,original_digest FROM security_enrichment_runs WHERE ingest_run_id=?`, emptyRun.ID).Scan(&source, &version, &published, &observed, &selection, &entries, &digest); err != nil {
		t.Fatal(err)
	}
	if source != "kev" || version != emptyFeed.Version || published != now.Format(time.RFC3339Nano) || observed != now.Format(time.RFC3339Nano) || selection != `["CVE-2026-1234"]` || entries != 0 || digest != emptyRun.Cursor {
		t.Fatalf("empty manifest: %s %s %s %s %s %d %s", source, version, published, observed, selection, entries, digest)
	}
	if result, err := s.ImportSecurityEnrichment(ctx, emptyRun, emptyFeed); err != nil || !result.Replay {
		t.Fatalf("empty replay: %+v %v", result, err)
	}
	findings := []model.Finding{{ID: "exact", Category: "vulnerability", VulnerabilityID: "CVE-2026-1234"}, {ID: "ghsa", Category: "vulnerability", VulnerabilityID: "GHSA-abcd-efgh-ijkl", Title: "CVE-2026-1234"}, {ID: "code", Category: "code_scanning", VulnerabilityID: "CVE-2026-1234"}, {ID: "lower", Category: "vulnerability", VulnerabilityID: "cve-2026-1234"}, {ID: "unknown", Category: "vulnerability", VulnerabilityID: "CVE-2026-9999"}, {ID: "prefix", Category: "vulnerability", VulnerabilityID: "CVE-2026-1234 extra"}}
	for _, test := range []struct {
		name      string
		clock     time.Time
		epssFresh bool
	}{{"present", now, true}, {"boundary", feed.PublishedAt.Add(72 * time.Hour), true}, {"expired", feed.PublishedAt.Add(72*time.Hour + time.Nanosecond), false}, {"future", now.Add(-2 * time.Hour), false}} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			got, err := readFindingEnrichments(ctx, tx, findings, test.clock)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("non-exact join: %+v", got)
			}
			evidence := got["exact"]
			if evidence.EPSS == nil || evidence.EPSS.EPSS == nil || *evidence.EPSS.EPSS != 0 || evidence.EPSS.RunID != run.ID || evidence.EPSS.Fresh != test.epssFresh {
				t.Fatalf("EPSS=%+v", evidence.EPSS)
			}
			if evidence.KEV == nil || !evidence.KEV.KEV || evidence.KEV.Fresh || evidence.KEV.RunID != kevRun.ID {
				t.Fatalf("KEV=%+v", evidence.KEV)
			}
		})
	}
}

func TestSecurityEnrichmentQueriesAndAdditiveMigrationPreserveLegacy(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	legacy := phase0Record()
	if !s.SaveObserved(legacy) {
		t.Fatal("save legacy")
	}
	run, item := importFixture()
	if _, err := s.ImportSecurityFindings(ctx, run, []model.SecurityFinding{item}); err != nil {
		t.Fatal(err)
	}
	beforeRuns, err := s.QueryIngestRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeFindings, err := s.QueryFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeLegacy := s.List()
	// Simulate the pre-003 database: only remove the empty additive fixture schema.
	if _, err := s.db.Exec(`DROP TABLE security_enrichment_observations; DROP TABLE security_enrichment_runs; DELETE FROM app_migrations WHERE version=3`); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateSecurity(); err != nil {
		t.Fatal(err)
	}
	afterRuns, err := s.QueryIngestRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeRuns, afterRuns) || !reflect.DeepEqual(beforeLegacy, s.List()) {
		t.Fatal("additive migration rewrote legacy evidence")
	}
	at := time.Now().UTC()
	enrichRun, feed := enrichmentFixture(t, 100, "epss", at, at)
	mustEnrichment(t, s, enrichRun, feed)
	afterFindings, err := s.QueryFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeFindings, afterFindings) {
		t.Fatal("enrichment changed persisted findings")
	}
	page, err := s.QueryFindingsPage(ctx, FindingQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if page.Enrichments[item.Finding.ID].EPSS == nil {
		t.Fatalf("page enrichment missing: %+v", page)
	}
	detail, err := s.GetFindingDetail(ctx, item.Finding.ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Enrichment == nil || !reflect.DeepEqual(*detail.Enrichment, page.Enrichments[item.Finding.ID]) {
		t.Fatalf("detail mismatch: %+v", detail.Enrichment)
	}
	var versions int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM app_migrations WHERE version=3`).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("migration version %d %v", versions, err)
	}
}

func TestSecurityEnrichmentRejectsInvalidInputBeforeDatabase(t *testing.T) {
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	for _, field := range []string{"connector", "scope", "cursor", "result", "coverage", "error", "id", "start", "finished", "source", "probability", "selection", "entry", "publication"} {
		t.Run(field, func(t *testing.T) {
			run, feed := enrichmentFixture(t, 100, "epss", at, at)
			switch field {
			case "connector":
				run.Connector = "epss"
			case "scope":
				run.Scope = "all"
			case "cursor":
				run.Cursor = "sha256:bad"
			case "result":
				run.Result = "failed"
			case "coverage":
				run.Coverage = "full"
			case "error":
				run.Error = "error"
			case "id":
				run.ID = "invalid"
			case "start":
				run.StartedAt = at.Add(-time.Hour)
			case "finished":
				run.FinishedAt = nil
			case "source":
				feed.Source = "unknown"
			case "probability":
				v := 1.1
				feed.Entries[0].EPSS = &v
			case "selection":
				feed.SelectedCVEs = nil
			case "entry":
				feed.Entries[0].CVEID = "CVE-2026-9999"
			case "publication":
				feed.PublishedAt = at.Add(time.Second)
			}
			var absent *Store
			if _, err := absent.ImportSecurityEnrichment(context.Background(), run, feed); err == nil {
				t.Fatal("invalid input reached database")
			}
		})
	}
}

func TestSecurityEnrichmentUTCReplayAndSubsecondPublicationOrdering(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	run, feed := enrichmentFixture(t, 100, "epss", at, at.Add(time.Hour))
	mustEnrichment(t, s, run, feed)
	zone := time.FixedZone("offset", 9*60*60)
	run.StartedAt = run.StartedAt.In(zone)
	finish := run.FinishedAt.In(zone)
	run.FinishedAt = &finish
	feed.PublishedAt = feed.PublishedAt.In(zone)
	feed.ObservedAt = feed.ObservedAt.In(zone)
	result, err := s.ImportSecurityEnrichment(ctx, run, feed)
	if err != nil || !result.Replay {
		t.Fatalf("UTC equivalent replay %+v %v", result, err)
	}
	newer, newFeed := enrichmentFixture(t, 101, "epss", at.Add(time.Nanosecond), at.Add(time.Minute))
	value := 0.5
	newFeed.Entries[0].EPSS = &value
	mustEnrichment(t, s, newer, newFeed)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	findings := []model.Finding{{ID: "exact", Category: "vulnerability", VulnerabilityID: "CVE-2026-1234"}}
	for _, test := range []struct {
		name  string
		clock time.Time
		fresh bool
	}{{"observed_future", at.Add(30 * time.Second), false}, {"observed_present", at.Add(time.Minute), true}} {
		got, err := readFindingEnrichments(ctx, tx, findings, test.clock)
		if err != nil {
			t.Fatal(err)
		}
		evidence := got["exact"].EPSS
		if evidence == nil || evidence.RunID != newer.ID || evidence.Fresh != test.fresh {
			t.Fatalf("%s evidence=%+v", test.name, evidence)
		}
	}
}
