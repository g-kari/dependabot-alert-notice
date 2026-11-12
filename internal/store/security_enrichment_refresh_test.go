package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

func insertRefreshFinding(t *testing.T, s *Store, f model.Finding) {
	t.Helper()
	body, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`INSERT INTO findings(id,category,asset_id,canonical_key,severity,triage_status,source_status,first_seen,last_seen,fingerprint,body_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, f.ID, f.Category, f.AssetID, f.CanonicalKey, f.Severity, f.TriageStatus, f.SourceStatus, f.FirstSeen.Format(time.RFC3339Nano), f.LastSeen.Format(time.RFC3339Nano), strings.Repeat("b", 64), string(body))
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshTargetsUseLastScannedRowAndNeverInferCVE(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 910)
	_, item := importFixture()
	for i := 1; i <= 205; i++ {
		f := item.Finding
		f.ID = fmt.Sprintf("zz-%03d", i)
		f.VulnerabilityID = "cve-2026-1234"
		if i == 205 {
			f.VulnerabilityID = "CVE-2026-1234"
		}
		insertRefreshFinding(t, s, f)
	}
	page, err := s.QuerySecurityEnrichmentRefreshTargets(context.Background(), c.Attempt.Targets[0].FindingID, 200)
	if err != nil || page.Scanned != 200 || page.After != "zz-200" || len(page.Targets) != 0 {
		t.Fatalf("bounded scan=%+v err=%v", page, err)
	}
	next, err := s.QuerySecurityEnrichmentRefreshTargets(context.Background(), page.After, 200)
	if err != nil || next.Scanned != 5 || next.After != "zz-205" || len(next.Targets) != 1 || next.Targets[0].FindingID != "zz-205" {
		t.Fatalf("scan cursor skipped rows=%+v err=%v", next, err)
	}
	empty, err := s.QuerySecurityEnrichmentRefreshTargets(context.Background(), next.After, 1)
	if err != nil || empty.Scanned != 0 || empty.After != "" || empty.Targets == nil || len(empty.Targets) != 0 {
		t.Fatalf("empty=%+v err=%v", empty, err)
	}
	for _, limit := range []int{0, 201, -1} {
		if _, err := s.QuerySecurityEnrichmentRefreshTargets(context.Background(), "", limit); err == nil {
			t.Fatalf("accepted limit=%d", limit)
		}
	}
	for _, change := range []string{"lower", "space", "GHSA", "substring", "category", "id", "asset", "key", "duplicate-json", "oversize"} {
		t.Run(change, func(t *testing.T) {
			f := item.Finding
			category, asset, key := f.Category, f.AssetID, f.CanonicalKey
			switch change {
			case "lower":
				f.VulnerabilityID = "cve-2026-1234"
			case "space":
				f.VulnerabilityID = " CVE-2026-1234"
			case "GHSA":
				f.VulnerabilityID = "GHSA-abcd-efgh-ijkl"
				f.Title = "CVE-2026-1234"
			case "substring":
				f.VulnerabilityID = "CVE-2026-1234-extra"
			case "category":
				category = "code_scanning"
			case "id":
				f.ID = "different"
			case "asset":
				asset = "different"
			case "key":
				key = "different"
			case "oversize":
				f.Title = strings.Repeat("x", refreshMaxFindingBytes)
			}
			body, err := json.Marshal(f)
			if err != nil {
				t.Fatal(err)
			}
			if change == "duplicate-json" {
				body = append([]byte(`{"id":"duplicate",`), body[1:]...)
			}
			if _, ok := refreshTarget(item.Finding.ID, category, asset, key, string(body)); ok {
				t.Fatalf("accepted %s", change)
			}
		})
	}
}

func TestRefreshCompletionRejectsChangedTargetsAndDuplicateManifestAtomically(t *testing.T) {
	for _, change := range []string{"body", "row-category", "row-asset", "row-key", "wrong-target", "duplicate", "connector", "scope"} {
		t.Run(change, func(t *testing.T) {
			s, c := refreshContractFixture(t, "epss", 911)
			ctx := context.Background()
			if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "body":
				if _, err := s.db.Exec(`UPDATE findings SET body_json=json_set(body_json,'$.title','mutated')`); err != nil {
					t.Fatal(err)
				}
			case "row-category":
				if _, err := s.db.Exec(`UPDATE findings SET category='code_scanning'`); err != nil {
					t.Fatal(err)
				}
			case "row-asset":
				if _, err := s.db.Exec(`INSERT INTO assets(id,type,provider,account,region,native_id,environment,criticality,body_json) VALUES('wrong','filesystem','trivy','demo','','second','','','{}')`); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`UPDATE findings SET asset_id='wrong'`); err != nil {
					t.Fatal(err)
				}
			case "row-key":
				if _, err := s.db.Exec(`UPDATE findings SET canonical_key='wrong'`); err != nil {
					t.Fatal(err)
				}
			case "wrong-target":
				c.Attempt.Targets = slices.Clone(c.Attempt.Targets)
				c.Attempt.Targets[0].Revision = strings.Repeat("b", 64)
			case "duplicate":
				c.Attempt.Targets = append(slices.Clone(c.Attempt.Targets), c.Attempt.Targets[0])
			case "connector":
				c.Attempt.Connector = "kev_feed"
			case "scope":
				c.Attempt.Scope = "different"
			}
			before := previewDatabaseState(t, s)
			if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err == nil {
				t.Fatalf("accepted %s", change)
			}
			if !reflect.DeepEqual(before, previewDatabaseState(t, s)) {
				t.Fatalf("%s partially wrote data", change)
			}
		})
	}
}

func TestRefreshAtomicRollbackAtManifestObservationAndSuccessUpdate(t *testing.T) {
	for _, stage := range []string{"manifest", "second-observation", "success-update"} {
		t.Run(stage, func(t *testing.T) {
			s, c := refreshContractFixture(t, "epss", 912)
			ctx := context.Background()
			oldRun, oldFeed := enrichmentFixture(t, 800, "epss", c.Feed.PublishedAt.Add(-time.Hour), c.Feed.ObservedAt)
			mustEnrichment(t, s, oldRun, oldFeed)
			_, item := importFixture()
			item.Finding.ID = "second-finding"
			item.Finding.VulnerabilityID = "CVE-2026-5678"
			insertRefreshFinding(t, s, item.Finding)
			targets, err := s.QuerySecurityEnrichmentRefreshTargets(ctx, "", 200)
			if err != nil {
				t.Fatal(err)
			}
			c.Attempt.Targets = targets.Targets
			c.Feed.SelectedCVEs = []string{"CVE-2026-1234", "CVE-2026-5678"}
			c.Attempt.Scope, err = threat.OfflineSelectionScope(c.Feed.SelectedCVEs)
			if err != nil {
				t.Fatal(err)
			}
			c.Feed.Entries = append(slices.Clone(c.Feed.Entries), model.SecurityEnrichmentEntry{CVEID: "CVE-2026-5678", EPSS: c.Feed.Entries[0].EPSS, Percentile: c.Feed.Entries[0].Percentile})
			if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
				t.Fatal(err)
			}
			sql := `CREATE TRIGGER reject_refresh BEFORE INSERT ON security_enrichment_runs BEGIN SELECT RAISE(ABORT,'synthetic'); END`
			if stage == "second-observation" {
				sql = `CREATE TRIGGER reject_refresh BEFORE INSERT ON security_enrichment_observations WHEN NEW.cve_id='CVE-2026-5678' BEGIN SELECT RAISE(ABORT,'synthetic'); END`
			}
			if stage == "success-update" {
				sql = `CREATE TRIGGER reject_refresh BEFORE UPDATE ON ingest_runs WHEN NEW.result='success' BEGIN SELECT RAISE(ABORT,'synthetic'); END`
			}
			if _, err := s.db.Exec(sql); err != nil {
				t.Fatal(err)
			}
			before := previewDatabaseState(t, s)
			if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err == nil {
				t.Fatal("accepted injected storage failure")
			}
			if !reflect.DeepEqual(before, previewDatabaseState(t, s)) {
				t.Fatal("failed completion changed any stored table")
			}
			state, err := s.ReconcileSecurityEnrichmentRefresh(ctx, c)
			if err != nil || state.State != "running" {
				t.Fatalf("rollback readback=%+v err=%v", state, err)
			}
			if _, err := s.db.Exec(`DROP TRIGGER reject_refresh`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
				t.Fatalf("same-ID retry after bounded running readback: %v", err)
			}
		})
	}
}

func TestRefreshFailureCodesLastGoodAndSuccessCannotBeDowngraded(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 913)
	ctx := context.Background()
	old, feed := enrichmentFixture(t, 801, "epss", c.Feed.PublishedAt.Add(-time.Hour), c.Feed.ObservedAt)
	mustEnrichment(t, s, old, feed)
	before, err := s.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"private-error", "", "fetch_failed with data", strings.Repeat("x", 100)} {
		if _, err := s.FailSecurityEnrichmentRefresh(ctx, c.Attempt, code, c.FinishedAt); err == nil {
			t.Fatalf("accepted arbitrary code=%q", code)
		}
	}
	if _, err := s.FailSecurityEnrichmentRefresh(ctx, c.Attempt, "parse_failed", c.FinishedAt); err != nil {
		t.Fatal(err)
	}
	if replay, err := s.FailSecurityEnrichmentRefresh(ctx, c.Attempt, "parse_failed", c.FinishedAt); err != nil || !replay {
		t.Fatalf("failure retry replay=%v err=%v", replay, err)
	}
	after, err := s.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failure removed or changed last-good finding evidence")
	}
	c.Attempt.RunID = "10000000-0000-4000-8000-000000000914"
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
		t.Fatal(err)
	}
	stable := previewDatabaseState(t, s)
	if _, err := s.FailSecurityEnrichmentRefresh(ctx, c.Attempt, "store_failed", c.FinishedAt); !errors.Is(err, ErrIngestConflict) {
		t.Fatalf("success downgrade error=%v", err)
	}
	for _, change := range []string{"digest", "version", "finish", "observed"} {
		changed := c
		switch change {
		case "digest":
			changed.OriginalDigest = "sha256:" + strings.Repeat("b", 64)
		case "version":
			changed.Feed.Version = "different"
		case "finish":
			changed.FinishedAt = changed.FinishedAt.Add(time.Second)
		case "observed":
			changed.Feed.ObservedAt = changed.Feed.ObservedAt.Add(time.Second)
		}
		if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, changed); !errors.Is(err, ErrIngestConflict) {
			t.Fatalf("same-ID %s collision=%v", change, err)
		}
	}
	if !reflect.DeepEqual(stable, previewDatabaseState(t, s)) {
		t.Fatal("same-ID collision rewrote evidence")
	}
}

func TestRefreshPublicationOrderObservationTieAndPositiveOnlyMissing(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 920)
	ctx := context.Background()
	complete := func(c SecurityEnrichmentRefreshCompletion) {
		t.Helper()
		if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	complete(c)
	old := c
	old.Attempt.RunID = "10000000-0000-4000-8000-000000000921"
	old.Feed.PublishedAt = c.Feed.PublishedAt.Add(-time.Hour)
	old.Feed.ObservedAt = c.Feed.ObservedAt.Add(time.Second)
	v := 0.9
	old.Feed.Entries = slices.Clone(c.Feed.Entries)
	old.Feed.Entries[0].EPSS = &v
	complete(old)
	tie := c
	tie.Attempt.RunID = "10000000-0000-4000-8000-000000000922"
	tie.Feed.ObservedAt = c.Feed.ObservedAt.Add(2 * time.Second)
	complete(tie)
	detail, err := s.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
	if err != nil || detail.Enrichment == nil || detail.Enrichment.EPSS == nil || detail.Enrichment.EPSS.RunID != tie.Attempt.RunID || *detail.Enrichment.EPSS.EPSS != 0 {
		t.Fatalf("publication/observation/zero=%+v err=%v", detail.Enrichment, err)
	}
	conflict := c
	conflict.Attempt.RunID = "10000000-0000-4000-8000-000000000923"
	conflict.Feed.Entries = slices.Clone(c.Feed.Entries)
	conflict.Feed.Entries[0].EPSS = &v
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, conflict.Attempt); err != nil {
		t.Fatal(err)
	}
	before := previewDatabaseState(t, s)
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, conflict); !errors.Is(err, ErrIngestConflict) {
		t.Fatalf("same publication contradiction=%v", err)
	}
	if !reflect.DeepEqual(before, previewDatabaseState(t, s)) {
		t.Fatal("publication conflict partially wrote")
	}
	missing := c
	missing.Attempt.RunID = "10000000-0000-4000-8000-000000000924"
	missing.Feed.PublishedAt = c.Feed.PublishedAt.Add(time.Minute)
	missing.Feed.Entries = nil
	complete(missing)
	detail, err = s.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
	if err != nil || detail.Enrichment.EPSS.RunID != tie.Attempt.RunID {
		t.Fatal("missing EPSS synthesized zero or cleared last-good")
	}
	kev := c
	kev.Attempt.RunID = "10000000-0000-4000-8000-000000000925"
	kev.Attempt.Connector = "kev_feed"
	kev.Feed.Source = "kev"
	kev.Feed.Entries = []model.SecurityEnrichmentEntry{{CVEID: "CVE-2026-1234", KEV: true, KEVDateAdded: &kev.Feed.PublishedAt}}
	complete(kev)
	absent := kev
	absent.Attempt.RunID = "10000000-0000-4000-8000-000000000926"
	absent.Feed.PublishedAt = c.Feed.PublishedAt.Add(time.Minute)
	absent.Feed.Entries = nil
	complete(absent)
	detail, err = s.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
	if err != nil || detail.Enrichment.KEV == nil || !detail.Enrichment.KEV.KEV || detail.Enrichment.KEV.RunID != kev.Attempt.RunID {
		t.Fatal("KEV non-inclusion fabricated false")
	}
}

func TestRefreshReconciliationMissingRunningTamperedSuccessAndCancelledUnknown(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 930)
	ctx := context.Background()
	state, err := s.ReconcileSecurityEnrichmentRefresh(ctx, c)
	if err != nil || state.State != "missing" {
		t.Fatalf("missing=%+v err=%v", state, err)
	}
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	before := previewDatabaseState(t, s)
	if replay, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil || !replay {
		t.Fatalf("begin retry replay=%v err=%v", replay, err)
	}
	state, err = s.ReconcileSecurityEnrichmentRefresh(ctx, c)
	if err != nil || state.State != "running" {
		t.Fatalf("running=%+v err=%v", state, err)
	}
	if !reflect.DeepEqual(before, previewDatabaseState(t, s)) {
		t.Fatal("readback/begin replay wrote state")
	}
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE security_enrichment_runs SET original_digest='wrong' WHERE ingest_run_id=?`, c.Attempt.RunID); err != nil {
		t.Fatal(err)
	}
	state, err = s.ReconcileSecurityEnrichmentRefresh(ctx, c)
	if err == nil || state.State != "unknown" {
		t.Fatalf("tampered manifest falsely established success=%+v err=%v", state, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	state, err = s.ReconcileSecurityEnrichmentRefresh(cancelled, c)
	if !errors.Is(err, context.Canceled) || state.State != "unknown" {
		t.Fatalf("cancelled=%+v err=%v", state, err)
	}
}

func TestRefreshInvalidMetadataIsRejectedBeforeDatabase(t *testing.T) {
	_, base := refreshContractFixture(t, "epss", 940)
	for _, change := range []string{"missing-publication", "missing-observation", "missing-version", "missing-finish", "digest", "future-publication", "observation-before-start", "finish-before-observation", "source", "noncanonical-selection", "too-many-targets"} {
		t.Run(change, func(t *testing.T) {
			c := base
			switch change {
			case "missing-publication":
				c.Feed.PublishedAt = time.Time{}
			case "missing-observation":
				c.Feed.ObservedAt = time.Time{}
			case "missing-version":
				c.Feed.Version = ""
			case "missing-finish":
				c.FinishedAt = time.Time{}
			case "digest":
				c.OriginalDigest = "sha256:invalid"
			case "future-publication":
				c.Feed.PublishedAt = c.Feed.ObservedAt.Add(time.Second)
			case "observation-before-start":
				c.Attempt.StartedAt = c.Feed.ObservedAt.Add(time.Second)
			case "finish-before-observation":
				c.FinishedAt = c.Feed.ObservedAt.Add(-time.Second)
			case "source":
				c.Feed.Source = "epss_feed"
			case "noncanonical-selection":
				c.Feed.SelectedCVEs = []string{" cve-2026-1234 "}
			case "too-many-targets":
				c.Attempt.Targets = make([]SecurityEnrichmentRefreshTarget, 201)
			}
			var absent *Store
			if _, err := absent.CompleteSecurityEnrichmentRefresh(context.Background(), c); err == nil {
				t.Fatalf("accepted %s before DB", change)
			}
		})
	}
}

func TestRefreshReconciliationRejectsCorruptObservationWithoutResending(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 941)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE security_enrichment_observations SET body_json='{}' WHERE ingest_run_id=?`, c.Attempt.RunID); err != nil {
		t.Fatal(err)
	}
	before := previewDatabaseState(t, s)
	state, err := s.ReconcileSecurityEnrichmentRefresh(ctx, c)
	if err == nil || state.State != "unknown" {
		t.Fatalf("corrupt evidence established state=%+v err=%v", state, err)
	}
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, c); err == nil {
		t.Fatal("replay silently replaced corrupt evidence")
	}
	if !reflect.DeepEqual(before, previewDatabaseState(t, s)) {
		t.Fatal("reconcile/replay overwrote corrupt receipt")
	}
}

func TestRefreshConcurrentSameUUIDCompletionWritesOnce(t *testing.T) {
	s, c := refreshContractFixture(t, "epss", 942)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		result SecurityEnrichmentImportResult
		err    error
	}
	answers := make(chan answer, 8)
	for i := 0; i < 8; i++ {
		go func() { r, e := s.CompleteSecurityEnrichmentRefresh(ctx, c); answers <- answer{r, e} }()
	}
	fresh, replayed := 0, 0
	var firstErr error
	for i := 0; i < 8; i++ {
		a := <-answers
		if a.err != nil {
			firstErr = a.err
			continue
		}
		if a.result.Replay {
			replayed++
		} else {
			fresh++
		}
	}
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	if fresh != 1 || replayed != 7 {
		t.Fatalf("same-ID completions fresh=%d replay=%d", fresh, replayed)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM security_enrichment_observations WHERE ingest_run_id=?`, c.Attempt.RunID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("duplicate observations=%d err=%v", n, err)
	}
}

func TestRefreshSharedHelperPreservesOfflineReceiptEncoding(t *testing.T) {
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, empty := range []bool{false, true} {
		run, feed := enrichmentFixture(t, 950, "epss", at.Add(-time.Hour), at)
		if empty {
			feed.Entries = nil
		}
		expectedFeed := feed
		if empty {
			expectedFeed.Entries = []model.SecurityEnrichmentEntry{}
		}
		original, err := json.Marshal(struct {
			Run  model.IngestRun
			Feed model.SecurityEnrichmentFeed
		}{run, expectedFeed})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(original)
		_, _, receipt, err := normalizeSecurityEnrichmentImport(run, feed)
		expected := fmt.Sprintf("%s-v1:%s:%x", run.Connector, run.Cursor, digest)
		if err != nil || receipt != expected {
			t.Fatalf("legacy offline receipt changed empty=%v got=%q want=%q err=%v", empty, receipt, expected, err)
		}
	}
}
