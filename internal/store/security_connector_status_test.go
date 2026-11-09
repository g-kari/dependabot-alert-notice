package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func newConnectorStatusStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewWithPath(filepath.Join(t.TempDir(), "connectors.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close connector store: %v", err)
		}
	})
	return s
}

func insertConnectorStatusRun(t *testing.T, s *Store, number int, source, scope, result, coverage string, start time.Time, finish *time.Time) string {
	t.Helper()
	id := fmt.Sprintf("00000000-0000-4000-8000-%012d", number)
	run := model.IngestRun{ID: id, Connector: source, Scope: scope, StartedAt: start, FinishedAt: finish, Result: result, Coverage: coverage, Cursor: "private-receipt-sentinel", Error: "private_error_sentinel"}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertIngestRun(context.Background(), tx, run); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestConnectorStatusSeparatesLatestFailureAndLastSuccess(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	old, recent := at.Add(-time.Hour), at.Add(-time.Minute)
	success := insertConnectorStatusRun(t, s, 1, "dependabot", "account/repo", "success", "full", old, &old)
	failure := insertConnectorStatusRun(t, s, 2, "dependabot", "account/repo", "failed", "unknown", recent, &recent)
	page, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page=%+v, want one recorded scope", page)
	}
	item := page.Items[0]
	if item.Status != "failed" || item.Coverage != "unknown" || item.LatestAttempt.ID != failure || item.LastSuccess == nil || item.LastSuccess.ID != success || *item.LastSuccess.AgeSeconds != 3600 {
		t.Fatalf("item=%+v, old success must not hide current failure", item)
	}
	if item.RecordedRuns != (ConnectorRunCounts{Total: 2, Success: 1, Failed: 1}) || item.Liveness != "unknown" {
		t.Fatalf("counts/liveness=%+v", item)
	}
	if page.Boundary.ConfiguredScopes != nil || page.Boundary.UnscannedScopes != nil || page.Boundary.AssetDenominator != nil || page.Boundary.AttemptHistory != "unknown" {
		t.Fatalf("observed scopes cannot establish coverage: %+v", page.Boundary)
	}
	body := securityQueryTestJSON(t, page)
	for _, forbidden := range []string{"private-receipt-sentinel", "private_error_sentinel", "cursor", "body_json", "raw_ref"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("status leaked %q", forbidden)
		}
	}
}

func TestConnectorStatusExactSourceScopePagingAndCounts(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for i, pair := range [][2]string{{"dependabot", "account/repo"}, {"dependabot", "other/repo"}, {"trivy", "account/repo"}, {"dependabot", "Account/repo"}, {"epss_offline", "cves-sha256:abc"}, {"kev_offline", "cves-sha256:abc"}, {"github_code_scanning", "account/repo"}, {"github_secret_scanning", "account/repo"}} {
		insertConnectorStatusRun(t, s, i+1, pair[0], pair[1], "success", "partial", at, &at)
	}
	for _, tc := range []struct {
		name, source, scope         string
		limit, offset, total, items int
	}{
		{"all", "", "", 50, 0, 8, 8},
		{"source", "dependabot", "", 50, 0, 3, 3},
		{"exact scope across sources", "", "account/repo", 50, 0, 4, 4},
		{"offline CVE selection across sources", "", "cves-sha256:abc", 50, 0, 2, 2},
		{"case-sensitive scope", "", "Account/repo", 50, 0, 1, 1},
		{"combined", "dependabot", "account/repo", 50, 0, 1, 1},
		{"literal", "", "%' OR 1=1 --", 50, 0, 0, 0},
		{"page", "", "", 1, 1, 8, 1},
		{"past end", "", "", 200, 1000000, 8, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{Source: tc.source, Scope: tc.scope, AsOf: at, Limit: tc.limit, Offset: tc.offset})
			if err != nil || page.Total != tc.total || len(page.Items) != tc.items || page.Items == nil || page.Limit != tc.limit || page.Offset != tc.offset {
				t.Fatalf("query=%+v page=%+v err=%v", tc, page, err)
			}
			// Scope is exact and source-specific: repository collection must not
			// include the independent EPSS/KEV CVE-selection scope (or vice versa).
			var sources []string
			for _, item := range page.Items {
				if tc.scope != "" && item.Scope != tc.scope {
					t.Fatalf("scope=%q returned different scope=%q source=%q", tc.scope, item.Scope, item.Source)
				}
				sources = append(sources, item.Source)
			}
			var wantSources []string
			switch tc.name {
			case "exact scope across sources":
				wantSources = []string{"dependabot", "github_code_scanning", "github_secret_scanning", "trivy"}
			case "offline CVE selection across sources":
				wantSources = []string{"epss_offline", "kev_offline"}
			case "case-sensitive scope":
				wantSources = []string{"dependabot"}
			}
			if wantSources != nil && !reflect.DeepEqual(sources, wantSources) {
				t.Fatalf("scope=%q sources=%v, want exactly %v", tc.scope, sources, wantSources)
			}
			if tc.name == "page" && page.Items[0].Scope != "account/repo" {
				t.Fatalf("binary source/scope order=%+v", page.Items)
			}
		})
	}
}

func TestConnectorStatusNanosecondTiesAndCompletionOrdering(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	nano := at.Add(time.Nanosecond)
	laterFinish := at.Add(time.Second)
	insertConnectorStatusRun(t, s, 1, "trivy", "scope", "success", "partial", at, &laterFinish)
	insertConnectorStatusRun(t, s, 2, "trivy", "scope", "success", "partial", nano, &nano)
	latest := insertConnectorStatusRun(t, s, 3, "trivy", "scope", "partial", "unknown", nano, &nano)
	lastSuccess := insertConnectorStatusRun(t, s, 4, "trivy", "scope", "success", "partial", at, &laterFinish)
	page, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: laterFinish, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	item := page.Items[0]
	if item.LatestAttempt.ID != latest || item.LastSuccess.ID != lastSuccess || item.Status != "partial" || item.RecordedRuns.Total != 4 {
		t.Fatalf("nanoseconds/IDs/completion order=%+v", item)
	}
}

func TestConnectorStatusFutureRunningAndNoSuccessAreUnknownLiveness(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	future := at.Add(time.Nanosecond)
	insertConnectorStatusRun(t, s, 1, "trivy", "future", "success", "partial", future, &future)
	insertConnectorStatusRun(t, s, 2, "trivy", "running", "running", "unknown", at.Add(-200*time.Hour), nil)
	page, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	f, r := page.Items[0], page.Items[1]
	if f.Status != "unknown" || f.Coverage != "unknown" || !f.LatestAttempt.Future || f.LatestAttempt.AgeSeconds != nil || f.LastSuccess == nil || !f.LastSuccess.Future {
		t.Fatalf("future evidence=%+v", f)
	}
	if r.Status != "running" || r.LastSuccess != nil || r.Liveness != "unknown" || *r.LatestAttempt.AgeSeconds != 720000 {
		t.Fatalf("running is recorded state, not guessed stuck/liveness: %+v", r)
	}
}

func TestConnectorStatusReadsOnlyBoundedScalarMetadata(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	// Poison receipt bodies: this query must not decode or load all historical
	// receipts merely to select the bounded latest scalar records.
	for i := 1; i <= 215; i++ {
		old := at.Add(-time.Duration(i) * time.Minute)
		insertConnectorStatusRun(t, s, i, "trivy", "scope", "failed", "unknown", old, &old)
	}
	id := insertConnectorStatusRun(t, s, 999, "trivy", "scope", "success", "partial", at, &at)
	if _, err := s.db.Exec(`UPDATE ingest_runs SET body_json='{"not_a_run":"private_payload_sentinel"}'`); err != nil {
		t.Fatal(err)
	}
	page, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 1})
	if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].LatestAttempt.ID != id || page.Items[0].RecordedRuns.Total != 216 {
		t.Fatalf("bounded projection=%+v err=%v", page, err)
	}
}

func TestConnectorStatusInvalidQuerySnapshotAndCancelledRead(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for _, query := range []ConnectorStatusQuery{{Limit: 50}, {AsOf: at, Limit: 0}, {AsOf: at, Limit: 201}, {AsOf: at, Limit: 50, Offset: -1}, {AsOf: at, Limit: 50, Offset: 1000001}, {AsOf: at, Limit: 50, Source: "new-provider"}, {AsOf: at, Limit: 50, Scope: " x"}, {AsOf: at, Limit: 50, Scope: "x\x00"}, {AsOf: at, Limit: 50, Scope: strings.Repeat("x", 257)}} {
		if _, err := s.QueryConnectorStatusPage(context.Background(), query); err == nil {
			t.Fatalf("accepted invalid query=%+v", query)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.QueryConnectorStatusPage(ctx, ConnectorStatusQuery{AsOf: at, Limit: 50}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read error=%v", err)
	}
	id := insertConnectorStatusRun(t, s, 1, "trivy", "scope", "success", "partial", at, &at)
	for _, update := range []string{`UPDATE ingest_runs SET started_at='bad'`, `UPDATE ingest_runs SET id='bad'`, `UPDATE ingest_runs SET finished_at=NULL`, `UPDATE ingest_runs SET started_at='2026-11-09T12:00:00+00:00'`} {
		t.Run(update, func(t *testing.T) {
			if _, err := s.db.Exec(update); err != nil {
				t.Fatal(err)
			}
			if _, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 50}); !errors.Is(err, ErrInvalidConnectorSnapshot) {
				t.Fatalf("malformed snapshot error=%v", err)
			}
			if _, err := s.db.Exec(`UPDATE ingest_runs SET id=?,started_at=?,finished_at=?`, id, at.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConnectorStatusLeavesEveryDatabaseTableUnchanged(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	seed := &model.AlertRecord{Alert: model.Alert{Owner: "example", Repo: "synthetic", Number: 1, State: "open", Severity: model.SeverityHigh, CreatedAt: at, UpdatedAt: at}, NotifiedAt: at}
	if _, err := s.SaveObservedWithError(context.Background(), seed); err != nil {
		t.Fatal(err)
	}
	run, feed := enrichmentFixture(t, 902, "epss", at, at)
	mustEnrichment(t, s, run, feed)
	insertConnectorStatusRun(t, s, 1, "dependabot", "example/synthetic", "failed", "unknown", at, &at)
	before := previewDatabaseState(t, s)
	for _, clock := range []time.Time{at, at.Add(time.Nanosecond), at.Add(-100 * time.Hour)} {
		for _, query := range []ConnectorStatusQuery{{AsOf: clock, Limit: 1}, {AsOf: clock, Limit: 200, Offset: 1}, {AsOf: clock, Limit: 50, Source: "dependabot"}, {AsOf: clock, Limit: 50, Scope: "missing"}} {
			if _, err := s.QueryConnectorStatusPage(context.Background(), query); err != nil {
				t.Fatal(err)
			}
		}
	}
	if after := previewDatabaseState(t, s); !reflect.DeepEqual(before, after) {
		t.Fatal("connector status read changed database tables")
	}
}
