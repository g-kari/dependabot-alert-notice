package enrichmentrefresh

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

// This is an explicitly authored synthetic strict offline envelope. It is not
// evidence of compatibility with a live EPSS/CISA response or transport.
const contractEPSS = "#model_version:synthetic-contract,score_date:2026-11-10\ncve,epss,percentile\nCVE-2026-1234,0,0\n"

type contractFetcher struct {
	calls  int
	source string
}

func (f *contractFetcher) Fetch(ctx context.Context, source string) ([]byte, error) {
	f.calls++
	f.source = source
	return []byte(contractEPSS), nil
}

func contractStore(t *testing.T, finding bool) *store.Store {
	t.Helper()
	db, err := store.NewWithPath(filepath.Join(t.TempDir(), "synthetic-refresh.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close synthetic store: %v", err)
		}
	})
	if finding {
		at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
		_, err := db.SaveObservedWithError(context.Background(), &model.AlertRecord{
			Alert: model.Alert{
				Owner: "example", Repo: "synthetic", Number: 1, State: "open",
				CVEID: "CVE-2026-1234", PackageName: "synthetic", PackageEcosystem: "npm",
				Summary: "Synthetic contract fixture", Severity: model.SeverityHigh,
				CreatedAt: at, UpdatedAt: at,
				HTMLURL: "https://github.com/example/synthetic/security/dependabot/1",
			},
			NotifiedAt: at,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestRefreshOnceContractEmptyPageKeepsCursorWithoutRun(t *testing.T) {
	db := contractStore(t, false)
	fetcher := &contractFetcher{}
	clockCalls, uuidCalls := 0, 0
	service := Service{
		Store: db, Fetcher: fetcher,
		Clock:   func() time.Time { clockCalls++; return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) },
		NewUUID: func() (string, error) { uuidCalls++; return "30000000-0000-4000-8000-000000000001", nil },
	}
	out, err := service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", After: "previous-cursor", Limit: 1})
	if err != nil || out.Outcome != "exhausted" || !out.Exhausted || out.Advance || out.NextAfter != "previous-cursor" || out.Scanned != 0 || out.Targets != 0 || out.RunID != "" || out.Pending != nil {
		t.Fatalf("empty-page result=%+v err=%v", out, err)
	}
	if clockCalls != 0 || uuidCalls != 0 || fetcher.calls != 0 {
		t.Fatalf("empty page used dependencies clock=%d uuid=%d fetch=%d", clockCalls, uuidCalls, fetcher.calls)
	}
	runs, err := db.QueryIngestRuns(context.Background())
	if err != nil || len(runs) != 0 {
		t.Fatalf("empty page created receipt runs=%+v err=%v", runs, err)
	}
}

func TestRefreshOnceContractFreshReservationUsesStrictSyntheticInput(t *testing.T) {
	db := contractStore(t, true)
	fetcher := &contractFetcher{}
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	clocks := []time.Time{start, start.Add(time.Minute), start.Add(2 * time.Minute)}
	clockCalls, uuidCalls := 0, 0
	runID := "30000000-0000-4000-8000-000000000002"
	service := Service{
		Store: db, Fetcher: fetcher,
		Clock: func() time.Time {
			if clockCalls >= len(clocks) {
				t.Fatal("unexpected clock read")
			}
			at := clocks[clockCalls]
			clockCalls++
			return at
		},
		NewUUID: func() (string, error) { uuidCalls++; return runID, nil },
	}
	out, err := service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
	if err != nil || out.Outcome != "success" || out.RunID != runID || !out.Advance || out.NextAfter == "" || out.NextAfter != out.ScanAfter || out.Scanned != 1 || out.Targets != 1 || out.Pending != nil {
		t.Fatalf("fresh result=%+v err=%v", out, err)
	}
	if clockCalls != 3 || uuidCalls != 1 || fetcher.calls != 1 || fetcher.source != "epss" {
		t.Fatalf("fresh calls clock=%d uuid=%d fetch=%d source=%q", clockCalls, uuidCalls, fetcher.calls, fetcher.source)
	}
	page, err := db.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 200})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("common read page=%+v err=%v", page, err)
	}
	e := page.Enrichments[page.Items[0].ID].EPSS
	pub := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	if e == nil || e.Source != "epss" || e.RunID != runID || e.Version != "synthetic-contract" || e.EPSS == nil || *e.EPSS != 0 || !e.PublishedAt.Equal(pub) || !e.ObservedAt.Equal(clocks[1]) {
		t.Fatalf("known synthetic evidence/provenance absent=%+v", e)
	}
	status, err := db.QueryConnectorStatusPageV2(context.Background(), store.ConnectorStatusQuery{Source: "epss_feed", AsOf: clocks[2], Limit: 200})
	if err != nil || status.Total != 1 || len(status.Items) != 1 || status.Items[0].LatestAttempt.ID != runID || status.Items[0].Status != "success" {
		t.Fatalf("v2 feed receipt=%+v err=%v", status, err)
	}
}

func TestRefreshOnceContractRunningReplayNeverRefetchesOrFails(t *testing.T) {
	db := contractStore(t, true)
	ctx := context.Background()
	page, err := db.QuerySecurityEnrichmentRefreshTargets(ctx, "", 200)
	if err != nil || len(page.Targets) != 1 {
		t.Fatalf("replay fixture page=%+v err=%v", page, err)
	}
	scope, err := threat.OfflineSelectionScope([]string{page.Targets[0].CVEID})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	runID := "30000000-0000-4000-8000-000000000003"
	attempt := store.SecurityEnrichmentRefreshAttempt{RunID: runID, Connector: "epss_feed", Scope: scope, StartedAt: start, Targets: page.Targets}
	if _, err := db.BeginSecurityEnrichmentRefresh(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	fetcher := &contractFetcher{}
	clockCalls, uuidCalls := 0, 0
	service := Service{
		Store: db, Fetcher: fetcher,
		Clock:   func() time.Time { clockCalls++; return start },
		NewUUID: func() (string, error) { uuidCalls++; return runID, nil },
	}
	out, err := service.RefreshOnce(ctx, Request{Connector: "epss_feed", Limit: 200})
	if err == nil || out.Outcome != "pending" || out.RunID != runID || out.Advance || out.Pending == nil || out.Pending.Attempt.RunID != runID {
		t.Fatalf("running replay result=%+v err=%v", out, err)
	}
	if clockCalls != 1 || uuidCalls != 1 || fetcher.calls != 0 {
		t.Fatalf("replay acquired ownership clock=%d uuid=%d fetch=%d", clockCalls, uuidCalls, fetcher.calls)
	}
	state, err := db.ReadSecurityEnrichmentRefreshAttempt(ctx, attempt, nil)
	if err != nil || state.State != "running" {
		t.Fatalf("replay changed reservation=%+v err=%v", state, err)
	}
}

type canceledPageRepository struct {
	Repository
	cancel context.CancelFunc
}

func (r canceledPageRepository) QuerySecurityEnrichmentRefreshTargets(ctx context.Context, after string, limit int) (store.SecurityEnrichmentRefreshTargetPage, error) {
	if _, err := r.Repository.QuerySecurityEnrichmentRefreshTargets(ctx, after, limit); err != nil {
		return store.SecurityEnrichmentRefreshTargetPage{}, err
	}
	r.cancel()
	return store.SecurityEnrichmentRefreshTargetPage{Targets: []store.SecurityEnrichmentRefreshTarget{}, Scanned: 1, After: "zz-last-scanned-ineligible"}, nil
}

func TestRefreshOnceContractCanceledIneligiblePageDoesNotAdvance(t *testing.T) {
	db := contractStore(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetcher := &contractFetcher{}
	clockCalls, uuidCalls := 0, 0
	service := Service{
		Store: canceledPageRepository{Repository: db, cancel: cancel}, Fetcher: fetcher,
		Clock:   func() time.Time { clockCalls++; return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) },
		NewUUID: func() (string, error) { uuidCalls++; return "30000000-0000-4000-8000-000000000004", nil },
	}
	out, err := service.RefreshOnce(ctx, Request{Connector: "epss_feed", After: "previous-cursor", Limit: 1})
	if !errors.Is(err, context.Canceled) || out.Advance || out.NextAfter != "previous-cursor" || out.RunID != "" || out.Pending != nil {
		t.Fatalf("canceled query advanced result=%+v err=%v", out, err)
	}
	if clockCalls != 0 || uuidCalls != 0 || fetcher.calls != 0 {
		t.Fatalf("canceled page continued clock=%d uuid=%d fetch=%d", clockCalls, uuidCalls, fetcher.calls)
	}
}
