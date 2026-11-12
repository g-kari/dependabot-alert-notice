package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var connectorStatusV2TestSources = []string{"dependabot", "epss_feed", "epss_offline", "github_code_scanning", "github_secret_scanning", "kev_feed", "kev_offline", "trivy"}

func TestConnectorStatusVersionedSourceRegistries(t *testing.T) {
	for _, source := range connectorStatusV2TestSources {
		wantV1 := source != "epss_feed" && source != "kev_feed"
		if got := IsConnectorStatusSource(source); got != wantV1 {
			t.Errorf("v1 source=%q accepted=%v, want %v", source, got, wantV1)
		}
		if !IsConnectorStatusSourceV2(source) {
			t.Errorf("v2 rejected source=%q", source)
		}
	}
	for _, source := range []string{"", "epss", "kev", "EPSS_FEED", "epss_feed ", "new-provider"} {
		if IsConnectorStatusSource(source) || IsConnectorStatusSourceV2(source) {
			t.Errorf("accepted unknown source=%q", source)
		}
	}
}

func TestConnectorStatusV1ExcludesOnlyFeedOriginsAndPreservesPaging(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	var want []string
	for i, source := range connectorStatusV2TestSources {
		insertConnectorStatusRun(t, s, i+1, source, "selection", "success", "partial", at, &at)
		if source != "epss_feed" && source != "kev_feed" {
			want = append(want, source)
		}
	}
	for _, query := range []ConnectorStatusQuery{{AsOf: at, Limit: 50}, {AsOf: at, Limit: 200, Scope: "selection"}} {
		page, err := s.QueryConnectorStatusPage(context.Background(), query)
		if err != nil || page.Total != 6 || len(page.Items) != 6 {
			t.Fatalf("v1 query=%+v page=%+v err=%v", query, page, err)
		}
		for i, source := range want {
			if page.Items[i].Source != source {
				t.Fatalf("v1 sources=%+v, want %v", page.Items, want)
			}
		}
	}
	for i, source := range want {
		page, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 1, Offset: i})
		if err != nil || page.Total != 6 || len(page.Items) != 1 || page.Items[0].Source != source {
			t.Fatalf("v1 offset=%d page=%+v err=%v, want source=%q", i, page, err, source)
		}
		page, err = s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 50, Source: source})
		if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].Source != source {
			t.Fatalf("v1 source=%q page=%+v err=%v", source, page, err)
		}
	}
	for _, source := range []string{"epss_feed", "kev_feed"} {
		if _, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 50, Source: source}); err == nil {
			t.Fatalf("v1 accepted explicit feed filter=%q", source)
		}
	}
	page, err := s.QueryConnectorStatusPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 200, Offset: 1000000})
	if err != nil || page.Total != 6 || len(page.Items) != 0 || page.Items == nil {
		t.Fatalf("v1 past end=%+v err=%v", page, err)
	}
}

func TestConnectorStatusVersionsDoNotHideUnknownRetainedSources(t *testing.T) {
	for _, source := range []string{"new-provider", "EPSS_FEED", "epss_feed "} {
		t.Run(source, func(t *testing.T) {
			s := newConnectorStatusStore(t)
			at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
			insertConnectorStatusRun(t, s, 1, "epss_feed", "selection", "running", "unknown", at, nil)
			insertConnectorStatusRun(t, s, 2, source, "selection", "running", "unknown", at, nil)
			for _, queryPage := range []func(context.Context, ConnectorStatusQuery) (ConnectorStatusPage, error){s.QueryConnectorStatusPage, s.QueryConnectorStatusPageV2} {
				for _, scope := range []string{"", "selection"} {
					if _, err := queryPage(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 50, Scope: scope}); !errors.Is(err, ErrInvalidConnectorSnapshot) {
						t.Fatalf("source=%q scope=%q error=%v, want invalid snapshot", source, scope, err)
					}
				}
			}
		})
	}
}

func TestConnectorStatusV2AllSourcesExactFiltersAndBoundedPages(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for i, source := range connectorStatusV2TestSources {
		insertConnectorStatusRun(t, s, i+1, source, "selection", "success", "partial", at, &at)
	}
	insertConnectorStatusRun(t, s, 20, "epss_feed", "Selection", "running", "unknown", at, nil)
	for _, tc := range []struct {
		source, scope               string
		limit, offset, total, items int
	}{
		{"", "", 200, 0, 9, 9}, {"", "selection", 50, 0, 8, 8},
		{"epss_feed", "", 50, 0, 2, 2}, {"epss_feed", "selection", 1, 0, 1, 1},
		{"kev_feed", "selection", 50, 0, 1, 1}, {"", "Selection", 50, 0, 1, 1},
		{"", "%' OR 1=1 --", 50, 0, 0, 0}, {"", "selection", 1, 1, 8, 1},
		{"", "", 200, 1000000, 9, 0},
	} {
		page, err := s.QueryConnectorStatusPageV2(context.Background(), ConnectorStatusQuery{AsOf: at, Source: tc.source, Scope: tc.scope, Limit: tc.limit, Offset: tc.offset})
		if err != nil || page.Total != tc.total || len(page.Items) != tc.items || page.Items == nil || page.Limit != tc.limit || page.Offset != tc.offset || !page.AsOf.Equal(at) {
			t.Fatalf("v2 query=%+v page=%+v err=%v", tc, page, err)
		}
		if tc.source == "" && tc.scope == "selection" {
			for i, item := range page.Items {
				if item.Source != connectorStatusV2TestSources[i+tc.offset] {
					t.Fatalf("v2 binary order=%+v", page.Items)
				}
			}
		}
	}
}

func TestConnectorStatusV2PreservesReceiptFutureNullAndUnknownBoundaries(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	old, recent, future := at.Add(-time.Hour), at.Add(-time.Minute), at.Add(time.Nanosecond)
	success := insertConnectorStatusRun(t, s, 1, "epss_feed", "selection", "success", "partial", old, &old)
	failure := insertConnectorStatusRun(t, s, 2, "epss_feed", "selection", "failed", "unknown", recent, &recent)
	insertConnectorStatusRun(t, s, 3, "kev_feed", "running", "running", "unknown", old, nil)
	insertConnectorStatusRun(t, s, 4, "kev_feed", "future", "success", "partial", future, &future)
	before := previewDatabaseState(t, s)
	page, err := s.QueryConnectorStatusPageV2(context.Background(), ConnectorStatusQuery{AsOf: at, Limit: 50})
	if err != nil || page.Total != 3 || len(page.Items) != 3 {
		t.Fatalf("v2 receipts=%+v err=%v", page, err)
	}
	f, futureItem, running := page.Items[0], page.Items[1], page.Items[2]
	if f.LatestAttempt.ID != failure || f.LastSuccess == nil || f.LastSuccess.ID != success || f.Status != "failed" || f.Coverage != "unknown" || f.RecordedRuns != (ConnectorRunCounts{Total: 2, Success: 1, Failed: 1}) || f.LastSuccess.AgeSeconds == nil || *f.LastSuccess.AgeSeconds != 3600 {
		t.Fatalf("latest failure/last success=%+v", f)
	}
	if futureItem.Status != "unknown" || futureItem.Coverage != "unknown" || !futureItem.LatestAttempt.Future || futureItem.LatestAttempt.AgeSeconds != nil || futureItem.LastSuccess == nil || !futureItem.LastSuccess.Future || futureItem.LastSuccess.AgeSeconds != nil {
		t.Fatalf("future receipt=%+v", futureItem)
	}
	if running.Status != "running" || running.LastSuccess != nil || running.LatestAttempt.FinishedAt != nil || running.LatestAttempt.AgeSeconds == nil || *running.LatestAttempt.AgeSeconds != 3600 {
		t.Fatalf("running receipt=%+v", running)
	}
	for _, item := range page.Items {
		if item.Liveness != "unknown" {
			t.Fatalf("inferred liveness=%+v", item)
		}
	}
	if page.Boundary != (ConnectorCoverageBoundary{Basis: "recorded_source_scope_pairs", AttemptHistory: "unknown"}) {
		t.Fatalf("inferred inventory=%+v", page.Boundary)
	}
	for _, forbidden := range []string{"private-receipt-sentinel", "private_error_sentinel", "body_json", "cursor", "raw_ref"} {
		if strings.Contains(securityQueryTestJSON(t, page), forbidden) {
			t.Fatalf("v2 leaked %q", forbidden)
		}
	}
	if after := previewDatabaseState(t, s); !reflect.DeepEqual(before, after) {
		t.Fatal("v2 read changed database tables")
	}
}

func TestConnectorStatusV2MatchesV1ForLegacySourcesAndRejectsInvalidReads(t *testing.T) {
	s := newConnectorStatusStore(t)
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for i, source := range []string{"dependabot", "trivy", "github_code_scanning", "github_secret_scanning", "epss_offline", "kev_offline"} {
		insertConnectorStatusRun(t, s, i+1, source, "selection", "success", "partial", at, &at)
	}
	query := ConnectorStatusQuery{AsOf: at, Limit: 50}
	v1, err := s.QueryConnectorStatusPage(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.QueryConnectorStatusPageV2(context.Background(), query)
	if err != nil || !reflect.DeepEqual(v1, v2) {
		t.Fatalf("legacy parity v1=%+v v2=%+v err=%v", v1, v2, err)
	}
	for _, invalid := range []ConnectorStatusQuery{{Limit: 50}, {AsOf: at}, {AsOf: at, Limit: 201}, {AsOf: at, Limit: 50, Offset: -1}, {AsOf: at, Limit: 50, Offset: 1000001}, {AsOf: at, Limit: 50, Source: "epss"}, {AsOf: at, Limit: 50, Scope: " x"}, {AsOf: at, Limit: 50, Scope: "x\x00"}, {AsOf: at, Limit: 50, Scope: strings.Repeat("x", 257)}} {
		if _, err := s.QueryConnectorStatusPageV2(context.Background(), invalid); err == nil {
			t.Fatalf("accepted invalid v2 query=%+v", invalid)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.QueryConnectorStatusPageV2(ctx, query); !errors.Is(err, context.Canceled) {
		t.Fatalf("v2 canceled read error=%v", err)
	}
	insertConnectorStatusRun(t, s, 20, "epss_feed", "selection", "success", "partial", at, &at)
	if _, err := s.db.Exec(`UPDATE ingest_runs SET finished_at=NULL WHERE connector='epss_feed'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueryConnectorStatusPageV2(context.Background(), query); !errors.Is(err, ErrInvalidConnectorSnapshot) {
		t.Fatalf("malformed selected feed lifecycle error=%v", err)
	}
	if _, err := s.QueryConnectorStatusPage(context.Background(), query); err != nil {
		t.Fatalf("v1 must exclude recognized feed origins before projection: %v", err)
	}
}
