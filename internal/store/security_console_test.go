package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestSecurityOverviewGlobalSnapshotAndBoundedSevereQueue(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-a", "example/alpha")
	insertSecurityQueryAsset(t, s, "asset-b", "example/empty")
	sources := []string{"dependabot", "trivy", "github_code_scanning", "github_secret_scanning"}
	for i := 0; i < 13; i++ {
		severity, status := "critical", "active"
		if i == 10 {
			severity = "high"
		}
		if i == 11 {
			severity, status = "low", "resolved"
		}
		if i == 12 {
			severity, status = "unknown", "unknown"
		}
		id := fmt.Sprintf("finding-%02d", i)
		insertSecurityQueryFinding(t, s, id, "asset-a", severity, status, at.Add(time.Duration(i)*time.Second), nil)
		insertSecurityQueryObservation(t, s, id, sources[i%len(sources)], i, at)
	}
	// A second older observation must not double count a finding or change latest provenance.
	insertSecurityQueryObservation(t, s, "finding-00", "trivy", 100, at.Add(-time.Hour))
	before := securityQueryTestJSON(t, mustConsoleAssets(t, s))
	view, err := s.QuerySecurityOverview(ctx, at)
	if err != nil {
		t.Fatal(err)
	}
	if view.Total != 13 || view.Active != 11 || view.Critical != 10 || view.High != 1 || view.Resolved != 1 || view.Unknown != 1 || view.Assets != 2 || view.AssetsWithoutFindings != 1 {
		t.Fatalf("global aggregates=%+v", view)
	}
	if len(view.Severe) != 8 || view.Severe[0].ID != "finding-09" || view.Severe[7].ID != "finding-02" {
		t.Fatalf("severe queue must be bounded, severity-first, newest-first: %+v", view.Severe)
	}
	sum := 0
	for _, source := range view.Sources {
		sum += source.Count
	}
	if sum != 13 || len(view.Sources) != 4 || view.SourcesTruncated {
		t.Fatalf("latest-source counts=%+v", view.Sources)
	}
	if got := securityQueryTestJSON(t, mustConsoleAssets(t, s)); got != before {
		t.Fatal("overview mutated assets")
	}
	if _, err := s.QuerySecurityOverview(ctx, time.Time{}); err == nil {
		t.Fatal("zero evaluation clock accepted")
	}
}
func mustConsoleAssets(t *testing.T, s *Store) []model.Asset {
	t.Helper()
	items, err := s.QueryAssets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestConsoleAssetsSearchPagingSavedIdentityAndDetail(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	assets := []model.Asset{
		{ID: "asset-a", Type: "repository", Provider: "github", Account: "Account-A", Region: "", NativeID: "example/alpha%_", Environment: "production", Criticality: "high"},
		{ID: "asset-b", Type: "artifact", Provider: "local", Account: "Account-B", Region: "region-b", NativeID: "registry.test/image:1"},
	}
	for _, asset := range assets {
		_, err := s.db.Exec(`INSERT INTO assets(id,type,provider,account,region,native_id,environment,criticality,body_json) VALUES(?,?,?,?,?,?,?,?,?)`, asset.ID, asset.Type, asset.Provider, asset.Account, asset.Region, asset.NativeID, asset.Environment, asset.Criticality, securityQueryTestJSON(t, asset))
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("finding-%d", i)
		insertSecurityQueryFinding(t, s, id, "asset-a", "high", "active", at, nil)
		insertSecurityQueryObservation(t, s, id, "github_code_scanning", i, at.Add(time.Duration(i)*time.Nanosecond))
	}
	for _, tc := range []struct {
		name         string
		query        ConsoleAssetQuery
		total, items int
	}{
		{"all", ConsoleAssetQuery{Limit: 1}, 2, 1}, {"next", ConsoleAssetQuery{Limit: 1, Offset: 1}, 2, 1},
		{"source", ConsoleAssetQuery{Source: "github_code_scanning", Limit: 20}, 1, 1},
		{"literal wildcards", ConsoleAssetQuery{Search: "%_", Limit: 20}, 1, 1},
		{"saved facts", ConsoleAssetQuery{Provider: "github", Account: "Account-A", Environment: "production", Criticality: "high", Limit: 20}, 1, 1},
		{"region", ConsoleAssetQuery{Region: "region-b", Limit: 20}, 1, 1},
		{"case sensitive account", ConsoleAssetQuery{Account: "account-a", Limit: 20}, 0, 0},
		{"literal injection", ConsoleAssetQuery{Search: "' OR 1=1 --", Limit: 20}, 0, 0},
		{"bounded past end", ConsoleAssetQuery{Limit: 200, Offset: 1000000}, 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.QueryConsoleAssetsPage(ctx, tc.query)
			if err != nil || page.Total != tc.total || len(page.Items) != tc.items || page.Items == nil {
				t.Fatalf("query=%+v page=%+v err=%v", tc.query, page, err)
			}
		})
	}
	page, err := s.QueryConsoleAssetsPage(ctx, ConsoleAssetQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	item := page.Items[0]
	if item.Findings != 3 || item.Active != 3 || !item.LastObserved.Equal(at.Add(2*time.Nanosecond)) || item.Asset != assets[0] || strings.Join(item.Sources, ",") != "github_code_scanning" || item.SourcesTruncated {
		t.Fatalf("saved facts/scalar summaries=%+v", item)
	}
	detail, err := s.GetConsoleAssetDetail(ctx, "asset-a", FindingQuery{Source: "github_code_scanning", AssetID: "asset-b", Limit: 1, Offset: 1})
	if err != nil || detail.Asset != assets[0] || detail.Findings.Total != 3 || len(detail.Findings.Items) != 1 || detail.Findings.Items[0].AssetID != "asset-a" {
		t.Fatalf("asset bound detail=%+v err=%v", detail, err)
	}
	if _, err := s.GetConsoleAssetDetail(ctx, "missing", FindingQuery{Limit: 20}); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("missing error=%v", err)
	}
	// Pagination-only API contract remains separate and unchanged.
	api, err := s.QueryAssetsPage(ctx, 1, 1)
	if err != nil || api.Total != 2 || len(api.Items) != 1 || api.Items[0] != assets[1] {
		t.Fatalf("legacy asset API page=%+v err=%v", api, err)
	}
	for _, query := range []ConsoleAssetQuery{{Limit: 0}, {Limit: 201}, {Limit: 1, Offset: -1}, {Limit: 1, Offset: 1000001}, {Limit: 1, Search: strings.Repeat("x", 257)}, {Limit: 1, Provider: "bad\nprovider"}, {Limit: 1, Source: "UPPERCASE"}, {Limit: 1, Source: strings.Repeat("x", 65)}} {
		if _, err := s.QueryConsoleAssetsPage(ctx, query); err == nil {
			t.Fatalf("invalid asset query accepted: %+v", query)
		}
	}
}

func TestSecurityConsoleEmptyUnknownAndNoPersistentMutation(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-empty", "javascript:alert('<evidence>')")
	var before, after int
	if err := s.db.QueryRow(`SELECT total_changes()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		view, err := s.QuerySecurityOverview(ctx, at)
		if err != nil || view.Total != 0 || view.Assets != 1 || view.AssetsWithoutFindings != 1 || len(view.Severe) != 0 {
			t.Fatalf("empty retained state=%+v err=%v", view, err)
		}
		page, err := s.QueryConsoleAssetsPage(ctx, ConsoleAssetQuery{Limit: 1})
		if err != nil || !page.Items[0].LastObserved.IsZero() {
			t.Fatalf("unobserved is unknown: %+v err=%v", page, err)
		}
		detail, err := s.GetConsoleAssetDetail(ctx, "asset-empty", FindingQuery{Limit: 1})
		if err != nil || detail.Findings.Total != 0 {
			t.Fatalf("empty asset detail=%+v err=%v", detail, err)
		}
	}
	if err := s.db.QueryRow(`SELECT total_changes()`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("reads wrote persistent data: before=%d after=%d", before, after)
	}
}

func TestSecurityOverviewSourceMaterializationIsBounded(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-a", "synthetic/many-sources")
	for i := 0; i < 66; i++ {
		id := fmt.Sprintf("finding-%03d", i)
		insertSecurityQueryFinding(t, s, id, "asset-a", "low", "active", at, nil)
		insertSecurityQueryObservation(t, s, id, fmt.Sprintf("synthetic_source_%03d", i), i, at)
	}
	view, err := s.QuerySecurityOverview(context.Background(), at)
	if err != nil || view.Total != 66 || len(view.Sources) != 64 || !view.SourcesTruncated {
		t.Fatalf("bounded overview groups=%+v err=%v", view, err)
	}
	page, err := s.QueryConsoleAssetsPage(context.Background(), ConsoleAssetQuery{Limit: 1})
	if err != nil || len(page.Items) != 1 || len(page.Items[0].Sources) != 64 || !page.Items[0].SourcesTruncated {
		t.Fatalf("bounded asset sources=%+v err=%v", page, err)
	}
}

func TestSecurityConsoleCanceledContextStopsReadsWithoutMutation(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-cancel", "synthetic/cancel")
	var before, after int
	if err := s.db.QueryRow(`SELECT total_changes()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.QuerySecurityOverview(ctx, at); !errors.Is(err, context.Canceled) {
		t.Fatalf("overview cancellation=%v", err)
	}
	if _, err := s.QueryConsoleAssetsPage(ctx, ConsoleAssetQuery{Limit: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("asset page cancellation=%v", err)
	}
	if _, err := s.GetConsoleAssetDetail(ctx, "asset-cancel", FindingQuery{Limit: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("asset detail cancellation=%v", err)
	}
	if _, err := s.QueryConnectorStatusPage(ctx, ConnectorStatusQuery{AsOf: at, Limit: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("recorded status cancellation=%v", err)
	}
	if err := s.db.QueryRow(`SELECT total_changes()`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("canceled reads mutated persistent data")
	}
}
