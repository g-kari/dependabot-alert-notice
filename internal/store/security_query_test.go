package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func newSecurityQueryTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewWithPath(filepath.Join(t.TempDir(), "query.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close security query store: %v", err)
		}
	})
	if _, err := s.db.Exec(`INSERT INTO ingest_runs(id,connector,scope,started_at,result,coverage,body_json) VALUES('test-run','trivy','test','2026-11-05T10:00:00Z','success','full','{}')`); err != nil {
		t.Fatal(err)
	}
	return s
}

func securityQueryTestJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func insertSecurityQueryAsset(t *testing.T, s *Store, id, nativeID string) {
	t.Helper()
	asset := model.Asset{ID: id, Type: "repository", Provider: "github", Account: "example", NativeID: nativeID}
	if _, err := s.db.Exec(`INSERT INTO assets(id,type,provider,account,region,native_id,environment,criticality,body_json) VALUES(?,?,?,?,?,?,?,?,?)`, asset.ID, asset.Type, asset.Provider, asset.Account, asset.Region, asset.NativeID, asset.Environment, asset.Criticality, securityQueryTestJSON(t, asset)); err != nil {
		t.Fatal(err)
	}
}

func insertSecurityQueryFinding(t *testing.T, s *Store, id, assetID, severity, status string, at time.Time, metadata map[string]any) {
	t.Helper()
	body := map[string]any{
		"id": id, "category": "vulnerability", "asset_id": assetID, "canonical_key": "canonical-" + id,
		"severity": severity, "triage_status": "new", "source_status": status, "first_seen": at, "last_seen": at,
	}
	for key, value := range metadata {
		body[key] = value
	}
	if _, err := s.db.Exec(`INSERT INTO findings(id,category,asset_id,canonical_key,severity,triage_status,source_status,first_seen,last_seen,fingerprint,body_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, "vulnerability", assetID, body["canonical_key"], severity, "new", status, at.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano), "test-fingerprint", securityQueryTestJSON(t, body)); err != nil {
		t.Fatal(err)
	}
}

func insertSecurityQueryObservation(t *testing.T, s *Store, findingID, source string, number int, at time.Time) {
	t.Helper()
	observation := model.Observation{ID: fmt.Sprintf("observation-%04d", number), Source: source, Account: "example", SourceFindingID: findingID + ":native", FindingID: findingID, IngestRunID: "test-run", Fingerprint: fmt.Sprintf("fingerprint-%04d", number), ObservedAt: at}
	if _, err := s.db.Exec(`INSERT INTO observations(id,source,account,source_finding_id,finding_id,ingest_run_id,raw_ref,observed_at,fingerprint,body_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, observation.ID, observation.Source, observation.Account, observation.SourceFindingID, observation.FindingID, observation.IngestRunID, observation.RawRef, at.Format(time.RFC3339Nano), observation.Fingerprint, securityQueryTestJSON(t, observation)); err != nil {
		t.Fatal(err)
	}
}

func insertSecurityQueryEvent(t *testing.T, s *Store, findingID string, number int, at time.Time) {
	t.Helper()
	event := model.Event{ID: fmt.Sprintf("event-%04d", number), EntityID: findingID, EventType: "finding_observed", Actor: "trivy", Timestamp: at}
	if _, err := s.db.Exec(`INSERT INTO events(id,entity_id,event_type,actor,timestamp,before_ref,after_ref,body_json) VALUES(?,?,?,?,?,?,?,?)`, event.ID, event.EntityID, event.EventType, event.Actor, at.Format(time.RFC3339Nano), event.BeforeRef, event.AfterRef, securityQueryTestJSON(t, event)); err != nil {
		t.Fatal(err)
	}
}

func TestQueryFindingsPageFiltersRetainsHistoryAndPaginates(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-a", "example/alpha")
	insertSecurityQueryAsset(t, s, "asset-b", "example/beta")
	insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "high", "active", at, nil)
	insertSecurityQueryFinding(t, s, "finding-b", "asset-b", "low", "resolved", at.Add(time.Minute), nil)
	insertSecurityQueryFinding(t, s, "finding-c", "asset-a", "high", "active", at, nil)
	insertSecurityQueryObservation(t, s, "finding-a", "dependabot", 1, at)
	insertSecurityQueryObservation(t, s, "finding-a", "dependabot", 2, at.Add(time.Second))
	insertSecurityQueryObservation(t, s, "finding-b", "trivy", 3, at.Add(time.Minute))
	insertSecurityQueryObservation(t, s, "finding-c", "trivy", 4, at)

	for _, tc := range []struct {
		name  string
		query FindingQuery
		total int
		ids   string
	}{
		{"all retained history", FindingQuery{Limit: 50}, 3, "finding-b,finding-a,finding-c"},
		{"stable page", FindingQuery{Limit: 1, Offset: 1}, 3, "finding-a"},
		{"past end", FindingQuery{Limit: 200, Offset: 1000000}, 3, ""},
		{"source uses exists", FindingQuery{Source: "dependabot", Limit: 50}, 1, "finding-a"},
		{"severity", FindingQuery{Severity: "high", Limit: 50}, 2, "finding-a,finding-c"},
		{"source status", FindingQuery{SourceStatus: "resolved", Limit: 50}, 1, "finding-b"},
		{"asset", FindingQuery{AssetID: "asset-b", Limit: 50}, 1, "finding-b"},
		{"asset native search", FindingQuery{Search: "example/BETA", Limit: 50}, 1, "finding-b"},
		{"canonical search", FindingQuery{Search: "canonical-finding-a", Limit: 50}, 1, "finding-a"},
		{"combined", FindingQuery{Search: "beta", Source: "trivy", Severity: "low", SourceStatus: "resolved", AssetID: "asset-b", Limit: 50}, 1, "finding-b"},
		{"contradiction", FindingQuery{Source: "dependabot", Severity: "low", Limit: 50}, 0, ""},
		{"asset injection", FindingQuery{AssetID: "asset-b' OR 1=1 --", Limit: 50}, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.QueryFindingsPage(context.Background(), tc.query)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, finding := range page.Items {
				ids = append(ids, finding.ID)
			}
			if page.Total != tc.total || strings.Join(ids, ",") != tc.ids || page.Limit != tc.query.Limit || page.Offset != tc.query.Offset {
				t.Fatalf("query=%+v page=%+v ids=%v, want total=%d ids=%s", tc.query, page, ids, tc.total, tc.ids)
			}
			if page.Items == nil {
				t.Error("page.Items must be an empty array, not nil")
			}
		})
	}
}

func TestQueryFindingsPageSearchMetadataAndLiteralWildcards(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-a", "example/alpha")
	insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "unknown", "unknown", at, map[string]any{
		"title": "Synthetic 100%_safe\\title", "vulnerability_id": "CVE-2026-2468", "package_name": "example-lib", "package_ecosystem": "ecosystem-only", "installed_version": "installed-only", "fixed_version": "fixed-only",
	})
	insertSecurityQueryFinding(t, s, "finding-b", "asset-a", "low", "active", at, nil)
	for _, search := range []string{"100%_safe\\title", "%", "_", "\\", "CVE-2026-2468", "example-lib", "ecosystem-only", "installed-only", "fixed-only"} {
		t.Run(search, func(t *testing.T) {
			page, err := s.QueryFindingsPage(context.Background(), FindingQuery{Search: search, Limit: 50})
			if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "finding-a" {
				t.Fatalf("search=%q page=%+v err=%v, want only finding-a", search, page, err)
			}
		})
	}
	for _, search := range []string{"%' OR 1=1 --", "missing%", "missing_", "missing\\"} {
		page, err := s.QueryFindingsPage(context.Background(), FindingQuery{Search: search, Limit: 50})
		if err != nil || page.Total != 0 || page.Items == nil {
			t.Fatalf("literal search=%q page=%+v err=%v, want empty page", search, page, err)
		}
	}
}

func TestQueryFindingsPageOrdersRFC3339NanoChronologically(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	insertSecurityQueryAsset(t, s, "asset-a", "example/alpha")
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "high", "active", at, nil)
	insertSecurityQueryFinding(t, s, "finding-b", "asset-a", "high", "active", at.Add(time.Nanosecond), nil)
	insertSecurityQueryFinding(t, s, "finding-c", "asset-a", "high", "active", at.Add(10*time.Nanosecond), nil)
	page, err := s.QueryFindingsPage(context.Background(), FindingQuery{Limit: 50})
	if err != nil || len(page.Items) != 3 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if page.Items[0].ID != "finding-c" || page.Items[1].ID != "finding-b" || page.Items[2].ID != "finding-a" {
		t.Fatalf("order=%+v, want newest nanosecond first even with variable precision timestamps", page.Items)
	}
}

func TestSecurityPageQueriesValidateBounds(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	for _, query := range []FindingQuery{
		{}, {Limit: -1}, {Limit: 201}, {Limit: 1, Offset: -1}, {Limit: 1, Offset: 1000001},
		{Limit: 1, Search: strings.Repeat("a", 257)}, {Limit: 1, Search: "\x00"}, {Limit: 1, Search: "\xff"},
		{Limit: 1, Source: strings.Repeat("a", 65)}, {Limit: 1, Source: "trivy' OR 1=1 --"}, {Limit: 1, Source: "0invalid"}, {Limit: 1, Severity: "urgent"}, {Limit: 1, SourceStatus: "closed"},
		{Limit: 1, AssetID: strings.Repeat("a", 129)}, {Limit: 1, AssetID: "\x00"},
	} {
		if _, err := s.QueryFindingsPage(context.Background(), query); err == nil {
			t.Errorf("query=%+v: expected validation error", query)
		}
	}
	for _, bounds := range [][2]int{{0, 0}, {-1, 0}, {201, 0}, {1, -1}, {1, 1000001}} {
		if _, err := s.QueryAssetsPage(context.Background(), bounds[0], bounds[1]); err == nil {
			t.Errorf("limit=%d offset=%d: expected validation error", bounds[0], bounds[1])
		}
	}
}

func TestQueryAssetsPageStableOrderingAndEmptyArrays(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	insertSecurityQueryAsset(t, s, "asset-b", "example/beta")
	insertSecurityQueryAsset(t, s, "asset-a", "example/alpha")
	for offset := 0; offset < 3; offset++ {
		page, err := s.QueryAssetsPage(context.Background(), 1, offset)
		if err != nil || page.Total != 2 || page.Limit != 1 || page.Offset != offset || page.Items == nil {
			t.Fatalf("offset=%d page=%+v err=%v", offset, page, err)
		}
		if offset < 2 && (len(page.Items) != 1 || page.Items[0].ID != fmt.Sprintf("asset-%c", 'a'+offset)) {
			t.Fatalf("offset=%d items=%+v, want matching stable asset", offset, page.Items)
		}
		if offset == 2 && len(page.Items) != 0 {
			t.Fatalf("offset=%d items=%+v, want empty", offset, page.Items)
		}
	}
}

func TestGetFindingDetailRetainsLatestBoundedHistoryChronologically(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	insertSecurityQueryAsset(t, s, "asset-a", "example/alpha")
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "high", "active", at, nil)
	for i := 0; i < 205; i++ {
		// Insert out of time order to prove that row insertion order is not used
		// as evidence chronology. Include whole-second and fractional timestamps.
		number := 204 - i
		observedAt := at.Add(time.Duration(number) * time.Nanosecond)
		insertSecurityQueryObservation(t, s, "finding-a", "trivy", number, observedAt)
		insertSecurityQueryEvent(t, s, "finding-a", number, observedAt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	detail, err := s.GetFindingDetail(ctx, "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Finding.ID != "finding-a" || detail.Asset.ID != "asset-a" || len(detail.Observations) != 200 || len(detail.Events) != 200 || !detail.ObservationsTruncated || !detail.EventsTruncated {
		t.Fatalf("detail sizes/flags: finding=%s asset=%s observations=%d events=%d truncated=%v/%v", detail.Finding.ID, detail.Asset.ID, len(detail.Observations), len(detail.Events), detail.ObservationsTruncated, detail.EventsTruncated)
	}
	if detail.Observations[0].ID != "observation-0005" || detail.Observations[199].ID != "observation-0204" || detail.Events[0].ID != "event-0005" || detail.Events[199].ID != "event-0204" {
		t.Fatal("detail must return latest 200 in chronological order")
	}
}

func TestGetFindingDetailEmptyHistoryAndMissingFinding(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	insertSecurityQueryAsset(t, s, "asset-a", "example/alpha")
	insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "high", "active", time.Now().UTC(), nil)
	detail, err := s.GetFindingDetail(context.Background(), "finding-a")
	if err != nil || detail.Observations == nil || detail.Events == nil || len(detail.Observations) != 0 || len(detail.Events) != 0 || detail.ObservationsTruncated || detail.EventsTruncated {
		t.Fatalf("detail=%+v err=%v, want empty non-nil history with false flags", detail, err)
	}
	for _, id := range []string{"missing", "", "finding-a' OR 1=1 --", strings.Repeat("a", 129)} {
		if _, err := s.GetFindingDetail(context.Background(), id); !errors.Is(err, ErrFindingNotFound) {
			t.Errorf("id=%q error=%v, want ErrFindingNotFound", id, err)
		}
	}
}

func TestSecurityPageQueriesPropagateContextAndStorageErrors(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.QueryFindingsPage(ctx, FindingQuery{Limit: 1}); !errors.Is(err, context.Canceled) {
		t.Errorf("findings canceled error=%v", err)
	}
	if _, err := s.QueryAssetsPage(ctx, 1, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("assets canceled error=%v", err)
	}
	if _, err := s.GetFindingDetail(ctx, "finding-a"); !errors.Is(err, context.Canceled) {
		t.Errorf("detail canceled error=%v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueryFindingsPage(context.Background(), FindingQuery{Limit: 1}); err == nil {
		t.Error("closed findings store returned success")
	}
	if _, err := s.QueryAssetsPage(context.Background(), 1, 0); err == nil {
		t.Error("closed assets store returned success")
	}
	if _, err := s.GetFindingDetail(context.Background(), "finding-a"); err == nil || errors.Is(err, ErrFindingNotFound) {
		t.Errorf("closed detail store error=%v, want a storage error, not missing finding", err)
	}
}
