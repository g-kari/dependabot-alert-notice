package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestFindingProjectionAndNativeLiteralSearch(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "a", "owner/repo")
	insertSecurityQueryFinding(t, s, "native%_\\id", "a", "high", "active", at, nil)
	insertSecurityQueryFinding(t, s, "missing", "a", "low", "resolved", at, map[string]any{"source": "forged", "source_finding_id": "forged"})
	insertSecurityQueryObservation(t, s, "native%_\\id", "dependabot", 1, at)
	insertSecurityQueryObservation(t, s, "native%_\\id", "trivy", 2, at.Add(time.Nanosecond))
	insertSecurityQueryObservation(t, s, "native%_\\id", "codeql", 3, at.Add(time.Nanosecond))
	insertSecurityQueryObservation(t, s, "native%_\\id", "old", 99, at.Add(-time.Hour))
	for _, tc := range []struct{ source, want string }{{"", "codeql"}, {"dependabot", "dependabot"}, {"trivy", "trivy"}} {
		page, err := s.QueryFindingsPage(context.Background(), FindingQuery{Search: ":native", Source: tc.source, Limit: 20})
		if err != nil || len(page.Items) != 1 {
			t.Fatalf("source %q page=%+v err=%v", tc.source, page, err)
		}
		if page.Items[0].Source != tc.want || page.Items[0].SourceFindingID != "native%_\\id:native" {
			t.Fatalf("projection=%+v", page.Items)
		}
	}
	for _, q := range []string{"%_\\id:native", "%not-present", "_not-present"} {
		page, err := s.QueryFindingsPage(context.Background(), FindingQuery{Search: q, Limit: 20})
		want := 0
		if q == "%_\\id:native" {
			want = 1
		}
		if err != nil || page.Total != want {
			t.Fatalf("literal %q page=%+v err=%v", q, page, err)
		}
	}
	detail, err := s.GetFindingDetail(context.Background(), "native%_\\id")
	if err != nil || detail.Finding.Source != "codeql" {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
	missing, err := s.GetFindingDetail(context.Background(), "missing")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(missing.Finding)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["source"]; ok {
		t.Fatalf("persisted metadata leaked: %s", body)
	}
	if _, ok := fields["source_finding_id"]; ok {
		t.Fatalf("persisted metadata leaked: %s", body)
	}
	if fields["id"] != "missing" || fields["severity"] != "low" {
		t.Fatalf("flat identity changed: %s", body)
	}
}

func TestRelatedFindingsExactCVEAndFilters(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "a", "owner/a")
	insertSecurityQueryAsset(t, s, "b", "owner/b")
	rows := []struct{ id, asset, cve, category, title, severity, status string }{
		{"anchor", "a", "CVE-2026-1234", "vulnerability", "", "high", "active"},
		{"candidate-a", "b", "CVE-2026-1234", "vulnerability", "", "high", "resolved"},
		{"candidate-b", "a", "CVE-2026-1234", "vulnerability", "", "low", "active"},
		{"longer", "a", "CVE-2026-12345", "vulnerability", "", "high", "active"},
		{"ghsa", "a", "GHSA-xxxx-yyyy-zzzz", "vulnerability", "CVE-2026-1234", "high", "active"},
		{"title", "a", "", "vulnerability", "CVE-2026-1234", "high", "active"},
		{"lower", "a", "cve-2026-1234", "vulnerability", "", "high", "active"},
		{"secret", "a", "CVE-2026-1234", "secret", "", "high", "active"},
	}
	for i, r := range rows {
		insertSecurityQueryFinding(t, s, r.id, r.asset, r.severity, r.status, at, map[string]any{"vulnerability_id": r.cve, "category": r.category, "title": r.title})
		if _, err := s.db.Exec("UPDATE findings SET category=? WHERE id=?", r.category, r.id); err != nil {
			t.Fatal(err)
		}
		source := "trivy"
		if r.id == "candidate-a" {
			source = "dependabot"
		}
		insertSecurityQueryObservation(t, s, r.id, source, i+1, at)
	}
	run, feed := enrichmentFixture(t, 100, "epss", at, at)
	mustEnrichment(t, s, run, feed)
	var receiptBefore string
	if err := s.db.QueryRow("SELECT cursor FROM ingest_runs WHERE id=?", run.ID).Scan(&receiptBefore); err != nil {
		t.Fatal(err)
	}
	var findingBefore string
	if err := s.db.QueryRow("SELECT body_json FROM findings WHERE id='candidate-a'").Scan(&findingBefore); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		q     FindingQuery
		total int
		id    string
	}{
		{"first", FindingQuery{Limit: 1}, 2, "candidate-a"},
		{"second", FindingQuery{Limit: 1, Offset: 1}, 2, "candidate-b"},
		{"beyond", FindingQuery{Limit: 1, Offset: 2}, 2, ""},
		{"composed", FindingQuery{Search: "candidate-a:native", Source: "dependabot", Severity: "high", SourceStatus: "resolved", AssetID: "b", Limit: 20}, 1, "candidate-a"},
		{"source excludes", FindingQuery{Source: "codeql", Limit: 20}, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := s.QueryRelatedFindings(ctx, "anchor", tc.q)
			if err != nil || page.Total != tc.total || page.Relationship != "same_cve" || page.CVEID != "CVE-2026-1234" || page.AnchorID != "anchor" || page.Items == nil {
				t.Fatalf("page=%+v err=%v", page, err)
			}
			wantSource := "trivy"
			if tc.id == "candidate-a" {
				wantSource = "dependabot"
			}
			if tc.id != "" && (len(page.Items) != 1 || page.Items[0].ID != tc.id || page.Items[0].Source != wantSource) {
				t.Fatalf("items=%+v", page.Items)
			}
			if tc.id != "" {
				evidence, ok := page.Enrichments[tc.id]
				if !ok || evidence.EPSS == nil || evidence.EPSS.RunID != run.ID || len(page.Enrichments) != 1 {
					t.Fatalf("enrichment inconsistent with page: %+v", page.Enrichments)
				}
			}
			if tc.id == "" && len(page.Items) != 0 {
				t.Fatalf("items=%+v", page.Items)
			}
		})
	}
	for _, id := range []string{"ghsa", "title", "lower", "secret"} {
		page, err := s.QueryRelatedFindings(ctx, id, FindingQuery{Limit: 20})
		if err != nil || page.Relationship != "none" || page.Total != 0 || page.CVEID != "" || page.Items == nil || len(page.Items) != 0 {
			t.Fatalf("id=%s page=%+v err=%v", id, page, err)
		}
	}
	if _, err := s.QueryRelatedFindings(ctx, "absent", FindingQuery{Limit: 20}); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("not found err=%v", err)
	}
	for _, q := range []FindingQuery{{Limit: 20, CVEID: "CVE-2026-1234"}, {Limit: 201}, {Limit: 20, Offset: 1000001}} {
		if _, err := s.QueryRelatedFindings(ctx, "anchor", q); err == nil {
			t.Fatalf("accepted %+v", q)
		}
	}
	page, err := s.QueryFindingsPage(ctx, FindingQuery{Limit: 20, CVEID: "CVE-2026-1234"})
	if err != nil || page.Total != 3 {
		t.Fatalf("CVE page=%+v err=%v", page, err)
	}
	var receiptAfter, findingAfter string
	if err := s.db.QueryRow("SELECT cursor FROM ingest_runs WHERE id=?", run.ID).Scan(&receiptAfter); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT body_json FROM findings WHERE id='candidate-a'").Scan(&findingAfter); err != nil {
		t.Fatal(err)
	}
	if receiptBefore != receiptAfter || findingBefore != findingAfter {
		t.Fatal("read queries changed receipt or native finding")
	}
	if replay, err := s.ImportSecurityEnrichment(ctx, run, feed); err != nil || !replay.Replay {
		t.Fatalf("old receipt replay=%+v err=%v", replay, err)
	}
	for _, cve := range []string{"cve-2026-1234", " CVE-2026-1234", "GHSA-xxxx-yyyy-zzzz", "CVE-2026-1234,CVE-2026-12345"} {
		if _, err := s.QueryFindingsPage(ctx, FindingQuery{Limit: 20, CVEID: cve}); err == nil {
			t.Fatalf("accepted CVE %q", cve)
		}
	}
}
