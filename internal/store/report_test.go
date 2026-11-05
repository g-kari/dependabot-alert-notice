package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/feed"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestListReportFiltersBeforePagination(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now().UTC()
	items := make([]feed.Item, 35)
	for i := range items {
		items[i] = feed.Item{ExternalID: fmt.Sprint(i), Title: "unrelated", Published: now.Add(time.Duration(i) * time.Second)}
	}
	if err := s.SaveFeedItems(context.Background(), "https://other.example/feed", items, now); err != nil {
		t.Fatal(err)
	}
	matching := []feed.Item{{ExternalID: "match", Title: "matching advisory", Published: now.Add(-time.Hour), CVEIDs: []string{"CVE-2026-12345"}}}
	if err := s.SaveFeedItems(context.Background(), "https://security.example/feed", matching, now); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListReport(context.Background(), ReportFilter{Days: 7, CVE: "cve-2026-12345", Feed: "security.example", PageSize: 2})
	if err != nil || len(rows) != 1 || rows[0].Item.ExternalID != "match" {
		t.Fatalf("filtered older article missing: rows=%+v err=%v", rows, err)
	}
}

func TestListReportRepositoryFilter(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now().UTC()
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 1, CVEID: "CVE-2026-12345"}, NotifiedAt: now})
	items := []feed.Item{
		{ExternalID: "related", Title: "related", CVEIDs: []string{"CVE-2026-12345"}},
		{ExternalID: "unrelated", Title: "unrelated", CVEIDs: []string{"CVE-2026-54321"}},
	}
	if err := s.SaveFeedItems(context.Background(), "https://example.com/feed", items, now); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListReport(context.Background(), ReportFilter{Repo: "ORG/API"})
	if err != nil || len(rows) != 1 || rows[0].Item.ExternalID != "related" {
		t.Fatalf("repository filter: rows=%+v err=%v", rows, err)
	}
}

func TestReportPageCountsAndAlerts(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: fmt.Sprint(i), Number: 1, CVEID: "cve-2026-12345", CVSSScore: 9.8, CVSSKnown: true, Description: strings.Repeat("large description", 100)}, NotifiedAt: now})
	}
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "unrelated", Number: 2, CVEID: "CVE-2026-54321"}, NotifiedAt: now})
	items := []feed.Item{{ExternalID: "first", Published: now, CVEIDs: []string{"CVE-2026-12345", "CVE-2026-54321"}}, {ExternalID: "second", Published: now.Add(-time.Minute)}}
	if err := s.SaveFeedItems(context.Background(), "https://example.com/feed", items, now); err != nil {
		t.Fatal(err)
	}
	page, err := s.QueryReport(context.Background(), ReportFilter{PageSize: 1, Page: 2})
	if err != nil || page.Total != 2 || page.CVECount != 2 || len(page.Rows) != 1 || page.Rows[0].Item.ExternalID != "second" {
		t.Fatalf("page metadata/ordering: %+v err=%v", page, err)
	}
	alerts, err := s.ListReportAlerts(context.Background(), []string{"CVE-2026-12345", "cve-2026-12345"})
	if err != nil || len(alerts) != 3 {
		t.Fatalf("CVE query: count=%d err=%v", len(alerts), err)
	}
	for _, alert := range alerts {
		if alert.Alert.Description != "" || !alert.Alert.CVSSKnown || alert.Alert.CVSSScore != 9.8 || alert.Alert.ID <= 0 {
			t.Fatalf("lightweight scoring record: %+v", alert.Alert)
		}
	}
	var id, parent, unused int
	var queryPlan string
	if err := s.db.QueryRow(`EXPLAIN QUERY PLAN SELECT id FROM alert_records WHERE UPPER(json_extract(alert_json,'$.CVEID'))=?`, "CVE-2026-12345").Scan(&id, &parent, &unused, &queryPlan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(queryPlan, "INDEX alert_cve_lookup") {
		t.Fatalf("CVE lookup should use its index: %s", queryPlan)
	}
}
