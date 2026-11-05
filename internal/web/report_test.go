package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/feed"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestVulnerabilityReportPaginationAndFilters(t *testing.T) {
	srv, s, _ := newTestServer(t)
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now().UTC()
	items := make([]feed.Item, 31)
	for i := range items {
		items[i] = feed.Item{ExternalID: fmt.Sprint(i), Title: fmt.Sprintf("advisory-%02d", i), Published: now.Add(-time.Duration(i) * time.Minute), CVEIDs: []string{"CVE-2026-12345"}}
	}
	if err := s.SaveFeedItems(context.Background(), "https://example.com/feed", items, now); err != nil {
		t.Fatal(err)
	}
	request := func(path string) string {
		t.Helper()
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	body := request("/reports/vulnerabilities?days=30&feed=example.com&cve=CVE-2026-12345")
	if !strings.Contains(body, "次のページ") || !strings.Contains(body, "31 件") || strings.Contains(body, "advisory-25") {
		t.Fatal("first page should show 25 articles, total count and next page")
	}
	if !strings.Contains(body, "cve=CVE-2026-12345") || !strings.Contains(body, "days=30") || !strings.Contains(body, "feed=example.com") {
		t.Fatal("pagination link lost filters")
	}
	body = request("/reports/vulnerabilities?days=30&feed=example.com&cve=CVE-2026-12345&page=2")
	if !strings.Contains(body, "advisory-25") || strings.Contains(body, "次のページ") || !strings.Contains(body, "前のページ") {
		t.Fatal("last page should show remaining articles and only previous link")
	}
	request("/reports/vulnerabilities?page=9223372036854775807")
}

func TestVulnerabilityReportShowsPartialFailureAndRefreshing(t *testing.T) {
	srv, s, _ := newTestServer(t)
	t.Cleanup(func() { _ = s.Close() })
	srv.cfg.RSS = config.RSSConfig{Enabled: true, Feeds: []config.RSSFeed{{Name: "Working Feed", URL: "https://working.example", Enabled: true}, {Name: "Blocked Feed", URL: "https://blocked.example", Enabled: true}}}
	now := time.Now().UTC()
	if err := s.SaveFeedStatus(context.Background(), store.FeedStatus{FeedURL: "https://working.example", LastAttemptAt: &now, LastSuccessAt: &now, ItemCount: 3}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFeedFailure(context.Background(), store.FeedStatus{FeedURL: "https://blocked.example", LastAttemptAt: &now, LastError: "403 Forbidden"}); err != nil {
		t.Fatal(err)
	}
	srv.feedRefreshing = true
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/reports/vulnerabilities", nil))
	for _, want := range []string{"Working Feed", "Blocked Feed", "403 Forbidden", "更新中", "disabled", "一部のフィード"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestVulnerabilityReportExcludesOnlyRepositoryAssociation(t *testing.T) {
	srv, s, _ := newTestServer(t)
	t.Cleanup(func() { _ = s.Close() })
	srv.cfg.Targets = []config.Target{{Owner: "ORG", Excludes: []string{"excluded"}}}
	now := time.Now().UTC()
	for i, repo := range []string{"excluded", "active"} {
		s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: repo, Number: i + 1, CVEID: "CVE-2026-12345"}, NotifiedAt: now})
	}
	if err := s.SaveFeedItems(context.Background(), "https://example.com/feed", []feed.Item{{ExternalID: "one", Title: "kept-article", CVEIDs: []string{"CVE-2026-12345"}}}, now); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/reports/vulnerabilities", nil))
	body := w.Body.String()
	if !strings.Contains(body, "kept-article") || !strings.Contains(body, "org/active") || strings.Contains(body, "org/excluded") {
		t.Fatal("exclusion should hide association and keep article")
	}
	if !strings.Contains(body, "暫定（要確認）") || !strings.Contains(body, "不明") || !strings.Contains(body, "確認する項目") {
		t.Fatal("unconfirmed score and unknown CVSS must be explained")
	}
}

func TestRefreshFeedsPartialFailurePreservesPreviousResult(t *testing.T) {
	srv, s, _ := newTestServer(t)
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Hour)
	blocked := "https://blocked.example/feed"
	working := "https://working.example/feed"
	srv.cfg.RSS = config.RSSConfig{Enabled: true, Feeds: []config.RSSFeed{{URL: blocked, Name: "blocked", Enabled: true}, {URL: working, Name: "working", Enabled: true}}}
	if err := s.CommitFeed(ctx, store.FeedBatch{FeedURL: blocked, Items: []feed.Item{{ExternalID: "previous", Title: "previous"}}, FetchedAt: now}); err != nil {
		t.Fatal(err)
	}
	srv.fetchFeed = func(_ context.Context, url string, _ feed.FetchOptions) (feed.FetchResult, error) {
		if url == blocked {
			return feed.FetchResult{}, errors.New("403 Forbidden")
		}
		return feed.FetchResult{Items: []feed.Item{{ExternalID: "new", Title: "new"}}}, nil
	}
	if err := srv.RefreshFeeds(ctx); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("partial failure missing: %v", err)
	}
	items, err := s.ListFeedItems(ctx, 10)
	if err != nil || len(items) != 2 {
		t.Fatalf("partial results lost: items=%+v err=%v", items, err)
	}
	statuses, err := s.ListFeedStatuses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range statuses {
		if status.FeedURL == blocked && (status.LastSuccessAt == nil || !status.LastSuccessAt.Equal(now) || status.LastError != "403 Forbidden" || status.ItemCount != 1) {
			t.Fatalf("failed feed lost previous success: %+v", status)
		}
	}
}

func TestRefreshFeedsConditionalRequestAndPersistedRetry(t *testing.T) {
	srv, s, _ := newTestServer(t)
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	url := "https://example.com/feed"
	srv.cfg.RSS = config.RSSConfig{Enabled: true, Feeds: []config.RSSFeed{{URL: url, Name: "fixture", Enabled: true}}}
	before := time.Now().UTC().Add(-time.Hour)
	if err := s.CommitFeed(ctx, store.FeedBatch{FeedURL: url, Items: []feed.Item{{ExternalID: "previous", Title: "previous"}}, FetchedAt: before, ETag: "version-one"}); err != nil {
		t.Fatal(err)
	}
	srv.fetchFeed = func(_ context.Context, _ string, options feed.FetchOptions) (feed.FetchResult, error) {
		if options.ETag != "version-one" {
			t.Errorf("persisted ETag not sent: %+v", options)
		}
		return feed.FetchResult{NotModified: true, ETag: options.ETag}, nil
	}
	if err := srv.RefreshFeeds(ctx); err != nil {
		t.Fatal(err)
	}
	statuses, err := s.ListFeedStatuses(ctx)
	if err != nil || len(statuses) != 1 || statuses[0].LastSuccessAt == nil || !statuses[0].LastSuccessAt.After(before) || statuses[0].ItemCount != 1 || statuses[0].ETag != "version-one" {
		t.Fatalf("304 should preserve articles/count/validator: %+v %v", statuses, err)
	}
	due := time.Now().UTC().Add(time.Minute)
	srv.fetchFeed = func(context.Context, string, feed.FetchOptions) (feed.FetchResult, error) {
		return feed.FetchResult{}, &feed.HTTPStatusError{StatusCode: 429, Status: "429 Too Many Requests", RetryAt: due}
	}
	if err := srv.RefreshFeeds(ctx); err == nil {
		t.Fatal("429 should report a source failure")
	}
	// A new server must honor the persisted waiting time, including manual refresh.
	restarted := New(srv.cfg, "", s, nil)
	calls := 0
	restarted.fetchFeed = func(context.Context, string, feed.FetchOptions) (feed.FetchResult, error) {
		calls++
		return feed.FetchResult{}, nil
	}
	if err := restarted.RefreshFeeds(ctx); err != nil || calls != 0 {
		t.Fatalf("rate-limited source retried early: calls=%d err=%v", calls, err)
	}
	items, err := s.ListFeedItems(ctx, 10)
	if err != nil || len(items) != 1 || items[0].ExternalID != "previous" {
		t.Fatalf("304/429 changed articles: %+v %v", items, err)
	}
	statuses, err = s.ListFeedStatuses(ctx)
	if err != nil || len(statuses) != 1 || statuses[0].NextAttemptAt == nil || !statuses[0].NextAttemptAt.Equal(due) {
		t.Fatalf("retry deadline not persisted: %+v %v", statuses, err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	status := statuses[0]
	status.NextAttemptAt = &past
	if err := s.SaveFeedStatus(ctx, status); err != nil {
		t.Fatal(err)
	}
	restarted.fetchFeed = func(context.Context, string, feed.FetchOptions) (feed.FetchResult, error) {
		calls++
		return feed.FetchResult{Items: []feed.Item{{ExternalID: "after-retry", Title: "after retry"}}, ETag: "version-two"}, nil
	}
	if err := restarted.RefreshFeeds(ctx); err != nil || calls != 1 {
		t.Fatalf("expired retry should resume: calls=%d err=%v", calls, err)
	}
	statuses, err = s.ListFeedStatuses(ctx)
	if err != nil || statuses[0].NextAttemptAt != nil || statuses[0].LastError != "" || statuses[0].ETag != "version-two" {
		t.Fatalf("success should clear retry/error and update validator: %+v %v", statuses, err)
	}
}
