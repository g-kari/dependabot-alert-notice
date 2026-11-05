package store

import (
	"context"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/feed"
)

func TestSaveAndListFeedItemsDeduplicates(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.db.Close() })
	now := time.Now().UTC()
	items := []feed.Item{{ExternalID: "id", Title: "CVE-2024-1234", Link: "https://example.com", Summary: "summary", Published: now, CVEIDs: []string{"CVE-2024-1234"}}}
	if err := s.SaveFeedItems(context.Background(), "https://feed.example", items, now); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveFeedItems(context.Background(), "https://feed.example", items, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListFeedItems(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].CVEIDs) != 1 {
		t.Fatalf("got=%+v", got)
	}
}

func TestFeedFailurePreservesLastSuccessfulMetadata(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now().UTC()
	feedURL := "https://example.com/feed"
	if err := s.SaveFeedStatus(context.Background(), FeedStatus{FeedURL: feedURL, LastAttemptAt: &now, LastSuccessAt: &now, ItemCount: 12, ETag: "etag-one"}); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Hour)
	if err := s.RecordFeedFailure(context.Background(), FeedStatus{FeedURL: feedURL, LastAttemptAt: &later, LastError: "403 Forbidden"}); err != nil {
		t.Fatal(err)
	}
	var success, etag, failure string
	var count int
	if err := s.db.QueryRow(`SELECT last_success_at,item_count,etag,last_error FROM rss_feed_status WHERE feed_url=?`, feedURL).Scan(&success, &count, &etag, &failure); err != nil {
		t.Fatal(err)
	}
	if success != now.Format(time.RFC3339Nano) || count != 12 || etag != "etag-one" || failure != "403 Forbidden" {
		t.Fatalf("successful metadata erased: success=%q count=%d etag=%q error=%q", success, count, etag, failure)
	}
}

func TestCommitFeedRollsBackWhenStatusCannotBeSaved(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	url := "https://example.com/feed"
	if err := s.SaveFeedItems(ctx, url, []feed.Item{{ExternalID: "previous", Title: "previous"}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER reject_status BEFORE INSERT ON rss_feed_status BEGIN SELECT RAISE(ABORT,'fixture status failure'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.CommitFeed(ctx, FeedBatch{FeedURL: url, Items: []feed.Item{{ExternalID: "new", Title: "new"}}, FetchedAt: now})
	if err == nil {
		t.Fatal("status write failure should fail the whole batch")
	}
	items, err := s.ListFeedItems(ctx, 10)
	if err != nil || len(items) != 1 || items[0].ExternalID != "previous" {
		t.Fatalf("failed batch changed saved articles: items=%+v err=%v", items, err)
	}
}
