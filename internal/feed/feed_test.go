package feed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestFetchRSSAndExtractCVE(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<?xml version="1.0"?><rss><channel><item><guid>one</guid><title>Fix CVE-2024-1234</title><link>https://example.com/a</link><description><![CDATA[<b>CVE-2024-1234</b> CVE-2025-0042]]></description></item></channel></rss>`))
	}))
	defer srv.Close()
	items, err := Fetch(context.Background(), srv.URL, FetchOptions{HTTPClient: srv.Client(), MaxItems: 10, AllowPrivateNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].CVEIDs) != 2 || items[0].CVEIDs[0] != "CVE-2024-1234" {
		t.Fatalf("items = %+v", items)
	}
	if strings.Contains(items[0].Summary, "<b>") {
		t.Fatalf("summary still has html: %q", items[0].Summary)
	}
}

func TestFetchUsesIdentifiableUserAgent(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "security-notice/1.0" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`<rss><channel><item><title>CVE-2026-12345</title></item></channel></rss>`))
	}))
	defer srv.Close()

	items, err := Fetch(context.Background(), srv.URL, FetchOptions{HTTPClient: srv.Client(), AllowPrivateNetwork: true})
	if err != nil || len(items) != 1 {
		t.Fatalf("custom User-Agent feed: items=%+v err=%v", items, err)
	}
}

func TestFetchRejectsHTTPByDefault(t *testing.T) {
	_, err := Fetch(context.Background(), "http://example.com/feed", FetchOptions{})
	if err == nil {
		t.Fatal("expected HTTPS error")
	}
}

func TestFetchAtom(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<feed><entry><id>x</id><title>CVE-2024-7</title><link href="https://example.com/a"/><updated>2026-01-01T00:00:00Z</updated></entry></feed>`))
	}))
	defer srv.Close()
	items, err := Fetch(context.Background(), srv.URL, FetchOptions{HTTPClient: srv.Client(), AllowPrivateNetwork: true})
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%+v err=%v", items, err)
	}
}

func TestParseRSS1RDF(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel><title>JPCERT/CC</title></channel>
  <item rdf:about="https://example.org/advisory"><title>CVE-2026-12345 の注意喚起</title><link>https://example.org/advisory</link><description>修正を適用</description><dc:date>2026-09-29T00:00:00Z</dc:date></item>
</rdf:RDF>`)
	items, err := Parse(body, 10)
	if err != nil {
		t.Fatalf("RSS 1.0 parse: %v", err)
	}
	if len(items) != 1 || items[0].Link != "https://example.org/advisory" || len(items[0].CVEIDs) != 1 || items[0].Published.IsZero() {
		t.Fatalf("RSS 1.0 items = %+v", items)
	}
}

func TestFetchWithCacheRequestsValidatorsAndKeeps304(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != `"version-one"` || r.Header.Get("If-Modified-Since") != "Wed, 30 Sep 2026 00:00:00 GMT" {
			t.Error("conditional validators missing")
		}
		w.Header().Set("ETag", `"version-two"`)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	result, err := FetchWithCache(context.Background(), srv.URL, FetchOptions{HTTPClient: srv.Client(), AllowPrivateNetwork: true, ETag: `"version-one"`, LastModified: "Wed, 30 Sep 2026 00:00:00 GMT"})
	if err != nil || !result.NotModified || result.ETag != `"version-two"` || len(result.Items) != 0 || result.LastModified == "" {
		t.Fatalf("conditional response=%+v err=%v", result, err)
	}
}

func TestFetchRateLimitHonorsRetryAfter(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	start := time.Now()
	_, err := FetchWithCache(context.Background(), srv.URL, FetchOptions{HTTPClient: srv.Client(), AllowPrivateNetwork: true})
	var status *HTTPStatusError
	if !errors.As(err, &status) || status.StatusCode != 429 || status.RetryAt.Before(start.Add(119*time.Second)) || status.RetryAt.After(start.Add(125*time.Second)) {
		t.Fatalf("rate limit metadata missing: %+v err=%v", status, err)
	}
}

func TestFetchTimeoutAppliesToInjectedClient(t *testing.T) {
	// A real server returning on cancellation can race an empty response against
	// the client's deadline. Test the injected-client contract with virtual time
	// and a transport that waits for the request context, without network I/O.
	synctest.Test(t, func(t *testing.T) {
		client := &http.Client{Transport: deadlineTransport(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		})}
		start := time.Now()
		_, err := Fetch(context.Background(), "https://example.invalid/feed", FetchOptions{HTTPClient: client, AllowPrivateNetwork: true, Timeout: 20 * time.Millisecond})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("configured deadline ignored: %v", err)
		}
		if elapsed := time.Since(start); elapsed != 20*time.Millisecond {
			t.Fatalf("configured timeout changed: elapsed=%v, want 20ms", elapsed)
		}
	})
}

type deadlineTransport func(*http.Request) (*http.Response, error)

func (f deadlineTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestRetryAfterBounds(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		header string
		wait   time.Duration
	}{
		{"seconds", "60", time.Minute},
		{"http-date", now.Add(time.Hour).Format(http.TimeFormat), time.Hour},
		{"invalid", "invalid", 15 * time.Minute},
		{"missing", "", 15 * time.Minute},
		{"past", now.Add(-time.Hour).Format(http.TimeFormat), 0},
		{"bounded", "999999999", 24 * time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := retryAt(test.header, now); !got.Equal(now.Add(test.wait)) {
				t.Fatalf("Retry-After %q = %v, want %v", test.header, got, now.Add(test.wait))
			}
		})
	}
}
