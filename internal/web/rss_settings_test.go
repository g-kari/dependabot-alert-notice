package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

func TestRSSSettings_AddToggleDeletePersists(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.RSS = config.RSSConfig{RefreshInterval: time.Hour, RequestTimeout: 10 * time.Second, MaxItemsPerFeed: 100, RetentionDays: 90}
	srv.cfgPath = filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(srv.cfgPath, srv.cfg); err != nil {
		t.Fatal(err)
	}

	page := httptest.NewRecorder()
	srv.Handler().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "RSSフィードを追加") {
		t.Fatalf("settings page status=%d, RSS form missing=%v", page.Code, !strings.Contains(page.Body.String(), "RSSフィードを追加"))
	}
	cookie := page.Result().Cookies()[0]
	post := func(path string, values url.Values) *httptest.ResponseRecorder {
		t.Helper()
		values.Set("csrf_token", cookie.Value)
		values.Set("revision", ""+strings.TrimSpace(values.Get("revision")))
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	add := url.Values{"name": {"Security Feed"}, "url": {"https://example.com/security.xml"}, "revision": {"0"}}
	if w := post("/settings/rss/add", add); w.Code != http.StatusSeeOther {
		t.Fatalf("add status=%d body=%s", w.Code, w.Body.String())
	}
	loaded, err := config.Load(srv.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.RSS.Enabled || len(loaded.RSS.Feeds) != 1 || !loaded.RSS.Feeds[0].Enabled {
		t.Fatalf("added feed not active in saved config: %+v", loaded.RSS)
	}
	if w := post("/settings/rss/add", url.Values{"name": {"Duplicate"}, "url": {"https://example.com/security.xml"}, "revision": {"1"}}); w.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d, want 409", w.Code)
	}
	if w := post("/settings/rss/0/toggle", url.Values{"revision": {"1"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("toggle status=%d body=%s", w.Code, w.Body.String())
	}
	if srv.cfg.RSS.Feeds[0].Enabled {
		t.Fatal("feed should be disabled")
	}
	if w := post("/settings/rss/0/delete", url.Values{"revision": {"2"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body.String())
	}
	loaded, err = config.Load(srv.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.RSS.Feeds) != 0 || loaded.RSS.Enabled {
		t.Fatalf("feed should be removed and RSS disabled: %+v", loaded.RSS)
	}
}

func TestRSSSettings_RejectsInvalidURLAndMissingCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.RSS = config.RSSConfig{RefreshInterval: time.Hour, RequestTimeout: 10 * time.Second, MaxItemsPerFeed: 100, RetentionDays: 90}
	values := url.Values{"name": {"bad"}, "url": {"http://127.0.0.1/feed"}, "revision": {"0"}}
	req := httptest.NewRequest(http.MethodPost, "/settings/rss/add", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d, want 403", w.Code)
	}
	cookieW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(cookieW, httptest.NewRequest(http.MethodGet, "/settings", nil))
	cookie := cookieW.Result().Cookies()[0]
	values.Set("csrf_token", cookie.Value)
	req = httptest.NewRequest(http.MethodPost, "/settings/rss/add", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || len(srv.cfg.RSS.Feeds) != 0 {
		t.Fatalf("invalid URL status=%d, feeds=%d", w.Code, len(srv.cfg.RSS.Feeds))
	}
}
