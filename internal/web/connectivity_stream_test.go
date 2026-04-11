package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

func TestConnectivityStream_Headers(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/connectivity-stream", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityStream(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
}

func TestConnectivityStream_ContainsDoneEvent(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
	}
	t.Setenv("SLACK_BOT_TOKEN", "")

	req := httptest.NewRequest(http.MethodGet, "/api/connectivity-stream", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityStream(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `"type":"done"`) {
		t.Error("レスポンスにdoneイベントが含まれていない")
	}
}

func TestConnectivityStream_ContainsToolEvents(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
	}
	t.Setenv("SLACK_BOT_TOKEN", "")

	req := httptest.NewRequest(http.MethodGet, "/api/connectivity-stream", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityStream(w, req)

	body := w.Body.String()
	for _, tool := range []string{"gh", "claude", "slack"} {
		if !strings.Contains(body, `"type":"`+tool+`"`) {
			t.Errorf("レスポンスに %q イベントが含まれていない", tool)
		}
	}
}

func TestConnectivityStream_EventFormat(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
	}
	t.Setenv("SLACK_BOT_TOKEN", "")

	req := httptest.NewRequest(http.MethodGet, "/api/connectivity-stream", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityStream(w, req)

	// "data: {...}\n\n" 形式を確認
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var event streamEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Errorf("SSEイベントのJSONパース失敗: %q, err: %v", payload, err)
		}
		if event.Type == "" {
			t.Errorf("typeフィールドが空: %q", payload)
		}
	}
}

func TestConnectivityStream_WithTarget(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
		Targets:    []config.Target{{Owner: "testorg", Repo: "testrepo"}},
	}
	t.Setenv("SLACK_BOT_TOKEN", "")

	req := httptest.NewRequest(http.MethodGet, "/api/connectivity-stream", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityStream(w, req)

	if !strings.Contains(w.Body.String(), `"type":"target"`) {
		t.Error("ターゲットイベントが含まれていない")
	}
}
