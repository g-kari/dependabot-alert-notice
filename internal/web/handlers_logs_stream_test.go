package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestLogsStream_Headers(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/logs-stream", nil)
	ctx, cancel := withTimeout(req.Context(), 50*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	srv.handleLogsStream(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
}

func TestLogsStream_ExistingLogsOnConnect(t *testing.T) {
	srv, st, _ := newTestServer(t)
	st.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "info", Message: "既存ログ1"})
	st.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "error", Message: "既存ログ2"})

	req := httptest.NewRequest(http.MethodGet, "/api/logs-stream", nil)
	ctx, cancel := withTimeout(req.Context(), 50*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	srv.handleLogsStream(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "既存ログ1") {
		t.Error("接続時の既存ログ1がSSEに含まれていない")
	}
	if !strings.Contains(body, "既存ログ2") {
		t.Error("接続時の既存ログ2がSSEに含まれていない")
	}
}

func TestLogsStream_ReadySentinel(t *testing.T) {
	srv, st, _ := newTestServer(t)
	st.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "info", Message: "既存ログ"})

	req := httptest.NewRequest(http.MethodGet, "/api/logs-stream", nil)
	ctx, cancel := withTimeout(req.Context(), 50*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	srv.handleLogsStream(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "event: ready") {
		t.Error("既存ログ送信後に event: ready が含まれていない")
	}
	// readyは既存ログの後に来る
	readyIdx := strings.Index(body, "event: ready")
	logIdx := strings.Index(body, "既存ログ")
	if readyIdx < logIdx {
		t.Error("event: ready が既存ログより前に来ている")
	}
}

func TestLogsStream_EventFormat(t *testing.T) {
	srv, st, _ := newTestServer(t)
	st.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "info", Message: "フォーマットテスト"})

	req := httptest.NewRequest(http.MethodGet, "/api/logs-stream", nil)
	ctx, cancel := withTimeout(req.Context(), 50*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	srv.handleLogsStream(w, req)

	body := w.Body.String()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") {
			return
		}
	}
	t.Error("SSEのdata行が見つからない")
}
