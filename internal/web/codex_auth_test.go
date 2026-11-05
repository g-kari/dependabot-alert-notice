package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

type fakeCodexAuth struct {
	status  toolResult
	started bool
}

func (f *fakeCodexAuth) Status(_ context.Context, _ string) toolResult { return f.status }
func (f *fakeCodexAuth) StartLogin(_ context.Context, _ string) error {
	f.started = true
	return nil
}

func TestCodexAuth_StatusAndLocalLogin(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.CodexPath = "codex"
	auth := &fakeCodexAuth{status: toolResult{OK: true, Message: "ChatGPTで認証済み"}}
	srv.codexAuth = auth

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/settings/codex/status", nil))
	var got toolResult
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil || !got.OK {
		t.Fatalf("status=%d result=%+v err=%v", w.Code, got, err)
	}

	page := httptest.NewRecorder()
	srv.Handler().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/settings", nil))
	cookie := page.Result().Cookies()[0]
	form := url.Values{"csrf_token": {cookie.Value}}
	req := httptest.NewRequest(http.MethodPost, "/settings/codex/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther || !auth.started {
		t.Fatalf("login status=%d started=%v body=%s", w.Code, auth.started, w.Body.String())
	}

	auth.started = false
	req = httptest.NewRequest(http.MethodPost, "/settings/codex/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || auth.started {
		t.Fatalf("remote login status=%d started=%v", w.Code, auth.started)
	}
}

func TestSettingsSave_SwitchesToCodex(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.Evaluator.Sandbox.Enabled = true
	var selected config.Config
	srv.SetEvaluatorConfigChanged(func(cfg config.Config) { selected = cfg })
	form := url.Values{"eval_provider": {"codex"}, "codex_path": {"custom-codex"}, "eval_codex_model": {"gpt-6-sol"}, "eval_claude_model": {"claude-sonnet-test"}, "sandbox_enabled": {"true"}, "sandbox_codex_image": {"codex-evaluator:local"}}
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleSettingsSave(w, req)
	if w.Code != http.StatusSeeOther || srv.cfg.Evaluator.Provider != "codex" || selected.CodexPath != "custom-codex" || selected.Evaluator.Sandbox.CodexImage != "codex-evaluator:local" || selected.Evaluator.CodexModel != "gpt-6-sol" || selected.Evaluator.ClaudeModel != "claude-sonnet-test" {
		t.Fatalf("status=%d cfg=%+v callback=%+v", w.Code, srv.cfg.Evaluator, selected.Evaluator)
	}
}
