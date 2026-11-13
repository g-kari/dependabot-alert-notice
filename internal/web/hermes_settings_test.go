package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

func TestSettingsSave_SwitchesToHermesProxy(t *testing.T) {
	srv, _, _ := newTestServer(t)
	var selected config.Config
	srv.SetEvaluatorConfigChanged(func(cfg config.Config) { selected = cfg })
	form := url.Values{
		"eval_provider":        {"hermes"},
		"eval_hermes_model":    {"Hermes-Test-Model"},
		"eval_hermes_base_url": {config.HermesProxyDefaultURL},
	}
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleSettingsSave(w, req)
	if w.Code != http.StatusSeeOther || srv.cfg.Evaluator.Provider != "hermes" || selected.Evaluator.HermesModel != "Hermes-Test-Model" || selected.Evaluator.HermesBaseURL != config.HermesProxyDefaultURL {
		t.Fatalf("status=%d config=%+v callback=%+v", w.Code, srv.cfg.Evaluator, selected.Evaluator)
	}
}

func TestSettingsPage_HermesDoesNotRequireCodexCLI(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.Evaluator.Provider = "hermes"
	w := httptest.NewRecorder()
	srv.handleSettings(w, httptest.NewRequest(http.MethodGet, "/settings", nil))
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `option value="hermes"`) || !strings.Contains(body, "Hermes Proxy") {
		t.Fatalf("settings page does not expose Hermes provider: status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(body, `id="codex-auth"`) || strings.Contains(body, "Codex CLI パス") {
		t.Fatal("Hermes settings should not present Codex CLI as a requirement")
	}
}

func TestSettingsSave_HermesHiddenFieldsRemainUnchanged(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.Evaluator.Provider = "hermes"
	srv.cfg.Evaluator.HermesModel = "Hermes-Custom"
	srv.cfg.Evaluator.HermesBaseURL = config.HermesProxyDefaultURL
	srv.cfg.Evaluator.Sandbox.Enabled = true
	srv.cfg.Evaluator.Sandbox.MemoryLimit = "1g"
	form := url.Values{"eval_provider": {"claude"}}
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleSettingsSave(w, req)
	if w.Code != http.StatusSeeOther || srv.cfg.Evaluator.Provider != "claude" || srv.cfg.Evaluator.HermesModel != "Hermes-Custom" || srv.cfg.Evaluator.HermesBaseURL != config.HermesProxyDefaultURL || !srv.cfg.Evaluator.Sandbox.Enabled || srv.cfg.Evaluator.Sandbox.MemoryLimit != "1g" {
		t.Fatalf("hidden settings changed during provider switch: status=%d evaluator=%+v", w.Code, srv.cfg.Evaluator)
	}
}

func TestSettingsPage_ShowsHermesDataFlowBeforeSelection(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.Evaluator.Provider = "claude"
	w := httptest.NewRecorder()
	srv.handleSettings(w, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Hermes Proxyを選ぶと、評価対象のアラート情報は選択モデルへ送信されます") {
		t.Fatalf("Hermes data-flow notice should be visible before selecting the provider: status=%d", w.Code)
	}
}
