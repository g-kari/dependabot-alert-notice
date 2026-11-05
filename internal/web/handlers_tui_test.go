package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/control"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/tui"
)

func tuiRequest(t *testing.T, s *Server, method, path string, body any, token bool) *httptest.ResponseRecorder {
	t.Helper()
	var data bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&data).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:8999"+path, &data)
	r.RemoteAddr = "127.0.0.1:1234"
	if token {
		r.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-token"})
		r.Header.Set("X-CSRF-Token", "test-token")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func tuiServer(t *testing.T) *Server {
	t.Helper()
	s, db, _ := newTestServer(t)
	t.Cleanup(func() { _ = db.Close() })
	s.cfg = config.Defaults()
	return s
}
func TestTUISettingsReadRedactsSecrets(t *testing.T) {
	s := tuiServer(t)
	s.cfg.Slack.BotToken = "private-bot"
	s.cfg.Slack.AppToken = "private-app"
	s.cfg.Discord.WebhookURL = "private-webhook"
	w := tuiRequest(t, s, "GET", "/api/tui/config", nil, false)
	if w.Code != 200 {
		t.Fatalf("status=%d: %s", w.Code, w.Body.String())
	}
	var got control.Settings
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-bot", "private-app", "private-webhook", "bot_token:", "app_token:", "webhook_url:", "config_revision:"} {
		if strings.Contains(got.YAML, secret) {
			t.Fatalf("exposed %q", secret)
		}
	}
	if got.CSRF == "" || len(w.Result().Cookies()) == 0 || !strings.Contains(got.YAML, "feeds:") {
		t.Fatal("missing settings/session")
	}
}
func TestTUISettingsSavePersistsAndSwitchesEvaluator(t *testing.T) {
	s := tuiServer(t)
	s.cfgPath = filepath.Join(t.TempDir(), "config.yaml")
	s.cfg.Slack.BotToken = "runtime-secret"
	called := false
	s.SetEvaluatorConfigChanged(func(c config.Config) { called = c.Evaluator.Provider == "codex" })
	w := tuiRequest(t, s, "PUT", "/api/tui/config", control.Settings{YAML: "targets: [{owner: acme, repo: api}]\nevaluator: {provider: codex}\nrss: {enabled: false}\n"}, true)
	if w.Code != 200 {
		t.Fatalf("status=%d: %s", w.Code, w.Body.String())
	}
	if s.cfg.ConfigRevision != 1 || !called || s.cfg.Slack.BotToken != "runtime-secret" || s.cfg.RSS.Enabled {
		t.Fatal("configuration not applied safely")
	}
	raw, err := os.ReadFile(s.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "runtime-secret") {
		t.Fatal("persisted credential")
	}
	if len(s.feedConfigChanged) == 0 || len(s.riskConfigChanged) == 0 {
		t.Fatal("schedulers not notified")
	}
	stale := tuiRequest(t, s, "PUT", "/api/tui/config", control.Settings{YAML: "targets: []\n"}, true)
	if stale.Code != 409 || len(s.cfg.Targets) != 1 {
		t.Fatal("stale update overwrote settings")
	}
}
func TestTUISettingsRejectsUnsafeInputWithoutChangingSettings(t *testing.T) {
	for _, input := range []string{"web: [broken", "unknown_field: true", "evaluator: {sandbox: {enabled: false}}", "slack: {bot_token: secret}", "discord: {webhook_url: secret}", "poll_interval: 0s", "rss: {refresh_interval: 1s}", "null", "{}\n---\ntargets: []"} {
		t.Run(input, func(t *testing.T) {
			s := tuiServer(t)
			w := tuiRequest(t, s, "PUT", "/api/tui/config", control.Settings{YAML: input}, true)
			if w.Code != 400 {
				t.Fatalf("status=%d: %s", w.Code, w.Body.String())
			}
			if s.cfg.ConfigRevision != 0 || !s.cfg.Evaluator.Sandbox.Enabled {
				t.Fatal("invalid input changed config")
			}
		})
	}
}
func TestTUIRequiresLocalHostAndCSRF(t *testing.T) {
	s := tuiServer(t)
	if w := tuiRequest(t, s, "PUT", "/api/tui/config", control.Settings{YAML: "targets: []"}, false); w.Code != 403 {
		t.Fatalf("missing CSRF status=%d", w.Code)
	}
	for _, tt := range []struct{ host, remote string }{{"127.0.0.1:8999", "192.0.2.1:90"}, {"attacker.example:8999", "127.0.0.1:90"}} {
		r := httptest.NewRequest("GET", "http://"+tt.host+"/api/tui/config", nil)
		r.RemoteAddr = tt.remote
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("remote=%s host=%s status=%d", tt.remote, tt.host, w.Code)
		}
	}
}
func TestTUIFailedSaveLeavesRuntimeUnchanged(t *testing.T) {
	s := tuiServer(t)
	s.cfgPath = filepath.Join(t.TempDir(), "missing", "config.yaml")
	w := tuiRequest(t, s, "PUT", "/api/tui/config", control.Settings{YAML: "targets: [{owner: acme}]"}, true)
	if w.Code != 500 || s.cfg.ConfigRevision != 0 || len(s.cfg.Targets) != 0 {
		t.Fatalf("failed save changed runtime: %d", w.Code)
	}
}
func TestTUIRestartRequiredForStaticSettings(t *testing.T) {
	s := tuiServer(t)
	w := tuiRequest(t, s, "PUT", "/api/tui/config", control.Settings{YAML: "web: {port: 9010}"}, true)
	var result control.Saved
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.RestartRequired {
		t.Fatal("missing restart notice")
	}
}

func TestTUIEndToEndSettingsAndClientExit(t *testing.T) {
	s := tuiServer(t)
	s.cfgPath = filepath.Join(t.TempDir(), "config.yaml")
	api := httptest.NewServer(s.Handler())
	defer api.Close()
	var out bytes.Buffer
	// The first root item is poll_interval. Save and leave the client.
	if err := tui.Run(context.Background(), api.URL, strings.NewReader("4\n1\n45m\ns\ny\n0\n"), &out); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PollInterval != 45*time.Minute || !strings.Contains(out.String(), "再起動") {
		t.Fatalf("setting not persisted: %s", out.String())
	}
	w := tuiRequest(t, s, "GET", "/api/tui/status", nil, false)
	if w.Code != 200 {
		t.Fatal("client exit affected application")
	}
}

func TestTUIStatusAndManualActions(t *testing.T) {
	s := tuiServer(t)
	s.cfg.Targets = []config.Target{{Owner: "testorg"}}
	saveAlert(s.store, 12, "package", model.SeverityHigh)
	w := tuiRequest(t, s, "GET", "/api/tui/status", nil, false)
	var status control.Status
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Alerts) != 1 {
		t.Fatal("missing stored alert")
	}
	unavailable := tuiRequest(t, s, "POST", "/api/tui/poll", nil, true)
	if unavailable.Code != 503 {
		t.Fatalf("missing worker status=%d", unavailable.Code)
	}
	pollDone := make(chan struct{})
	s.SetPollFn(func() { close(pollDone) })
	accepted := tuiRequest(t, s, "POST", "/api/tui/poll", nil, true)
	if accepted.Code != 303 {
		t.Fatalf("manual poll status=%d", accepted.Code)
	}
	select {
	case <-pollDone:
	case <-time.After(time.Second):
		t.Fatal("poll did not run")
	}
	rejected := tuiRequest(t, s, "POST", "/api/tui/evaluate/99999", nil, true)
	if rejected.Code != 404 {
		t.Fatalf("missing alert status=%d", rejected.Code)
	}
}
