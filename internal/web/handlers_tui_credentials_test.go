package web

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/control"
)

func TestTUICredentialsSaveRedactsAndRequiresRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows storage unsupported")
	}
	s := tuiServer(t)
	s.cfgPath = filepath.Join(t.TempDir(), "config.yaml")
	if err := config.Save(s.cfgPath, s.cfg); err != nil {
		t.Fatal(err)
	}
	secret := "xoxb-private-fixture"
	changes := control.CredentialChanges{Values: map[string]*string{"slack_bot_token": &secret}}
	if w := tuiRequest(t, s, "PATCH", "/api/tui/credentials", changes, false); w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	w := tuiRequest(t, s, "PATCH", "/api/tui/credentials", changes, true)
	if w.Code != 200 {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	var got control.CredentialsStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.SlackBot.Saved || !got.SlackBot.Managed || got.SlackBot.Active || !got.RestartRequired || got.Revision != 1 || s.cfg.Slack.BotToken != "" {
		t.Fatal("incorrect saved/active state")
	}
	for _, endpoint := range []string{"/api/tui/credentials", "/api/tui/config", "/api/tui/status"} {
		w = tuiRequest(t, s, "GET", endpoint, nil, false)
		if w.Code != 200 || strings.Contains(w.Body.String(), secret) {
			t.Fatalf("unsafe response: %s", endpoint)
		}
	}
	if w = tuiRequest(t, s, "PATCH", "/api/tui/credentials", changes, true); w.Code != 409 {
		t.Fatal("stale writer accepted")
	}
	w = tuiRequest(t, s, "PUT", "/api/tui/config", control.Settings{YAML: "targets: []\nrss: {enabled: false}\n"}, true)
	if w.Code != 200 {
		t.Fatal("ordinary settings save failed")
	}
	loaded, err := config.Load(s.cfgPath)
	if err != nil || loaded.Slack.BotToken != secret || loaded.CredentialsRevision != 1 {
		t.Fatal("restart would not restore credential")
	}
	s.cfg = loaded
	w = tuiRequest(t, s, "GET", "/api/tui/credentials", nil, false)
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.RestartRequired || !got.SlackBot.Active {
		t.Fatal("restart status incorrect")
	}
}

func TestTUICredentialsRejectInvalidRemoteAndStorageFailure(t *testing.T) {
	s := tuiServer(t)
	s.cfgPath = filepath.Join(t.TempDir(), "missing", "config.yaml")
	bad := "invalid-private-secret"
	w := tuiRequest(t, s, "PATCH", "/api/tui/credentials", control.CredentialChanges{Values: map[string]*string{"slack_app_token": &bad}}, true)
	if w.Code != 400 || strings.Contains(w.Body.String(), bad) {
		t.Fatal("unsafe validation response")
	}
	value := "xapp-private-fixture"
	w = tuiRequest(t, s, "PATCH", "/api/tui/credentials", control.CredentialChanges{Values: map[string]*string{"slack_app_token": &value}}, true)
	if w.Code != 500 || s.cfg.Slack.AppToken != "" {
		t.Fatal("save failure changed state")
	}
	req := httptest.NewRequest("GET", "http://127.0.0.1:8999/api/tui/credentials", nil)
	req.RemoteAddr = "192.0.2.1:1"
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("remote request accepted")
	}
	if _, err := os.Stat(s.cfgPath + ".credentials.json"); !os.IsNotExist(err) {
		t.Fatal("unexpected credential file")
	}
}
