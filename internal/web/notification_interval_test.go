package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/control"
)

func TestNotificationIntervalWebAndTUISettings(t *testing.T) {
	for _, surface := range []string{"web", "tui"} {
		t.Run(surface, func(t *testing.T) {
			s := tuiServer(t)
			for _, raw := range []string{"30m", "-1h", "invalid"} {
				var w *httptest.ResponseRecorder
				if surface == "web" {
					r := httptest.NewRequest("POST", "/settings", strings.NewReader("notification_interval="+raw+"&sandbox_enabled=true"))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					w = httptest.NewRecorder()
					s.handleSettingsSave(w, r)
				} else {
					w = tuiRequest(t, s, "PUT", "/api/tui/config", control.Settings{Revision: s.cfg.ConfigRevision, YAML: "notification_interval: " + raw}, true)
				}
				if raw == "30m" {
					if w.Code != 200 && w.Code != 303 {
						t.Fatalf("save=%d %s", w.Code, w.Body.String())
					}
					if s.cfg.NotificationInterval != 30*time.Minute {
						t.Fatal("interval not applied")
					}
				} else if w.Code != 400 || s.cfg.NotificationInterval != 30*time.Minute {
					t.Fatalf("invalid interval changed settings: %d %s", w.Code, w.Body.String())
				}
			}
		})
	}
}
