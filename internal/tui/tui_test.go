package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/control"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"gopkg.in/yaml.v3"
)

func TestDetailShowsConditionalAWSResult(t *testing.T) {
	var out bytes.Buffer
	menu := terminal{reader: strings.NewReader("1\n"), out: &out}
	status := control.Status{Alerts: []*model.AlertRecord{{Alert: model.Alert{ID: 1}, Evaluation: &model.Evaluation{AWSRisk: "EC2で実行する場合の確認項目"}}}}
	if err := menu.show("2", status); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "aws_risk") || !strings.Contains(out.String(), "EC2で実行する場合の確認項目") {
		t.Fatal(out.String())
	}
}

func TestRunSettingsSaveAndCancel(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		wantSave    bool
	}{{"save", "4\n1\n1h\ns\ny\n0\n", true}, {"discard", "4\n1\n2h\nq\n0\n", false}, {"EOF", "4\n1\n2h\n", false}, {"decline", "4\n1\n2h\ns\nn\nq\n0\n", false}} {
		t.Run(tt.name, func(t *testing.T) {
			saves := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/tui/config" {
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				if r.Method == "GET" {
					http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "session", Path: "/"})
					_ = json.NewEncoder(w).Encode(control.Settings{Revision: 7, YAML: "poll_interval: 30m\n", CSRF: "session"})
					return
				}
				if r.Method != "PUT" {
					t.Errorf("unexpected method %s", r.Method)
					return
				}
				cookie, err := r.Cookie("csrf_token")
				if err != nil || cookie.Value != "session" || r.Header.Get("X-CSRF-Token") != "session" {
					t.Error("missing CSRF handshake")
				}
				var settings control.Settings
				if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
					t.Error(err)
				}
				if settings.Revision != 7 || !strings.Contains(settings.YAML, "1h") {
					t.Errorf("incorrect settings: %+v", settings)
				}
				saves++
				_ = json.NewEncoder(w).Encode(control.Saved{Revision: 8, RestartRequired: true})
			}))
			defer api.Close()
			var out bytes.Buffer
			if err := Run(context.Background(), api.URL, strings.NewReader(tt.input), &out); err != nil {
				t.Fatal(err)
			}
			if (saves == 1) != tt.wantSave {
				t.Fatalf("saves=%d", saves)
			}
			if tt.wantSave && !strings.Contains(out.String(), "再起動") {
				t.Fatal("missing restart notice")
			}
		})
	}
}
func TestClientRejectsRemoteOrAmbiguousURLs(t *testing.T) {
	for _, url := range []string{"https://example.com", "http://192.0.2.1", "http://127.0.0.1/path", "http://user:pass@127.0.0.1", "http://127.0.0.1?token=x", "http://127.0.0.1#x"} {
		if _, err := NewClient(url); err == nil {
			t.Errorf("accepted %s", url)
		}
	}
}
func TestSettingsSequenceEditing(t *testing.T) {
	var out bytes.Buffer
	menu := terminal{reader: strings.NewReader("a\nowner: acme\nrepo: api\n.\n1\n2\nfrontend\n0\ns\n"), out: &out}
	node, err := parseNode("[]")
	if err != nil {
		t.Fatal(err)
	}
	command, err := menu.edit(node, "targets")
	if err != nil {
		t.Fatal(err)
	}
	if command != "save" || len(node.Content) != 1 || node.Content[0].Content[3].Value != "frontend" {
		t.Fatalf("edited node=%+v command=%s", node, command)
	}
}
func TestTerminalSanitizesUntrustedControlCharacters(t *testing.T) {
	if strings.Contains(clean("evil\x1b[2J\r\ntext"), "\x1b") || strings.Contains(clean("evil\rtext"), "\r") {
		t.Fatal("terminal controls survived")
	}
}
func TestClientReportsConflictAndDoesNotFollowRedirects(t *testing.T) {
	for _, code := range []int{409, 302} {
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://example.com")
			http.Error(w, "設定が更新されています", code)
		}))
		c, err := NewClient(api.URL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Settings(context.Background()); err == nil {
			t.Errorf("status %d accepted", code)
		}
		api.Close()
	}
}

func TestSettingsMultilineInputPreservesYAMLIndentation(t *testing.T) {
	var out bytes.Buffer
	menu := terminal{reader: strings.NewReader("a\nevaluator\nprovider: codex\nsandbox:\n  image: customized\n  enabled: true\n.\ns\n"), out: &out}
	node, err := parseNode("{}")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := menu.edit(node, ""); err != nil {
		t.Fatal(err)
	}
	if len(node.Content) != 2 || node.Content[1].Content[3].Kind != yaml.MappingNode {
		t.Fatal("nested map indentation was lost")
	}
}
