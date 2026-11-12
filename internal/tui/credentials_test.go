package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/g-kari/dependabot-alert-notice/internal/control"
)

func TestSecretInputNeverRendersValueAndCancels(t *testing.T) {
	for _, key := range []tea.KeyPressMsg{{Code: tea.KeyEnter}, {Code: tea.KeyEsc}, {Code: 'c', Mod: tea.ModCtrl}, {Code: 'd', Mod: tea.ModCtrl}} {
		model := secretInputModel{label: "Slack token"}
		next, _ := model.Update(tea.KeyPressMsg{Code: tea.KeyExtended, Text: "xoxb-private-fixture"})
		model = next.(secretInputModel)
		if strings.Contains(model.View().Content, "private") || strings.Contains(model.View().Content, "xoxb") {
			t.Fatal("secret rendered")
		}
		next, _ = model.Update(key)
		model = next.(secretInputModel)
		if !model.done {
			t.Fatal("not finished")
		}
		if key.Code == tea.KeyEnter {
			if string(model.value) != "xoxb-private-fixture" {
				t.Fatal("input lost")
			}
		} else if !model.cancelled || len(model.value) != 0 {
			t.Fatal("cancel retained secret")
		}
	}
}
func TestSecretInputRejectsNonTerminal(t *testing.T) {
	var out bytes.Buffer
	term := terminal{ctx: context.Background(), reader: strings.NewReader("private\n"), out: &out}
	if _, err := term.readSecret("token"); err == nil {
		t.Fatal("echo-prone input accepted")
	}
	if strings.Contains(out.String(), "private") {
		t.Fatal("secret leaked")
	}
}
func TestCredentialsSlackSaveOrCancelIsAtomicAndRedacted(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{true: "cancel", false: "save"}[cancel], func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" {
					calls++
					var changes control.CredentialChanges
					if err := json.NewDecoder(r.Body).Decode(&changes); err != nil {
						t.Error(err)
					}
					if changes.Revision != 4 || changes.Values["slack_bot_token"] == nil || *changes.Values["slack_bot_token"] != "xoxb-private-fixture" || changes.Values["slack_app_token"] == nil || *changes.Values["slack_app_token"] != "xapp-private-fixture" {
						t.Error("incorrect payload")
					}
				}
				if err := json.NewEncoder(w).Encode(control.CredentialsStatus{Revision: 4, RestartRequired: r.Method == "PATCH"}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer client.http.CloseIdleConnections()
			var out bytes.Buffer
			inputs := 0
			term := terminal{ctx: context.Background(), reader: strings.NewReader("1\ny\n0\n"), out: &out, secretReader: func(string) (string, error) {
				inputs++
				if inputs == 1 {
					return "xoxb-private-fixture", nil
				}
				if cancel {
					return "", io.EOF
				}
				return "xapp-private-fixture", nil
			}}
			err = term.credentials(context.Background(), client)
			if cancel {
				if err != io.EOF || calls != 0 {
					t.Fatal("partial save after cancel")
				}
			} else if err != nil || calls != 1 {
				t.Fatalf("save failed: %v calls=%d", err, calls)
			}
			if strings.Contains(out.String(), "private-fixture") {
				t.Fatal("secret leaked in output")
			}
		})
	}
}

func TestCredentialsDeclineBlankDisableAndInherit(t *testing.T) {
	cases := []struct {
		name, input string
		secrets     []string
		key         string
		want        *string
		calls       int
	}{
		{name: "decline", input: "2\nn\n0\n", secrets: []string{"https://discord.com/api/webhooks/123/private-fixture"}},
		{name: "blank", input: "1\n0\n", secrets: []string{"", ""}},
		{name: "disable", input: "4\ny\n0\n", key: "discord_webhook_url", want: new(string), calls: 1},
		{name: "inherit", input: "6\ny\n0\n", key: "discord_webhook_url", calls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" {
					calls++
					var changes control.CredentialChanges
					if err := json.NewDecoder(r.Body).Decode(&changes); err != nil {
						t.Error(err)
					}
					value, ok := changes.Values[tc.key]
					if !ok || (value == nil) != (tc.want == nil) || (value != nil && *value != *tc.want) {
						t.Error("incorrect disable/inherit")
					}
				}
				if err := json.NewEncoder(w).Encode(control.CredentialsStatus{}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := NewClient(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer client.http.CloseIdleConnections()
			var out bytes.Buffer
			index := 0
			term := terminal{ctx: context.Background(), reader: strings.NewReader(tc.input), out: &out, secretReader: func(string) (string, error) { value := tc.secrets[index]; index++; return value, nil }}
			if err := term.credentials(context.Background(), client); err != nil {
				t.Fatal(err)
			}
			if calls != tc.calls {
				t.Fatalf("calls=%d expected=%d", calls, tc.calls)
			}
			if strings.Contains(out.String(), "private-fixture") {
				t.Fatal("secret displayed")
			}
		})
	}
}

func TestSecretInputV2PasteValidationAndEditing(t *testing.T) {
	for _, tt := range []struct {
		name    string
		text    string
		invalid bool
	}{
		{"token", "xoxb-private-fixture", false},
		{"space", "private fixture", true},
		{"newline", "private\nfixture", true},
		{"escape", "private\x1bfixture", true},
		{"unicode", "秘密", true},
		{"too long", strings.Repeat("x", 4097), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			model := secretInputModel{label: "Token"}
			next, _ := model.Update(tea.PasteMsg{Content: tt.text})
			model = next.(secretInputModel)
			if model.invalid != tt.invalid || len(model.value) > 4096 || model.done {
				t.Fatalf("paste validation: invalid=%t length=%d done=%t", model.invalid, len(model.value), model.done)
			}
			if strings.Contains(model.View().Content, "private") {
				t.Fatal("paste rendered secret")
			}
			before := len(model.value)
			next, _ = model.Update(tea.KeyReleaseMsg{Code: tea.KeyEnter})
			model = next.(secretInputModel)
			if model.done || len(model.value) != before {
				t.Fatal("key release changed input")
			}
			next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyBackspace})
			model = next.(secretInputModel)
			if len(model.value) != max(0, before-1) {
				t.Fatal("backspace did not remove one character")
			}
			buffer := model.value
			next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
			model = next.(secretInputModel)
			if !model.cancelled || len(model.value) != 0 {
				t.Fatal("cancel retained pasted secret")
			}
			for _, r := range buffer {
				if r != 0 {
					t.Fatal("cancel did not clear backing buffer")
				}
			}
		})
	}
}
