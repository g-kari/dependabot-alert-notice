package tui

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestChoiceModelNavigatesAndChoosesWithoutTypingValue(t *testing.T) {
	m := newChoiceModel("モデル", []choice{{"one", "モデル1"}, {"two", "モデル2"}}, 0, "keep", nil)
	updated, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m = updated.(choiceModel)
	updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = updated.(choiceModel)
	if !m.done || m.value != "two" {
		t.Fatalf("selection=%+v", m)
	}
}

func TestChoiceModelCancellationAndShortcuts(t *testing.T) {
	for _, tt := range []struct {
		key         tea.KeyPressMsg
		value       string
		interrupted bool
	}{
		{tea.KeyPressMsg{Code: tea.KeyEsc}, "keep", false},
		{tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}, "", true},
		{tea.KeyPressMsg{Code: tea.KeyExtended, Text: "s"}, "save", false},
	} {
		m := newChoiceModel("設定", []choice{{"one", "項目"}}, 0, "keep", map[string]string{"s": "save"})
		updated, _ := m.Update(tt.key)
		m = updated.(choiceModel)
		if !m.done || m.value != tt.value || m.interrupted != tt.interrupted {
			t.Fatalf("key=%v model=%+v", tt.key, m)
		}
	}
}

func TestChoiceModelViewportKeepsSelectionVisibleAndSanitizesText(t *testing.T) {
	var options []choice
	for i := 0; i < 50; i++ {
		options = append(options, choice{"value", "item"})
	}
	options[49].label = "last\x1b[2J"
	m := newChoiceModel("title\x1b[2J", options, 49, "keep", nil)
	updated, _ := m.Update(tea.WindowSizeMsg{Width: 35, Height: 12})
	m = updated.(choiceModel)
	view := m.View().Content
	if !strings.Contains(view, "last") || strings.Contains(view, "\x1b[2J") || strings.Count(view, "item") >= 10 {
		t.Fatalf("unsafe or unbounded view: %q", view)
	}
}

func TestScalarSettingsCanSelectFromCandidates(t *testing.T) {
	for _, tt := range []struct{ path, yaml, input, want string }{
		{"evaluator.provider", "claude", "2\n", "codex"},
		{"evaluator.provider", "claude", "3\n", "hermes"},
		{"notification_interval", "30m0s", "1\n", "1h0m0s"},
		{"notification_interval", "30m0s", "m\n45m\n", "45m"},
		{"evaluator.codex_model", "''", "2\n", "gpt-6-luna"},
		{"notify_min_severity", "low", "4\n", "high"},
		{"evaluator.auto_eval", "false", "2\n", "true"},
		{"evaluator.sandbox.runtime", "auto", "2\n", "apple"},
		{"evaluator.sandbox.runtime", "auto", "4\n", "podman"},
		{"evaluator.codex_model", "custom-current", "\n", "custom-current"},
		{"evaluator.codex_model", "gpt-6-luna", "m\nmy-custom-model\n", "my-custom-model"},
		{"evaluator.codex_model", "gpt-6-luna", "m\n-\n", ""},
		{"evaluator.sandbox.enabled", "true", "1\n", "true"},
		{"evaluator.provider", "claude", "0\n", "claude"},
	} {
		t.Run(tt.path+tt.input, func(t *testing.T) {
			node, err := parseNode(tt.yaml)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			menu := terminal{reader: strings.NewReader(tt.input), out: &out}
			if _, err := menu.edit(node, tt.path); err != nil {
				t.Fatal(err)
			}
			if node.Value != tt.want {
				t.Fatalf("value=%q want=%q output=%s", node.Value, tt.want, out.String())
			}
		})
	}
}

func TestCancelledCustomModelDoesNotChangeDraft(t *testing.T) {
	node, err := parseNode("current-model")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	menu := terminal{reader: strings.NewReader("m\n"), out: &out}
	if _, err := menu.edit(node, "evaluator.codex_model"); err != io.EOF {
		t.Fatalf("error=%v", err)
	}
	if node.Value != "current-model" {
		t.Fatal("EOF changed model")
	}
}

func TestSequenceDeletionCanChooseItemFromList(t *testing.T) {
	node, err := parseNode("[first, second]")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	menu := terminal{reader: strings.NewReader("d\n2\ny\ns\n"), out: &out}
	command, err := menu.edit(node, "slack.allowed_user_ids")
	if err != nil || command != "save" || len(node.Content) != 1 || node.Content[0].Value != "first" {
		t.Fatalf("delete failed: command=%s err=%v output=%s", command, err, out.String())
	}
}

func TestChoiceModelNumericSelectionAndCancelledConfirmation(t *testing.T) {
	m := newChoiceModel("確認", []choice{{"n", "キャンセル"}, {"y", "実行"}}, 0, "n", nil)
	updated, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = updated.(choiceModel)
	if m.value != "n" {
		t.Fatal("confirmation defaulted to execute")
	}
	m = newChoiceModel("設定", []choice{{"first", "first"}, {"second", "second"}}, 0, "keep", nil)
	updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyExtended, Text: "2"})
	m = updated.(choiceModel)
	updated, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = updated.(choiceModel)
	if m.value != "second" {
		t.Fatal("numeric selection failed")
	}
}

func TestChoiceModelAcceptsMultiDigitInputAndZeroInsideNumber(t *testing.T) {
	var options []choice
	for i := 1; i <= 12; i++ {
		options = append(options, choice{strconv.Itoa(i), "item"})
	}
	for _, keys := range [][]string{{"10"}, {"1", "0"}, {"12"}} {
		m := newChoiceModel("設定", options, 0, "0", map[string]string{"0": "0"})
		for _, key := range keys {
			updated, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyExtended, Text: key})
			m = updated.(choiceModel)
		}
		updated, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
		m = updated.(choiceModel)
		if m.value != strings.Join(keys, "") {
			t.Fatalf("keys=%v selected=%q", keys, m.value)
		}
	}
}

func TestChoiceModelV2IgnoresReleaseAndPasteCommands(t *testing.T) {
	for _, msg := range []tea.Msg{
		tea.KeyReleaseMsg{Code: tea.KeyDown},
		tea.KeyReleaseMsg{Code: tea.KeyEnter},
		tea.PasteMsg{Content: "s"},
		tea.PasteMsg{Content: "2\n"},
	} {
		model := newChoiceModel("選択", []choice{{"one", "1"}, {"two", "2"}}, 0, "keep", map[string]string{"s": "save"})
		next, cmd := model.Update(msg)
		model = next.(choiceModel)
		if model.done || model.selected != 0 || model.digits != "" || cmd != nil {
			t.Fatalf("non-press event changed selection: %T", msg)
		}
	}
}
