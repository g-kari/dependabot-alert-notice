package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/mattn/go-isatty"
	"gopkg.in/yaml.v3"
)

type choice struct{ value, label string }
type choiceModel struct {
	title                   string
	options                 []choice
	selected, width, height int
	cancel, value, digits   string
	shortcuts               map[string]string
	done, interrupted       bool
}

func newChoiceModel(title string, options []choice, selected int, cancel string, shortcuts map[string]string) choiceModel {
	if selected < 0 || selected >= len(options) {
		selected = 0
	}
	return choiceModel{title: title, options: options, selected: selected, cancel: cancel, shortcuts: shortcuts, width: 80, height: 24}
}
func (m choiceModel) Init() tea.Cmd { return nil }
func (m choiceModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch key := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = key.Width, key.Height
	case tea.KeyPressMsg:
		switch key.String() {
		case "ctrl+c", "ctrl+d":
			m.done, m.interrupted = true, true
			return m, tea.Quit
		case "esc":
			m.done, m.value = true, m.cancel
			return m, tea.Quit
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
			m.digits = ""
		case "down", "j":
			if m.selected+1 < len(m.options) {
				m.selected++
			}
			m.digits = ""
		case "home":
			m.selected = 0
			m.digits = ""
		case "end":
			m.selected = len(m.options) - 1
			m.digits = ""
		case "backspace":
			if len(m.digits) > 0 {
				m.digits = m.digits[:len(m.digits)-1]
			}
		case "enter":
			if m.digits != "" {
				n, err := strconv.Atoi(m.digits)
				if err != nil || n < 1 || n > len(m.options) {
					m.digits = ""
					return m, nil
				}
				m.selected = n - 1
			}
			if len(m.options) > 0 {
				m.done, m.value = true, m.options[m.selected].value
				return m, tea.Quit
			}
		default:
			text := key.String()
			if value, ok := m.shortcuts[text]; ok && (text != "0" || m.digits == "") {
				m.done, m.value = true, value
				return m, tea.Quit
			}
			if key.Text != "" {
				numeric := len(key.Text) > 0
				for _, r := range key.Text {
					if r < '0' || r > '9' {
						numeric = false
					}
				}
				if numeric && len(m.digits)+len(text) <= 6 {
					m.digits += text
				}
			}
		}
	}
	return m, nil
}
func (m choiceModel) View() tea.View {
	if m.done {
		return tea.NewView("")
	}
	var b strings.Builder
	width := max(12, m.width-2)
	fmt.Fprintf(&b, "\n%s\n\n", ansi.Truncate(clean(m.title), width, "…"))
	rows := max(1, min(12, m.height-8))
	start := max(0, m.selected-rows+1)
	end := min(len(m.options), start+rows)
	for i := start; i < end; i++ {
		marker := " "
		if i == m.selected {
			marker = ">"
		}
		fmt.Fprintf(&b, "%s\n", ansi.Truncate(fmt.Sprintf("%s %d %s", marker, i+1, clean(m.options[i].label)), width, "…"))
	}
	fmt.Fprintf(&b, "\n%d–%d / %d件\n", start+1, end, len(m.options))
	b.WriteString(ansi.Truncate("↑/↓ または j/k: 移動  Enter: 選択  Esc: 戻る", width, "…"))
	fmt.Fprintf(&b, "\n番号+Enter: %s\n", m.digits)
	return tea.NewView(b.String())
}
func (t *terminal) interactive() bool {
	in, ok := t.reader.(*os.File)
	if !ok {
		return false
	}
	out, ok := t.out.(*os.File)
	if !ok {
		return false
	}
	return os.Getenv("TERM") != "dumb" && (isatty.IsTerminal(in.Fd()) || isatty.IsCygwinTerminal(in.Fd())) && (isatty.IsTerminal(out.Fd()) || isatty.IsCygwinTerminal(out.Fd()))
}
func (t *terminal) menu(title string, options []choice, selected int, cancel string, shortcuts map[string]string) (string, error) {
	if t.interactive() {
		ctx := t.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		model, err := tea.NewProgram(newChoiceModel(title, options, selected, cancel, shortcuts), tea.WithInput(t.reader), tea.WithOutput(t.out), tea.WithContext(ctx)).Run()
		if err != nil {
			return "", fmt.Errorf("選択画面: %w", err)
		}
		chosen := model.(choiceModel)
		if chosen.interrupted || !chosen.done {
			return "", io.EOF
		}
		return chosen.value, nil
	}
	t.print("\n[%s]\n", clean(title))
	for i, option := range options {
		t.print("%d %s\n", i+1, clean(option.label))
	}
	command, err := t.line("> ")
	if err != nil {
		return "", err
	}
	if command == "" {
		return cancel, nil
	}
	if value, ok := shortcuts[command]; ok {
		return value, nil
	}
	if n, err := strconv.Atoi(command); err == nil && n >= 1 && n <= len(options) {
		return options[n-1].value, nil
	}
	return command, nil
}

const choiceKeep = "\x00keep"
const choiceCustom = "\x00custom"

func scalarChoices(n *yaml.Node, path string) ([]choice, bool) {
	if n.Tag == "!!bool" {
		return []choice{{"false", "無効 (false)"}, {"true", "有効 (true)"}}, false
	}
	switch path {
	case "notification_interval":
		return []choice{{"1h0m0s", "1時間ごと"}, {"30m0s", "30分ごと"}, {"5m0s", "5分ごと"}, {"0s", "都度通知"}}, true
	case "evaluator.provider":
		return []choice{{"claude", "Claude CLI"}, {"codex", "Codex CLI"}, {"hermes", "Hermes Proxy"}}, false
	case "evaluator.sandbox.runtime":
		return []choice{{"auto", "自動 (auto)"}, {"apple", "Apple container"}, {"docker", "Docker"}, {"podman", "Podman (rootless)"}}, false
	case "log_level":
		return []choice{{"debug", "Debug"}, {"info", "Info"}, {"warn", "Warn"}, {"error", "Error"}}, false
	case "notify_min_severity", "fetch_min_severity", "evaluator.min_severity":
		return []choice{{"", "指定なし"}, {"low", "Low"}, {"medium", "Medium"}, {"high", "High"}, {"critical", "Critical"}}, false
	case "evaluator.codex_model":
		return []choice{{"", "CLIの既定モデル"}, {"gpt-6-luna", "GPT-6 Luna (gpt-6-luna)"}, {"gpt-6.1-sol", "GPT-6.1 Sol (gpt-6.1-sol)"}, {"gpt-6-astra", "GPT-6 Astra (gpt-6-astra)"}}, true
	case "evaluator.claude_model":
		return []choice{{"", "CLIの既定モデル"}, {"sonnet", "Sonnet (sonnet)"}, {"opus", "Opus (opus)"}, {"haiku", "Haiku (haiku)"}}, true
	case "evaluator.hermes_model":
		return []choice{{"Hermes-4-70B", "Hermes-4-70B"}, {"Hermes-4.3-36B", "Hermes-4.3-36B"}, {"Hermes-4-405B", "Hermes-4-405B"}}, true
	}
	return nil, false
}
func (t *terminal) scalarValue(n *yaml.Node, path string) (string, bool, error) {
	options, custom := scalarChoices(n, path)
	if len(options) == 0 {
		value, err := t.line("新しい値 (Enterで保持、文字列は - で空): ")
		return value, value != "", err
	}
	selected := 0
	found := false
	for i, option := range options {
		if option.value == n.Value {
			selected, found = i, true
		}
	}
	if custom {
		currentLabel, customLabel := "現在のモデル: ", "別モデルを直接入力 (m)"
		if path == "notification_interval" {
			currentLabel, customLabel = "現在の間隔: ", "時間を直接入力 (m)"
		}
		if !found {
			selected = len(options)
			options = append(options, choice{n.Value, currentLabel + n.Value})
		}
		options = append(options, choice{choiceCustom, customLabel})
	}
	shortcuts := map[string]string{"0": choiceKeep, "q": choiceKeep}
	if custom {
		shortcuts["m"] = choiceCustom
	}
	value, err := t.menu(path+" — 現在: "+summary(n), options, selected, choiceKeep, shortcuts)
	if err != nil {
		return "", false, err
	}
	if value == choiceKeep {
		return "", false, nil
	}
	if value == choiceCustom {
		prompt := "モデルID (Enterで保持、- でCLIの既定モデル): "
		if path == "notification_interval" {
			prompt = "間隔（例: 1h、30m、0s。Enterで保持）: "
		}
		value, err = t.line(prompt)
		if err != nil {
			return "", false, err
		}
		if value == "" {
			return "", false, nil
		}
	}
	if value == "-" && custom && path != "notification_interval" {
		value = ""
	}
	return value, true, nil
}
