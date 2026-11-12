package tui

import (
	"context"
	"errors"
	"fmt"
	"io"

	tea "charm.land/bubbletea/v2"
	"github.com/g-kari/dependabot-alert-notice/internal/control"
)

var errSecretCancelled = errors.New("認証入力を取り消しました")

type secretInputModel struct {
	label           string
	value           []rune
	done, cancelled bool
	invalid         bool
	interrupted     bool
}

func (m secretInputModel) Init() tea.Cmd { return nil }
func (m secretInputModel) View() tea.View {
	return tea.NewView(clean(m.label) + "\n入力は非表示です。Enter: 確定（空欄は保持） / Esc: 取消\n")
}
func (m secretInputModel) appendText(text string) secretInputModel {
	for _, r := range text {
		if r >= 33 && r <= 126 && len(m.value) < 4096 {
			m.value = append(m.value, r)
		} else {
			m.invalid = true
		}
	}
	return m
}
func (m secretInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch key := msg.(type) {
	case tea.PasteMsg:
		m = m.appendText(key.Content)
	case tea.KeyPressMsg:
		switch key.String() {
		case "enter":
			m.done = true
			return m, tea.Quit
		case "esc", "ctrl+c", "ctrl+d":
			m.interrupted = key.String() != "esc"
			clear(m.value)
			m.value = nil
			m.done, m.cancelled = true, true
			return m, tea.Quit
		case "backspace", "delete":
			if len(m.value) > 0 {
				m.value[len(m.value)-1] = 0
				m.value = m.value[:len(m.value)-1]
			}
		default:
			m = m.appendText(key.Text)
		}
	}
	return m, nil
}
func (t *terminal) readSecret(label string) (string, error) {
	if t.secretReader != nil {
		return t.secretReader(label)
	}
	if !t.interactive() {
		return "", errors.New("認証情報は端末の非表示入力が必要です。SSH・tmuxなどの端末でTUIを実行してください")
	}
	ctx := t.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	model, err := tea.NewProgram(secretInputModel{label: label}, tea.WithContext(ctx), tea.WithInput(t.reader), tea.WithOutput(t.out)).Run()
	if err != nil {
		return "", fmt.Errorf("認証入力: %w", err)
	}
	result := model.(secretInputModel)
	defer clear(result.value)
	if !result.done || result.interrupted {
		return "", io.EOF
	}
	if result.cancelled {
		return "", errSecretCancelled
	}
	if result.invalid {
		return "", errors.New("認証入力に空白・制御文字が含まれるか、長すぎます。入力し直してください")
	}
	return string(result.value), nil
}
func (t *terminal) credentialDisplay(label string, state control.CredentialState) {
	source := "環境変数・YAMLを使用"
	if state.Managed {
		source = "TUI保存値を使用"
		if !state.Saved {
			source = "TUIで無効化"
		}
	}
	t.print("%s: 本体に設定済み=%t / TUI保存済み=%t / 環境変数あり=%t（%s）\n", label, state.Active, state.Saved, state.Environment, source)
}
func (t *terminal) credentials(ctx context.Context, c *Client) error {
	for {
		status, err := c.Credentials(ctx)
		if err != nil {
			return fmt.Errorf("認証設定の取得（本体も最新版へ更新・再起動してください）: %w", err)
		}
		t.credentialDisplay("Slack Bot", status.SlackBot)
		t.credentialDisplay("Slack App", status.SlackApp)
		t.credentialDisplay("Discord", status.Discord)
		if status.RestartRequired {
			t.print("保存済みの認証情報を反映するには本体を再起動してください。\n")
		}
		t.print("Slackチャンネル・承認可能ユーザーは「設定」で変更できます。\nGitHub: gh auth status / gh auth login\nAI: 利用するCLIでログインし、隔離用イメージを準備してください。\n")
		command, err := t.menu("認証・通知設定", []choice{
			{"1", "Slackトークンを登録・変更"}, {"2", "Discord Webhookを登録・変更"},
			{"3", "Slackを無効化"}, {"4", "Discordを無効化"},
			{"5", "Slackを環境変数・YAMLに戻す"}, {"6", "Discordを環境変数・YAMLに戻す"}, {"0", "戻る"},
		}, 0, "0", map[string]string{"0": "0", "q": "0"})
		if err != nil {
			return err
		}
		if command == "0" {
			return nil
		}
		values := map[string]*string{}
		switch command {
		case "1", "2":
			keys := []string{"discord_webhook_url"}
			labels := []string{"Discord Webhook URL"}
			if command == "1" {
				keys = []string{"slack_bot_token", "slack_app_token"}
				labels = []string{"Slack Bot Token (xoxb-...)", "Slack App Token (xapp-...)"}
			}
			for i, key := range keys {
				value, err := t.readSecret(labels[i])
				if errors.Is(err, errSecretCancelled) {
					return nil
				}
				if err != nil {
					return err
				}
				if value != "" {
					values[key] = &value
				}
			}
		case "3", "4", "5", "6":
			keys := []string{"discord_webhook_url"}
			if command == "3" || command == "5" {
				keys = []string{"slack_bot_token", "slack_app_token"}
			}
			for _, key := range keys {
				if command == "3" || command == "4" {
					value := ""
					values[key] = &value
				} else {
					values[key] = nil
				}
			}
		default:
			continue
		}
		if len(values) == 0 {
			t.print("変更はありません。\n")
			continue
		}
		yes, err := t.confirm("認証設定を保存しますか（反映には本体の再起動が必要）")
		if err != nil {
			return err
		}
		if !yes {
			continue
		}
		_, err = c.SaveCredentials(ctx, control.CredentialChanges{Revision: status.Revision, Values: values})
		if err != nil {
			t.print("保存できませんでした: %s\n", clean(err.Error()))
			continue
		}
		t.print("認証設定を保存しました。本体を再起動して反映してください。\n")
	}
}
