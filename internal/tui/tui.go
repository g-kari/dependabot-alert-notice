package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	"github.com/g-kari/dependabot-alert-notice/internal/control"
	"gopkg.in/yaml.v3"
)

type terminal struct {
	ctx          context.Context
	reader       io.Reader
	out          io.Writer
	input        *bufio.Reader
	err          error
	secretReader func(string) (string, error)
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) || r == '\u2028' || r == '\u2029' {
			return '�'
		}
		return r
	}, s)
}
func (t *terminal) print(format string, args ...any) {
	if t.err == nil {
		_, t.err = fmt.Fprintf(t.out, format, args...)
	}
}
func (t *terminal) rawLine(label string) (string, error) {
	if t.err != nil {
		return "", t.err
	}
	t.print("%s", label)
	if t.err != nil {
		return "", t.err
	}
	if t.input == nil {
		t.input = bufio.NewReader(t.reader)
	}
	s, err := t.input.ReadString('\n')
	return strings.TrimRight(s, "\r\n"), err
}
func (t *terminal) line(label string) (string, error) {
	s, err := t.rawLine(label)
	return strings.TrimSpace(s), err
}
func (t *terminal) confirm(label string) (bool, error) {
	if t.interactive() {
		value, err := t.menu(label, []choice{{"n", "キャンセル"}, {"y", "実行"}}, 0, "n", map[string]string{"y": "y", "n": "n", "q": "n"})
		return value == "y", err
	}
	s, err := t.line(label + " (y/N): ")
	return strings.EqualFold(s, "y") || strings.EqualFold(s, "yes"), err
}

// Run attaches a terminal menu to a running application without starting a DB or workers.
// Ending this client leaves the application running.
func Run(ctx context.Context, base string, in io.Reader, out io.Writer) error {
	client, err := NewClient(base)
	if err != nil {
		return err
	}
	defer client.http.CloseIdleConnections()
	if _, err = client.Settings(ctx); err != nil {
		return err
	}
	t := terminal{ctx: ctx, reader: in, out: out}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		command, err := t.menu("Security Notice TUI — "+base, []choice{
			{"1", "状態・アラート一覧"}, {"2", "アラート詳細"}, {"3", "ログ"}, {"4", "設定"}, {"5", "手動取得"}, {"6", "AI評価"}, {"7", "認証・通知設定"}, {"0", "終了"},
		}, 0, "0", map[string]string{"0": "0", "q": "0"})
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("TUI入力: %w", err)
		}
		switch command {
		case "0", "q":
			return nil
		case "4":
			err = t.settings(ctx, client)
		case "5":
			var yes bool
			yes, err = t.confirm("全監視対象の取得を実行しますか")
			if err == nil && yes {
				err = client.Action(ctx, "poll")
				if err == nil {
					t.print("取得を受け付けました。\n")
				}
			}
		case "6":
			var raw string
			raw, err = t.line("評価するアラートID: ")
			if err == nil {
				var id int
				id, err = strconv.Atoi(raw)
				if err == nil && id > 0 {
					var yes bool
					yes, err = t.confirm("AI評価を実行しますか")
					if err == nil && yes {
						err = client.Action(ctx, "evaluate/"+strconv.Itoa(id))
						if err == nil {
							t.print("AI評価を受け付けました。\n")
						}
					}
				} else {
					err = errors.New("正のアラートIDを指定してください")
				}
			}
		case "7":
			err = t.credentials(ctx, client)
		case "1", "2", "3":
			var status control.Status
			status, err = client.Status(ctx)
			if err == nil {
				err = t.show(command, status)
			}
		default:
			t.print("メニューの番号を入力してください。\n")
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			t.print("エラー: %s\n", clean(err.Error()))
		}
		if t.err != nil {
			return fmt.Errorf("TUI表示: %w", t.err)
		}
	}
}
func (t *terminal) show(command string, s control.Status) error {
	switch command {
	case "1":
		t.print("\n取得中: %t / アラート最大100件\nID\tリポジトリ\tパッケージ\t重要度\t状態\tAI評価\n", s.Polling)
		for _, r := range s.Alerts {
			t.print("%d\t%s/%s\t%s\t%s\t%s\t%s\n", r.Alert.ID, clean(r.Alert.Owner), clean(r.Alert.Repo), clean(r.Alert.PackageName), clean(string(r.Alert.Severity)), clean(string(r.State)), clean(string(r.EvalStatus)))
		}
	case "2":
		raw, err := t.line("アラートID: ")
		if err != nil {
			return err
		}
		id, err := strconv.Atoi(raw)
		if err != nil {
			return errors.New("アラートIDが不正です")
		}
		for _, r := range s.Alerts {
			if r.Alert.ID == id {
				b, err := json.MarshalIndent(r, "", "  ")
				if err != nil {
					return fmt.Errorf("アラート表示: %w", err)
				}
				t.print("%s\n", string(b))
				return nil
			}
		}
		return errors.New("一覧の最大100件内にアラートがありません")
	case "3":
		for _, entry := range s.Logs {
			t.print("%s [%s] %s\n", entry.Timestamp.Local().Format("2006-01-02 15:04:05"), clean(entry.Level), clean(entry.Message))
		}
	}
	return t.err
}
func parseNode(raw string) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("YAML入力: %w", err)
	}
	if len(doc.Content) != 1 {
		return nil, errors.New("YAMLを入力してください")
	}
	return doc.Content[0], nil
}
func (t *terminal) settings(ctx context.Context, c *Client) error {
	settings, err := c.Settings(ctx)
	if err != nil {
		return err
	}
	node, err := parseNode(settings.YAML)
	if err != nil {
		return err
	}
	for {
		command, err := t.edit(node, "")
		if err != nil {
			return err
		}
		switch command {
		case "cancel", "back":
			return nil
		case "reload":
			yes, err := t.confirm("編集内容を破棄して再読込しますか")
			if err != nil {
				return err
			}
			if !yes {
				continue
			}
			settings, err = c.Settings(ctx)
			if err != nil {
				return err
			}
			node, err = parseNode(settings.YAML)
			if err != nil {
				return err
			}
		case "save":
			yes, err := t.confirm("設定を保存しますか")
			if err != nil {
				return err
			}
			if !yes {
				continue
			}
			b, err := yaml.Marshal(node)
			if err != nil {
				return fmt.Errorf("設定変換: %w", err)
			}
			settings.YAML = string(b)
			saved, err := c.Save(ctx, settings)
			if err != nil {
				t.print("保存できません: %s\n編集内容は保持しています。競合時は r で再読込してください。\n", clean(err.Error()))
				continue
			}
			t.print("設定を保存しました (revision %d)。\n", saved.Revision)
			if saved.RestartRequired {
				t.print("通知接続・監視間隔・待受・保存先などの反映には、本体の再起動が必要です。\n")
			}
			return nil
		}
	}
}

var labels = map[string]string{
	"targets": "監視対象", "poll_interval": "監視間隔", "slack": "Slack通知・承認", "discord": "Discord通知", "evaluator": "AI評価", "rss": "RSSフィード", "threat": "脅威情報", "web": "Web待受", "service_profiles": "サービスプロファイル", "assessments": "CVE評価", "business_calendar": "営業日カレンダー", "gh_path": "GitHub CLIパス", "claude_path": "Claude CLIパス", "codex_path": "Codex CLIパス", "data_path": "DB保存先", "log_level": "ログレベル", "notification_interval": "通知をまとめる間隔", "notify_min_severity": "通知最低重要度", "fetch_min_severity": "取得最低重要度", "active_months": "活動月数フィルタ", "disable_approval": "承認を無効化", "feeds": "配信元", "excludes": "除外リポジトリ", "allowed_user_ids": "承認可能ユーザーID", "channel_id": "通知チャンネルID", "provider": "AIプロバイダー", "auto_eval": "AI自動評価", "sandbox": "AI隔離", "runtime": "隔離方式(auto/apple/docker/podman)", "container_path": "Apple containerパス", "container_cpus": "Apple VM CPU数", "apple_claude_image": "Apple Claudeイメージ", "apple_codex_image": "Apple Codexイメージ", "enabled": "有効", "refresh_interval": "更新間隔", "request_timeout": "取得タイムアウト", "retention_days": "保存期間(日)", "max_items_per_feed": "最大記事数", "claude_model": "Claudeモデル", "codex_model": "Codexモデル", "hermes_model": "Hermesモデル", "hermes_base_url": "Hermes Proxy URL", "min_severity": "AI評価最低重要度",
}

func label(key string) string {
	if v, ok := labels[key]; ok {
		return v + " (" + key + ")"
	}
	return key
}
func summary(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		var values []string
		for i := 0; i < len(n.Content); i += 2 {
			switch n.Content[i].Value {
			case "name", "owner", "repo", "id", "url":
				if n.Content[i+1].Kind == yaml.ScalarNode {
					values = append(values, clean(n.Content[i+1].Value))
				}
			}
		}
		if len(values) > 0 {
			return strings.Join(values, " / ")
		}
		return "{設定項目}"
	case yaml.SequenceNode:
		return fmt.Sprintf("[%d件]", len(n.Content))
	}
	return clean(n.Value)
}
func sequencePath(path string) bool {
	for _, name := range []string{"targets", "rss.feeds", "slack.allowed_user_ids", "service_profiles", "assessments", "business_calendar.holidays"} {
		if path == name {
			return true
		}
	}
	return strings.HasSuffix(path, ".excludes")
}
func (t *terminal) edit(n *yaml.Node, path string) (string, error) {
	if n.Tag == "!!null" && sequencePath(path) {
		n.Kind = yaml.SequenceNode
		n.Tag = "!!seq"
		n.Value = ""
		n.Content = nil
	}
	if n.Kind != yaml.MappingNode && n.Kind != yaml.SequenceNode {
		value, changed, err := t.scalarValue(n, path)
		if err != nil {
			return "", err
		}
		if !changed {
			return "back", nil
		}
		if path == "evaluator.sandbox.enabled" && value != "true" {
			t.print("AI隔離はこの画面から無効にできません。\n")
			return "back", nil
		}
		if n.Tag == "!!str" {
			if value == "-" {
				value = ""
			}
			n.Value = value
			return "back", nil
		}
		next, err := parseNode(value)
		if err != nil {
			t.print("入力エラー: %s\n", clean(err.Error()))
			return "back", nil
		}
		if n.Tag != "!!null" && (next.Kind != yaml.ScalarNode || next.Tag != n.Tag) {
			t.print("入力エラー: 同じ型の値を入力してください (例: true/false、整数)。\n")
			return "back", nil
		}
		*n = *next
		return "back", nil
	}
	selected := 0
	for {
		title := path
		if title == "" {
			title = "設定"
		}
		var options []choice
		count := len(n.Content)
		if n.Kind == yaml.MappingNode {
			count /= 2
		}
		for i := 0; i < count; i++ {
			if n.Kind == yaml.MappingNode {
				options = append(options, choice{strconv.Itoa(i + 1), label(n.Content[2*i].Value) + ": " + summary(n.Content[2*i+1])})
			} else {
				options = append(options, choice{strconv.Itoa(i + 1), summary(n.Content[i])})
			}
		}
		options = append(options, choice{"a", "追加 (a)"}, choice{"s", "保存 (s)"}, choice{"r", "再読込 (r)"}, choice{"q", "編集を破棄 (q)"}, choice{"0", "戻る (0)"})
		if n.Kind == yaml.SequenceNode && count > 0 {
			options = append(options, choice{"d", "削除する項目を選択 (d)"})
		}
		command, err := t.menu(title, options, selected, "0", map[string]string{"a": "a", "s": "s", "r": "r", "q": "q", "0": "0"})
		if err != nil {
			return "", err
		}
		if command == "d" && n.Kind == yaml.SequenceNode && count > 0 {
			item, err := t.menu(title+" — 削除する項目", options[:count], selected, "0", map[string]string{"0": "0", "q": "0"})
			if err != nil {
				return "", err
			}
			if item == "0" {
				continue
			}
			command = "d " + item
		}
		switch command {
		case "0":
			return "back", nil
		case "s":
			return "save", nil
		case "q":
			return "cancel", nil
		case "r":
			return "reload", nil
		case "a":
			var key string
			if n.Kind == yaml.MappingNode {
				key, err = t.line("追加する設定キー: ")
				if err != nil {
					return "", err
				}
				exists := false
				for i := 0; i < len(n.Content); i += 2 {
					if n.Content[i].Value == key {
						exists = true
					}
				}
				if exists || key == "" {
					t.print("既存のキーを編集してください。\n")
					continue
				}
				if key == "bot_token" || key == "app_token" || key == "webhook_url" || key == "config_revision" {
					t.print("この項目は変更できません。\n")
					continue
				}
			}
			t.print("追加する値をYAMLで入力し、単独の . で終了します（例: owner: acme と repo: api）。\n")
			var lines []string
			for {
				line, err := t.rawLine("")
				if err != nil {
					return "", err
				}
				if strings.TrimSpace(line) == "." {
					break
				}
				lines = append(lines, line)
			}
			next, err := parseNode(strings.Join(lines, "\n"))
			if err != nil {
				t.print("入力エラー: %s\n", clean(err.Error()))
				continue
			}
			if n.Kind == yaml.MappingNode {
				n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, next)
			} else {
				n.Content = append(n.Content, next)
			}
		default:
			if strings.HasPrefix(command, "d ") && n.Kind == yaml.SequenceNode {
				i, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(command, "d ")))
				if err != nil || i < 1 || i > count {
					t.print("番号が不正です。\n")
					continue
				}
				yes, err := t.confirm("選択した項目を削除しますか")
				if err != nil {
					return "", err
				}
				if yes {
					n.Content = append(n.Content[:i-1], n.Content[i:]...)
				}
				continue
			}
			i, err := strconv.Atoi(command)
			if err != nil || i < 1 || i > count {
				t.print("番号が不正です。\n")
				continue
			}
			selected = i - 1
			child := n.Content[i-1]
			childPath := fmt.Sprintf("%s.%d", path, i)
			if n.Kind == yaml.MappingNode {
				key := n.Content[2*(i-1)].Value
				child = n.Content[2*(i-1)+1]
				childPath = key
				if path != "" {
					childPath = path + "." + key
				}
			}
			action, err := t.edit(child, childPath)
			if err != nil {
				return "", err
			}
			if action != "back" {
				return action, nil
			}
		}
	}
}
