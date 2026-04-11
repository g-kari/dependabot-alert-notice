package config

import (
	"os"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestLoad_Defaults(t *testing.T) {
	path := writeTemp(t, `
targets:
  - owner: myorg
    repo: myrepo
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.PollInterval != 30*time.Minute {
		t.Errorf("PollInterval = %v, want 30m", cfg.PollInterval)
	}
	if cfg.ClaudePath != "claude" {
		t.Errorf("ClaudePath = %q, want %q", cfg.ClaudePath, "claude")
	}
	if cfg.GhPath != "gh" {
		t.Errorf("GhPath = %q, want %q", cfg.GhPath, "gh")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.Web.Port != 8999 {
		t.Errorf("Web.Port = %d, want 8999", cfg.Web.Port)
	}
	if !cfg.Evaluator.Sandbox.Enabled {
		t.Error("Evaluator.Sandbox.Enabled should be true by default")
	}
}

func TestLoad_Targets(t *testing.T) {
	path := writeTemp(t, `
targets:
  - owner: org1
    repo: repo1
  - owner: org2
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if len(cfg.Targets) != 2 {
		t.Fatalf("len(Targets) = %d, want 2", len(cfg.Targets))
	}
	if cfg.Targets[0].Owner != "org1" || cfg.Targets[0].Repo != "repo1" {
		t.Errorf("Targets[0] = %+v, want {org1 repo1}", cfg.Targets[0])
	}
	if cfg.Targets[1].Owner != "org2" || cfg.Targets[1].Repo != "" {
		t.Errorf("Targets[1] = %+v, want {org2 ''}", cfg.Targets[1])
	}
}

func TestLoad_PollInterval(t *testing.T) {
	path := writeTemp(t, `poll_interval: 5m`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.PollInterval != 5*time.Minute {
		t.Errorf("PollInterval = %v, want 5m", cfg.PollInterval)
	}
}

func TestLoad_SlackFromYAML(t *testing.T) {
	path := writeTemp(t, `
slack:
  channel_id: C12345
  bot_token: xoxb-test
  app_token: xapp-test
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Slack.ChannelID != "C12345" {
		t.Errorf("ChannelID = %q, want C12345", cfg.Slack.ChannelID)
	}
	if cfg.Slack.BotToken != "xoxb-test" {
		t.Errorf("BotToken = %q, want xoxb-test", cfg.Slack.BotToken)
	}
}

func TestLoad_SlackFromEnv(t *testing.T) {
	path := writeTemp(t, `slack:
  channel_id: C12345
`)
	t.Setenv("SLACK_BOT_TOKEN", "xoxb-from-env")
	t.Setenv("SLACK_APP_TOKEN", "xapp-from-env")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Slack.BotToken != "xoxb-from-env" {
		t.Errorf("BotToken = %q, want xoxb-from-env", cfg.Slack.BotToken)
	}
	if cfg.Slack.AppToken != "xapp-from-env" {
		t.Errorf("AppToken = %q, want xapp-from-env", cfg.Slack.AppToken)
	}
}

func TestLoad_EnvOverridesYAML(t *testing.T) {
	path := writeTemp(t, `slack:
  bot_token: xoxb-yaml
  app_token: xapp-yaml
`)
	t.Setenv("SLACK_BOT_TOKEN", "xoxb-env")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// 環境変数がYAMLを上書き
	if cfg.Slack.BotToken != "xoxb-env" {
		t.Errorf("BotToken = %q, want xoxb-env", cfg.Slack.BotToken)
	}
	// SLACK_APP_TOKEN未設定なのでYAMLの値が残る
	if cfg.Slack.AppToken != "xapp-yaml" {
		t.Errorf("AppToken = %q, want xapp-yaml", cfg.Slack.AppToken)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Load() should return error for nonexistent file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, `{invalid yaml: [`)
	_, err := Load(path)
	if err == nil {
		t.Error("Load() should return error for invalid YAML")
	}
}

// TestLoad_AutoEvalDefault はAI自動評価がデフォルトOFFであることを確認
func TestLoad_AutoEvalDefault(t *testing.T) {
	path := writeTemp(t, `targets:
  - owner: org
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Evaluator.AutoEval {
		t.Error("Evaluator.AutoEval should be false by default")
	}
}

// TestLoad_AutoEvalFromYAML はYAMLからAutoEvalが読み込まれることを確認
func TestLoad_AutoEvalFromYAML(t *testing.T) {
	path := writeTemp(t, `evaluator:
  auto_eval: true
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Evaluator.AutoEval {
		t.Error("Evaluator.AutoEval should be true when set in YAML")
	}
}

// TestLoad_NotifyMinSeverityDefault は通知最低重要度がデフォルト"low"であることを確認
func TestLoad_NotifyMinSeverityDefault(t *testing.T) {
	path := writeTemp(t, `targets:
  - owner: org
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.NotifyMinSeverity != "low" {
		t.Errorf("NotifyMinSeverity = %q, want %q", cfg.NotifyMinSeverity, "low")
	}
}

// TestLoad_NotifyMinSeverityFromYAML はYAMLからNotifyMinSeverityが読み込まれることを確認
func TestLoad_NotifyMinSeverityFromYAML(t *testing.T) {
	path := writeTemp(t, `notify_min_severity: high`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.NotifyMinSeverity != "high" {
		t.Errorf("NotifyMinSeverity = %q, want high", cfg.NotifyMinSeverity)
	}
}

// TestShouldNotify はShouldNotifyが重要度フィルタを正しく判定することを確認
func TestShouldNotify(t *testing.T) {
	tests := []struct {
		minSeverity string
		severity    string
		want        bool
	}{
		{"low", "critical", true},
		{"low", "high", true},
		{"low", "medium", true},
		{"low", "low", true},
		{"medium", "critical", true},
		{"medium", "high", true},
		{"medium", "medium", true},
		{"medium", "low", false},
		{"high", "critical", true},
		{"high", "high", true},
		{"high", "medium", false},
		{"high", "low", false},
		{"critical", "critical", true},
		{"critical", "high", false},
		{"critical", "medium", false},
		{"critical", "low", false},
		{"", "high", true}, // 空文字 = low（全通知）
	}
	for _, tt := range tests {
		cfg := &Config{NotifyMinSeverity: tt.minSeverity}
		got := cfg.ShouldNotify(tt.severity)
		if got != tt.want {
			t.Errorf("ShouldNotify(%q, severity=%q) = %v, want %v", tt.minSeverity, tt.severity, got, tt.want)
		}
	}
}

// TestLoad_ActiveMonthsDefault はActiveMonthsのデフォルトが0（フィルタなし）であることを確認
func TestLoad_ActiveMonthsDefault(t *testing.T) {
	path := writeTemp(t, `targets:
  - owner: org
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ActiveMonths != 0 {
		t.Errorf("ActiveMonths = %d, want 0 (disabled by default)", cfg.ActiveMonths)
	}
}

// TestLoad_ActiveMonths はYAMLからActiveMonthsが読み込まれることを確認
func TestLoad_ActiveMonths(t *testing.T) {
	path := writeTemp(t, `active_months: 6`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ActiveMonths != 6 {
		t.Errorf("ActiveMonths = %d, want 6", cfg.ActiveMonths)
	}
}

func TestLoad_SandboxConfig(t *testing.T) {
	path := writeTemp(t, `
evaluator:
  sandbox:
    enabled: false
    image: custom-image:v1
    memory_limit: 256m
    cpu_limit: "1.0"
    timeout: 30s
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Evaluator.Sandbox.Enabled {
		t.Error("Sandbox.Enabled should be false")
	}
	if cfg.Evaluator.Sandbox.Image != "custom-image:v1" {
		t.Errorf("Sandbox.Image = %q, want custom-image:v1", cfg.Evaluator.Sandbox.Image)
	}
	if cfg.Evaluator.Sandbox.Timeout != 30*time.Second {
		t.Errorf("Sandbox.Timeout = %v, want 30s", cfg.Evaluator.Sandbox.Timeout)
	}
}
