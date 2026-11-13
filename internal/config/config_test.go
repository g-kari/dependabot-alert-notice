package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
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
	if !cfg.RSS.Enabled || len(cfg.RSS.Feeds) != 6 {
		t.Fatalf("RSS defaults = %+v, want 6 enabled feeds", cfg.RSS)
	}
	for _, feed := range cfg.RSS.Feeds {
		if !feed.Enabled || !strings.HasPrefix(feed.URL, "https://") {
			t.Errorf("default feed = %+v, want enabled HTTPS feed", feed)
		}
	}
	for _, url := range []string{
		"https://share.0g0.xyz/security-incidents-feed.xml",
		"https://share.0g0.xyz/vulnerabilities-feed.xml",
	} {
		count := 0
		for _, feed := range cfg.RSS.Feeds {
			if feed.URL == url {
				count++
			}
		}
		if count != 1 {
			t.Errorf("default feed %q count = %d, want 1", url, count)
		}
	}
}

func TestLoad_ExplicitEmptyRSSFeedsRemainEmpty(t *testing.T) {
	path := writeTemp(t, "rss:\n  enabled: false\n  feeds: []\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RSS.Enabled || len(cfg.RSS.Feeds) != 0 {
		t.Fatalf("explicit RSS opt-out overwritten: %+v", cfg.RSS)
	}
}

func TestLoad_EvaluatorModels(t *testing.T) {
	path := writeTemp(t, "evaluator:\n  codex_model: gpt-6-sol\n  claude_model: claude-sonnet-test\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Evaluator.CodexModel != "gpt-6-sol" || cfg.Evaluator.ClaudeModel != "claude-sonnet-test" {
		t.Fatalf("evaluator models = %+v", cfg.Evaluator)
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

func TestLoad_RiskProfileAndRSSConfig(t *testing.T) {
	path := writeTemp(t, `
rss:
  enabled: true
  refresh_interval: 30m
  request_timeout: 5s
  max_items_per_feed: 20
  retention_days: 30
  feeds:
    - name: JPCERT
      url: https://example.com/feed.xml
      enabled: true
service_profiles:
  - id: api-prod
    owner: org
    repo: api
    environment: production
    exposure: internet
    authentication: customer
    business_criticality: critical
    max_outage_minutes: 60
    data_classification: restricted
    integrity_impact: high
    privilege_scope: production_write
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.RSS.Enabled || cfg.RSS.RefreshInterval != 30*time.Minute || cfg.RSS.MaxItemsPerFeed != 20 {
		t.Fatalf("RSS = %+v", cfg.RSS)
	}
	if len(cfg.ServiceProfiles) != 1 || cfg.ServiceProfiles[0].BusinessCriticality != model.RiskCritical {
		t.Fatalf("ServiceProfiles = %+v", cfg.ServiceProfiles)
	}
}

func TestLoad_CodexProvider(t *testing.T) {
	path := writeTemp(t, "codex_path: custom-codex\nevaluator:\n  provider: codex\n  sandbox:\n    codex_image: codex-image:v1\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CodexPath != "custom-codex" || cfg.Evaluator.Provider != "codex" || cfg.Evaluator.Sandbox.CodexImage != "codex-image:v1" {
		t.Fatalf("Codex settings = %+v / %+v", cfg.CodexPath, cfg.Evaluator)
	}
}

func TestLoad_RejectsUnknownEvaluatorProvider(t *testing.T) {
	path := writeTemp(t, "evaluator:\n  provider: unknown-provider\n")
	if _, err := Load(path); err == nil {
		t.Fatal("unknown evaluator provider should be rejected")
	}
}

func TestValidate_AllowsHermesProxyProvider(t *testing.T) {
	cfg := Defaults()
	cfg.Evaluator.Provider = "hermes"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Hermes provider should be valid: %v", err)
	}
}

func TestLoad_RejectsNonLoopbackHermesEndpoint(t *testing.T) {
	path := writeTemp(t, "evaluator:\n  provider: hermes\n  hermes_base_url: http://example.com/v1\n")
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback Hermes endpoint error = %v, want loopback restriction", err)
	}
}

func TestValidateHermesBaseURLLoopbackAndMalformedCases(t *testing.T) {
	for _, endpoint := range []string{
		"http://127.0.0.1:8645/v1",
		"http://localhost:8645/v1/",
		"http://[::1]:8645/v1",
	} {
		t.Run("accept/"+endpoint, func(t *testing.T) {
			if err := validateHermesBaseURL(endpoint); err != nil {
				t.Errorf("valid loopback endpoint %q rejected: %v", endpoint, err)
			}
		})
	}
	for _, endpoint := range []string{
		"https://127.0.0.1:8645/v1",
		"http://user:pass@127.0.0.1:8645/v1",
		"http://127.0.0.1:8645/v2",
		"http://127.0.0.1:8645/v1%2F",
		"http://127.0.0.1:8645/%76%31",
		"http://127.0.0.1:8646/v1",
		"http://127.0.0.1:8645/v1?token=x",
		"http://127.0.0.1:8645/v1?",
		"http://127.0.0.1:8645/v1#fragment",
		"http://127.0.0.1:8645/v1#",
		"http://127.0.0.1/v1",
		"http://0.0.0.0:8645/v1",
		"http://localhost.evil:8645/v1",
	} {
		t.Run("reject/"+endpoint, func(t *testing.T) {
			if err := validateHermesBaseURL(endpoint); err == nil {
				t.Errorf("unsafe or malformed endpoint %q accepted", endpoint)
			}
		})
	}
}
