package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"gopkg.in/yaml.v3"
)

type Target struct {
	Owner    string   `yaml:"owner"`
	Repo     string   `yaml:"repo"`
	Excludes []string `yaml:"excludes,omitempty"`
}

// RSSConfig は脆弱性フィード収集の設定。
type RSSConfig struct {
	Enabled         bool          `yaml:"enabled"`
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	MaxItemsPerFeed int           `yaml:"max_items_per_feed"`
	RetentionDays   int           `yaml:"retention_days"`
	Feeds           []RSSFeed     `yaml:"feeds"`
}

// RSSFeed はRSS/Atom配信元の設定。
type RSSFeed struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	Enabled bool   `yaml:"enabled"`
}

func defaultRSSFeeds() []RSSFeed {
	return []RSSFeed{
		{Name: "JPCERT/CC 脆弱性情報", URL: "https://www.jpcert.or.jp/rss/jpcert-all.rdf", Enabled: true},
		{Name: "CIS Advisories", URL: "https://www.cisecurity.org/feed/advisories", Enabled: true},
		{Name: "BleepingComputer", URL: "https://www.bleepingcomputer.com/feed/", Enabled: true},
		{Name: "The Hacker News", URL: "https://feeds.feedburner.com/TheHackersNews", Enabled: true},
		{Name: "セキュリティインシデント (share.0g0.xyz)", URL: "https://share.0g0.xyz/security-incidents-feed.xml", Enabled: true},
		{Name: "脆弱性情報 (share.0g0.xyz)", URL: "https://share.0g0.xyz/vulnerabilities-feed.xml", Enabled: true},
	}
}

// ThreatConfig は構造化脅威情報の取得設定。
type ThreatConfig struct {
	Enabled  bool          `yaml:"enabled"`
	KEVURL   string        `yaml:"kev_url"`
	EPSSURL  string        `yaml:"epss_url"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

// BusinessCalendar controls deadline calculations. Holidays are YYYY-MM-DD
// strings interpreted in the configured IANA timezone.
type BusinessCalendar struct {
	Timezone string   `yaml:"timezone" json:"timezone"`
	Holidays []string `yaml:"holidays,omitempty" json:"holidays,omitempty"`
}

// BusinessCalendarConfig is kept as a descriptive alias for integrations.
type BusinessCalendarConfig = BusinessCalendar

// IsExcluded はリポジトリ名が除外リストに含まれるか返す
func (t Target) IsExcluded(repo string) bool {
	for _, ex := range t.Excludes {
		if strings.EqualFold(strings.TrimSpace(ex), strings.TrimSpace(repo)) {
			return true
		}
	}
	return false
}

type SlackConfig struct {
	ChannelID      string   `yaml:"channel_id"`
	BotToken       string   `yaml:"bot_token"`
	AppToken       string   `yaml:"app_token"`
	AllowedUserIDs []string `yaml:"allowed_user_ids,omitempty"` // 空=全員許可。Slack User ID (U...) リスト
}

type DiscordConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

type WebConfig struct {
	Host string `yaml:"host,omitempty"`
	Port int    `yaml:"port"`
}

type SandboxConfig struct {
	Runtime          string        `yaml:"runtime"`
	ContainerPath    string        `yaml:"container_path"`
	ContainerCPUs    int           `yaml:"container_cpus"`
	AppleClaudeImage string        `yaml:"apple_claude_image"`
	AppleCodexImage  string        `yaml:"apple_codex_image"`
	Enabled          bool          `yaml:"enabled"`
	Image            string        `yaml:"image"`
	CodexImage       string        `yaml:"codex_image"`
	ClaudeHome       string        `yaml:"claude_home"`
	MemoryLimit      string        `yaml:"memory_limit"`
	CPULimit         string        `yaml:"cpu_limit"`
	Timeout          time.Duration `yaml:"timeout"`
}

type EvaluatorConfig struct {
	Provider       string        `yaml:"provider"`     // claude または codex
	ClaudeModel    string        `yaml:"claude_model"` // 空欄ならClaude CLIの既定値
	CodexModel     string        `yaml:"codex_model"`  // 空欄ならCodex CLIの既定値
	AutoEval       bool          `yaml:"auto_eval"`
	MinSeverity    string        `yaml:"min_severity"` // AI評価対象の最低重要度 (low/medium/high/critical)、デフォルト: high
	Sandbox        SandboxConfig `yaml:"sandbox"`
	MaxEvalPerPoll int           `yaml:"max_eval_per_poll"`
}

// ShouldEvaluate はアラートの重要度がAI評価対象かを返す
func (e *EvaluatorConfig) ShouldEvaluate(severity string) bool {
	min := e.MinSeverity
	if min == "" {
		min = "high" // デフォルトは high 以上
	}
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	minRank := rank[min]
	if minRank == 0 {
		minRank = 3
	}
	alertRank := rank[severity]
	if alertRank == 0 {
		alertRank = 1
	}
	return alertRank >= minRank
}

type Config struct {
	CredentialsRevision  uint64                 `yaml:"-" json:"-"`
	ConfigRevision       uint64                 `yaml:"config_revision,omitempty"`
	PollInterval         time.Duration          `yaml:"poll_interval"`
	Targets              []Target               `yaml:"targets"`
	Slack                SlackConfig            `yaml:"slack"`
	Discord              DiscordConfig          `yaml:"discord"`
	ClaudePath           string                 `yaml:"claude_path"`
	CodexPath            string                 `yaml:"codex_path"`
	GhPath               string                 `yaml:"gh_path"`
	GitHubAuth           ghcommand.Settings     `yaml:"github_auth,omitempty" json:"github_auth,omitempty"`
	LogLevel             string                 `yaml:"log_level"`
	DataPath             string                 `yaml:"data_path"`
	Web                  WebConfig              `yaml:"web"`
	Evaluator            EvaluatorConfig        `yaml:"evaluator"`
	NotifyMinSeverity    string                 `yaml:"notify_min_severity"` // 通知する最低重要度 (low/medium/high/critical)
	FetchMinSeverity     string                 `yaml:"fetch_min_severity"`  // 取得・保存する最低重要度 (low/medium/high/critical)、デフォルト: 空=全件
	ActiveMonths         int                    `yaml:"active_months"`       // 直近Nか月以内に更新されたリポのみ対象 (0=無効)
	DisableApproval      bool                   `yaml:"disable_approval"`    // true=承認/却下ボタンを無効化（閲覧専用モード）
	RSS                  RSSConfig              `yaml:"rss"`
	ServiceProfiles      []model.ServiceProfile `yaml:"service_profiles"`
	Assessments          []model.CVEAssessment  `yaml:"assessments"`
	Threat               ThreatConfig           `yaml:"threat"`
	BusinessCalendar     BusinessCalendar       `yaml:"business_calendar"`
	NotificationInterval time.Duration          `yaml:"notification_interval"`
}

// severityRank は重要度の数値ランク（大きいほど深刻）
var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}

// ShouldNotify はアラートの重要度が通知最低重要度を満たすか返す
func (c *Config) ShouldNotify(severity string) bool {
	minRank := severityRank[c.NotifyMinSeverity]
	if minRank == 0 {
		minRank = 1 // 未設定はlow扱い（全通知）
	}
	alertRank := severityRank[severity]
	if alertRank == 0 {
		alertRank = 1 // 不明は low 扱い
	}
	return alertRank >= minRank
}

func Save(path string, cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("設定がnilです")
	}
	if err := atomicSave(path, cfg); err != nil {
		return fmt.Errorf("設定ファイル書き込み失敗: %w", err)
	}
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("設定ファイル読み込み失敗: %w", err)
	}

	cfg := Defaults()

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("設定ファイルパース失敗: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("設定検証失敗: %w", err)
	}

	// 環境変数でオーバーライド
	if v := os.Getenv("SLACK_BOT_TOKEN"); v != "" {
		cfg.Slack.BotToken = v
	}
	if v := os.Getenv("SLACK_APP_TOKEN"); v != "" {
		cfg.Slack.AppToken = v
	}
	if v := os.Getenv("DISCORD_WEBHOOK_URL"); v != "" {
		cfg.Discord.WebhookURL = v
	}

	credentials, err := ReadCredentials(path)
	if err != nil {
		return nil, fmt.Errorf("認証設定読み込み: %w", err)
	}
	credentials.apply(cfg)
	return cfg, nil
}

// Defaults returns an independent configuration with the application defaults.
func Defaults() *Config {
	return &Config{
		NotificationInterval: time.Hour,
		PollInterval:         30 * time.Minute,
		ClaudePath:           "claude",
		CodexPath:            "codex",
		GhPath:               "gh",
		LogLevel:             "info",
		DataPath:             "store.db",
		NotifyMinSeverity:    "low",
		Web:                  WebConfig{Port: 8999},
		Evaluator: EvaluatorConfig{
			Provider:       "claude",
			MaxEvalPerPoll: 10,
			Sandbox: SandboxConfig{
				Runtime:          "auto",
				ContainerPath:    "container",
				ContainerCPUs:    1,
				AppleClaudeImage: "security-notice-apple-claude:latest",
				AppleCodexImage:  "security-notice-apple-codex:latest",
				Enabled:          true,
				Image:            "dependabot-evaluator:latest",
				CodexImage:       "dependabot-codex-evaluator:latest",
				MemoryLimit:      "512m",
				CPULimit:         "0.5",
				Timeout:          60 * time.Second,
			},
		},
		RSS:    RSSConfig{Enabled: true, RefreshInterval: time.Hour, RequestTimeout: 10 * time.Second, MaxItemsPerFeed: 100, RetentionDays: 90, Feeds: defaultRSSFeeds()},
		Threat: ThreatConfig{Interval: 24 * time.Hour, Timeout: 10 * time.Second},
	}

}
