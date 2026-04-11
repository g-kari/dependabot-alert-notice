package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Target struct {
	Owner    string   `yaml:"owner"`
	Repo     string   `yaml:"repo"`
	Excludes []string `yaml:"excludes,omitempty"`
}

// IsExcluded はリポジトリ名が除外リストに含まれるか返す
func (t Target) IsExcluded(repo string) bool {
	for _, ex := range t.Excludes {
		if ex == repo {
			return true
		}
	}
	return false
}

type SlackConfig struct {
	ChannelID string `yaml:"channel_id"`
	BotToken  string `yaml:"bot_token"`
	AppToken  string `yaml:"app_token"`
}

type DiscordConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

type WebConfig struct {
	Port int `yaml:"port"`
}

type SandboxConfig struct {
	Enabled     bool          `yaml:"enabled"`
	Image       string        `yaml:"image"`
	ClaudeHome  string        `yaml:"claude_home"`
	MemoryLimit string        `yaml:"memory_limit"`
	CPULimit    string        `yaml:"cpu_limit"`
	Timeout     time.Duration `yaml:"timeout"`
}

type EvaluatorConfig struct {
	AutoEval       bool          `yaml:"auto_eval"`
	Sandbox        SandboxConfig `yaml:"sandbox"`
	MaxEvalPerPoll int           `yaml:"max_eval_per_poll"`
}

type Config struct {
	PollInterval      time.Duration   `yaml:"poll_interval"`
	Targets           []Target        `yaml:"targets"`
	Slack             SlackConfig     `yaml:"slack"`
	Discord           DiscordConfig   `yaml:"discord"`
	ClaudePath        string          `yaml:"claude_path"`
	GhPath            string          `yaml:"gh_path"`
	LogLevel          string          `yaml:"log_level"`
	DataPath          string          `yaml:"data_path"`
	Web               WebConfig       `yaml:"web"`
	Evaluator         EvaluatorConfig `yaml:"evaluator"`
	NotifyMinSeverity string          `yaml:"notify_min_severity"` // 通知する最低重要度 (low/medium/high/critical)
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
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("設定シリアライズ失敗: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("設定ファイル書き込み失敗: %w", err)
	}
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("設定ファイル読み込み失敗: %w", err)
	}

	cfg := &Config{
		PollInterval:      30 * time.Minute,
		ClaudePath:        "claude",
		GhPath:            "gh",
		LogLevel:          "info",
		DataPath:          "store.db",
		NotifyMinSeverity: "low",
		Web:               WebConfig{Port: 8999},
		Evaluator: EvaluatorConfig{
			MaxEvalPerPoll: 10,
			Sandbox: SandboxConfig{
				Enabled:     true,
				Image:       "dependabot-evaluator:latest",
				MemoryLimit: "512m",
				CPULimit:    "0.5",
				Timeout:     60 * time.Second,
			},
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("設定ファイルパース失敗: %w", err)
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

	return cfg, nil
}
