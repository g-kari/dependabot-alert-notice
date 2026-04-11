package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Target struct {
	Owner string `yaml:"owner"`
	Repo  string `yaml:"repo"`
}

type SlackConfig struct {
	ChannelID string `yaml:"channel_id"`
	BotToken  string `yaml:"bot_token"`
	AppToken  string `yaml:"app_token"`
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
	Sandbox SandboxConfig `yaml:"sandbox"`
}

type Config struct {
	PollInterval time.Duration   `yaml:"poll_interval"`
	Targets      []Target        `yaml:"targets"`
	Slack        SlackConfig     `yaml:"slack"`
	ClaudePath   string          `yaml:"claude_path"`
	GhPath       string          `yaml:"gh_path"`
	LogLevel     string          `yaml:"log_level"`
	Web          WebConfig       `yaml:"web"`
	Evaluator    EvaluatorConfig `yaml:"evaluator"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("設定ファイル読み込み失敗: %w", err)
	}

	cfg := &Config{
		PollInterval: 30 * time.Minute,
		ClaudePath:   "claude",
		GhPath:       "gh",
		LogLevel:     "info",
		Web:          WebConfig{Port: 8080},
		Evaluator: EvaluatorConfig{
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

	return cfg, nil
}
