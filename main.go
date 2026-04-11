package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/discord"
	"github.com/g-kari/dependabot-alert-notice/internal/evaluator"
	"github.com/g-kari/dependabot-alert-notice/internal/github"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/slack"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/web"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "設定ファイルパス")
	once := flag.Bool("once", false, "1回だけ実行して終了")
	logLevel := flag.String("log-level", "", "ログレベル (debug, info, warn, error)")
	showVersion := flag.Bool("version", false, "バージョン表示")
	flag.Parse()

	if *showVersion {
		fmt.Printf("dependabot-alert-notice %s\n", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("設定読み込み失敗", "error", err)
		os.Exit(1)
	}

	// ログレベル設定
	level := cfg.LogLevel
	if *logLevel != "" {
		level = *logLevel
	}
	setupLogger(level)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dataPath := cfg.DataPath
	s, err := store.NewWithPath(dataPath)
	if err != nil {
		slog.Error("ストア初期化失敗", "path", dataPath, "error", err)
		os.Exit(1)
	}
	ghClient := github.New(cfg)
	eval := evaluator.New(cfg)
	m := merger.New(cfg, s, ghClient)

	// WebUIサーバー起動
	webSrv := web.New(cfg, *configPath, s, m)
	go func() {
		if err := webSrv.Start(ctx); err != nil {
			slog.Error("WebUIサーバー停止", "error", err)
		}
	}()

	// Slack Socket Mode起動（トークンが設定されている場合のみ）
	var slackClient *slack.SlackClient
	if cfg.Slack.BotToken != "" && cfg.Slack.AppToken != "" {
		slackClient = slack.New(cfg, s, m)
		go slackClient.Start(ctx)
	} else {
		slog.Warn("Slackトークン未設定のためSocket Mode無効")
	}

	// Discord Webhookクライアント初期化（webhook_urlが設定されている場合のみ）
	var discordClient *discord.Client
	if cfg.Discord.WebhookURL != "" {
		discordClient = discord.New(cfg.Discord.WebhookURL)
		slog.Info("Discord通知有効")
	} else {
		slog.Warn("Discord Webhook URL未設定のためDiscord通知無効")
	}

	// ポーリングループ
	if *once {
		pollOnce(ctx, cfg, ghClient, eval, s, slackClient, discordClient)
	} else {
		pollLoop(ctx, cfg, ghClient, eval, s, slackClient, discordClient)
	}
}

func setupLogger(level string) {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

func pollLoop(ctx context.Context, cfg *config.Config, ghClient github.Client, eval evaluator.Evaluator, s *store.Store, slackClient *slack.SlackClient, discordClient *discord.Client) {
	slog.Info("ポーリング開始", "interval", cfg.PollInterval)

	// 初回即実行
	pollOnce(ctx, cfg, ghClient, eval, s, slackClient, discordClient)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("シャットダウン")
			return
		case <-ticker.C:
			pollOnce(ctx, cfg, ghClient, eval, s, slackClient, discordClient)
		}
	}
}

// severityOrder は重要度の優先順位（数値が小さいほど高優先）
var severityOrder = map[model.Severity]int{
	model.SeverityCritical: 0,
	model.SeverityHigh:     1,
	model.SeverityMedium:   2,
	model.SeverityLow:      3,
}

func pollOnce(ctx context.Context, cfg *config.Config, ghClient github.Client, eval evaluator.Evaluator, s *store.Store, slackClient *slack.SlackClient, discordClient *discord.Client) {
	maxEval := cfg.Evaluator.MaxEvalPerPoll
	if maxEval <= 0 {
		maxEval = 10
	}
	evalCount := 0

	for _, target := range cfg.Targets {
		alerts, err := ghClient.FetchAlerts(ctx, target)
		if err != nil {
			slog.Error("アラート取得失敗", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo), "error", err)
			s.AddLog(model.LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Message:   fmt.Sprintf("アラート取得失敗 (%s/%s): %v", target.Owner, target.Repo, err),
			})
			continue
		}

		// 未処理アラートだけ抽出
		var newAlerts []model.Alert
		for _, alert := range alerts {
			if !s.Has(alert.ID) {
				newAlerts = append(newAlerts, alert)
			}
		}

		if len(newAlerts) == 0 {
			continue
		}

		// 重要度順にソート（CRITICAL→HIGH→MEDIUM→LOW）
		sort.Slice(newAlerts, func(i, j int) bool {
			oi := severityOrder[newAlerts[i].Severity]
			oj := severityOrder[newAlerts[j].Severity]
			return oi < oj
		})

		slog.Info("新規アラート", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo),
			"count", len(newAlerts), "max_eval_per_poll", maxEval, "eval_done_so_far", evalCount)

		for _, alert := range newAlerts {
			slog.Info("新規アラート検出", "id", alert.ID, "package", alert.PackageName, "severity", alert.Severity)
			s.AddLog(model.LogEntry{
				Timestamp: time.Now(),
				Level:     "info",
				Message:   fmt.Sprintf("新規アラート: %s (%s) in %s/%s", alert.PackageName, alert.Severity, alert.Owner, alert.Repo),
				AlertID:   alert.ID,
			})

			// AI評価（上限に達したらスキップ → 次回ポーリングで再試行）
			if evalCount >= maxEval {
				slog.Info("AI評価スキップ（上限到達）", "alertID", alert.ID, "max", maxEval)
				continue
			}

			evaluation, err := eval.Evaluate(ctx, alert)
			if err != nil {
				slog.Error("AI評価失敗", "alertID", alert.ID, "error", err)
				s.AddLog(model.LogEntry{
					Timestamp: time.Now(),
					Level:     "error",
					Message:   fmt.Sprintf("AI評価失敗 (#%d): %v", alert.ID, err),
					AlertID:   alert.ID,
				})
				// 評価失敗でもレコード保存（次回ポーリングでスキップされてしまうのを避けるため保存しない）
				continue
			}
			evalCount++

			record := &model.AlertRecord{
				Alert:      alert,
				Evaluation: evaluation,
				State:      model.AlertStatePending,
				NotifiedAt: time.Now(),
			}
			s.Save(record)

			// Slack通知
			if slackClient != nil {
				if err := slackClient.Notify(record); err != nil {
					slog.Error("Slack通知失敗", "alertID", alert.ID, "error", err)
				}
			}

			// Discord通知
			if discordClient != nil {
				if err := discordClient.Notify(record); err != nil {
					slog.Error("Discord通知失敗", "alertID", alert.ID, "error", err)
				}
			}
		}
	}
}
