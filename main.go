package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
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

	s := store.New()
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

	// ポーリングループ
	if *once {
		pollOnce(ctx, cfg, ghClient, eval, s, slackClient)
	} else {
		pollLoop(ctx, cfg, ghClient, eval, s, slackClient)
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

func pollLoop(ctx context.Context, cfg *config.Config, ghClient github.Client, eval evaluator.Evaluator, s *store.Store, slackClient *slack.SlackClient) {
	slog.Info("ポーリング開始", "interval", cfg.PollInterval)

	// 初回即実行
	pollOnce(ctx, cfg, ghClient, eval, s, slackClient)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("シャットダウン")
			return
		case <-ticker.C:
			pollOnce(ctx, cfg, ghClient, eval, s, slackClient)
		}
	}
}

func pollOnce(ctx context.Context, cfg *config.Config, ghClient github.Client, eval evaluator.Evaluator, s *store.Store, slackClient *slack.SlackClient) {
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

		for _, alert := range alerts {
			if s.Has(alert.ID) {
				continue
			}

			slog.Info("新規アラート検出", "id", alert.ID, "package", alert.PackageName, "severity", alert.Severity)
			s.AddLog(model.LogEntry{
				Timestamp: time.Now(),
				Level:     "info",
				Message:   fmt.Sprintf("新規アラート: %s (%s) in %s/%s", alert.PackageName, alert.Severity, alert.Owner, alert.Repo),
				AlertID:   alert.ID,
			})

			// AI評価
			evaluation, err := eval.Evaluate(ctx, alert)
			if err != nil {
				slog.Error("AI評価失敗", "alertID", alert.ID, "error", err)
				s.AddLog(model.LogEntry{
					Timestamp: time.Now(),
					Level:     "error",
					Message:   fmt.Sprintf("AI評価失敗 (#%d): %v", alert.ID, err),
					AlertID:   alert.ID,
				})
				// 評価失敗でもレコードは保存
				evaluation = nil
			}

			record := &model.AlertRecord{
				Alert:      alert,
				Evaluation: evaluation,
				State:      model.AlertStatePending,
				NotifiedAt: time.Now(),
			}
			s.Save(record)

			// Slack通知
			if slackClient != nil && evaluation != nil {
				if err := slackClient.Notify(record); err != nil {
					slog.Error("Slack通知失敗", "alertID", alert.ID, "error", err)
				}
			}
		}
	}
}
