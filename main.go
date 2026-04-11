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
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
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

	// JobQueue起動
	q := queue.New(100, 2)
	q.Register(queue.JobFetchAlerts, makeFetchHandler(cfg, ghClient, s, q))
	q.Register(queue.JobEvaluateAlert, makeEvaluateHandler(cfg, eval, s, slackClient, discordClient))
	q.Start(ctx)

	// WebUIサーバー起動
	webSrv := web.New(cfg, *configPath, s, m)
	webSrv.SetQueue(q)
	webSrv.SetPollFn(func() {
		enqueueFetchAll(cfg, q)
	})
	go func() {
		if err := webSrv.Start(ctx); err != nil {
			slog.Error("WebUIサーバー停止", "error", err)
		}
	}()

	// ポーリングループ
	if *once {
		// --once: キューに積んでStopを待つ
		enqueueFetchAll(cfg, q)
		// 処理完了を待つ（簡易: 少し待ってStop）
		time.Sleep(500 * time.Millisecond)
		q.Stop()
	} else {
		pollLoop(ctx, cfg, q)
		q.Stop()
	}
}

// enqueueFetchAll は全ターゲットのFetchAlertsジョブをキューに積む
func enqueueFetchAll(cfg *config.Config, q *queue.Queue) {
	for _, target := range cfg.Targets {
		q.Enqueue(queue.Job{
			Type:    queue.JobFetchAlerts,
			Payload: target,
		})
	}
}

// makeFetchHandler はFetchAlertsジョブのハンドラを返す
func makeFetchHandler(cfg *config.Config, ghClient github.Client, s *store.Store, q *queue.Queue) queue.Handler {
	return func(ctx context.Context, job queue.Job) error {
		target, ok := job.Payload.(config.Target)
		if !ok {
			return fmt.Errorf("FetchAlertsペイロード型エラー")
		}

		alerts, err := ghClient.FetchAlerts(ctx, target)
		if err != nil {
			slog.Error("アラート取得失敗", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo), "error", err)
			s.AddLog(model.LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Message:   fmt.Sprintf("アラート取得失敗 (%s/%s): %v", target.Owner, target.Repo, err),
			})
			return fmt.Errorf("FetchAlerts: %w", err)
		}

		newCount := 0
		for _, alert := range alerts {
			if s.HasByKey(alert.Owner, alert.Repo, alert.Number) {
				continue
			}
			record := &model.AlertRecord{
				Alert:      alert,
				State:      model.AlertStatePending,
				EvalStatus: model.EvalStatusPending,
				NotifiedAt: time.Now(),
			}
			s.Save(record)
			s.AddLog(model.LogEntry{
				Timestamp: time.Now(),
				Level:     "info",
				Message:   fmt.Sprintf("新規アラート: %s (%s) in %s/%s", alert.PackageName, alert.Severity, alert.Owner, alert.Repo),
				AlertID:   record.Alert.ID,
			})
			newCount++
		}
		if newCount > 0 {
			slog.Info("新規アラート登録", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo), "count", newCount)
		}

		// AI自動評価が有効な場合のみ pending/failed をEvaluateJobとして積む
		if cfg.Evaluator.AutoEval {
			maxEval := cfg.Evaluator.MaxEvalPerPoll
			if maxEval <= 0 {
				maxEval = 10
			}
			pending := s.ListPendingEvaluation(maxEval)
			sort.Slice(pending, func(i, j int) bool {
				oi := severityOrder[pending[i].Alert.Severity]
				oj := severityOrder[pending[j].Alert.Severity]
				return oi < oj
			})
			for _, record := range pending {
				// critical / high のみAI評価対象
				if record.Alert.Severity != model.SeverityCritical && record.Alert.Severity != model.SeverityHigh {
					continue
				}
				q.Enqueue(queue.Job{
					Type:    queue.JobEvaluateAlert,
					Payload: record.Alert.ID,
				})
			}
		}
		return nil
	}
}

// makeEvaluateHandler はEvaluateAlertジョブのハンドラを返す
func makeEvaluateHandler(cfg *config.Config, eval evaluator.Evaluator, s *store.Store, slackClient *slack.SlackClient, discordClient *discord.Client) queue.Handler {
	return func(ctx context.Context, job queue.Job) error {
		alertID, ok := job.Payload.(int)
		if !ok {
			return fmt.Errorf("EvaluateAlertペイロード型エラー")
		}

		record, err := s.Get(alertID)
		if err != nil {
			return fmt.Errorf("アラート取得失敗 (id=%d): %w", alertID, err)
		}

		// 評価中マークを付ける
		if err := s.UpdateEvalStatus(alertID, model.EvalStatusEvaluating); err != nil {
			return fmt.Errorf("eval_status更新失敗: %w", err)
		}

		alert := record.Alert
		slog.Info("AI評価中", "id", alert.ID, "package", alert.PackageName, "severity", alert.Severity)

		evaluation, err := eval.Evaluate(ctx, alert)
		if err != nil {
			slog.Error("AI評価失敗", "alertID", alert.ID, "error", err)
			s.AddLog(model.LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Message:   fmt.Sprintf("AI評価失敗 (#%d): %v", alert.ID, err),
				AlertID:   alert.ID,
			})
			if updateErr := s.UpdateEvalStatus(alert.ID, model.EvalStatusFailed); updateErr != nil {
				slog.Error("eval_status更新失敗", "alertID", alert.ID, "error", updateErr)
			}
			return fmt.Errorf("AI評価失敗: %w", err)
		}

		record.Evaluation = evaluation
		record.EvalStatus = model.EvalStatusDone
		s.Save(record)

		s.AddLog(model.LogEntry{
			Timestamp: time.Now(),
			Level:     "info",
			Message:   fmt.Sprintf("AI評価完了 (#%d %s/%s): %s → %s", alert.ID, alert.Owner, alert.Repo, alert.PackageName, evaluation.Recommendation),
			AlertID:   alert.ID,
		})

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

		return nil
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

func pollLoop(ctx context.Context, cfg *config.Config, q *queue.Queue) {
	slog.Info("ポーリング開始", "interval", cfg.PollInterval)

	// 初回即実行
	enqueueFetchAll(cfg, q)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("シャットダウン")
			return
		case <-ticker.C:
			enqueueFetchAll(cfg, q)
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
