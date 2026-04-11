package slack

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	slackgo "github.com/slack-go/slack"
)

// buildBlocks はアラートレコードからSlackブロックを生成する（eval nilセーフ）
func buildBlocks(record *model.AlertRecord) []slackgo.Block {
	alert := record.Alert
	eval := record.Evaluation

	severityEmoji := severityToEmoji(alert.Severity)
	headerText := fmt.Sprintf("%s %s in %s/%s", severityEmoji, alert.PackageName, alert.Owner, alert.Repo)

	blocks := []slackgo.Block{
		slackgo.NewHeaderBlock(
			slackgo.NewTextBlockObject(slackgo.PlainTextType, headerText, true, false),
		),
	}

	if alert.Summary != "" {
		blocks = append(blocks,
			slackgo.NewSectionBlock(
				slackgo.NewTextBlockObject(slackgo.MarkdownType,
					fmt.Sprintf("_%s_", alert.Summary),
					false, false,
				), nil, nil,
			),
		)
	}

	blocks = append(blocks,
		slackgo.NewSectionBlock(
			slackgo.NewTextBlockObject(slackgo.MarkdownType,
				fmt.Sprintf("*Severity:* %s | *CVE:* %s | *CVSS:* %.1f\n*Fixed in:* %s",
					alert.Severity, nonEmpty(alert.CVEID, "N/A"), alert.CVSSScore, nonEmpty(alert.FixedIn, "N/A")),
				false, false,
			), nil, nil,
		),
		slackgo.NewDividerBlock(),
	)

	if eval != nil {
		recEmoji := recommendationToEmoji(eval.Recommendation)
		evalText := fmt.Sprintf("%s *AI評価:* %s", recEmoji, eval.Recommendation)
		if eval.Impact != "" {
			evalText += fmt.Sprintf("\n\n*🔓 侵害される内容:*\n%s", eval.Impact)
		}
		if eval.Reasoning != "" {
			evalText += fmt.Sprintf("\n\n*⚠️ 侵害される使い方:*\n%s", eval.Reasoning)
		}
		blocks = append(blocks,
			slackgo.NewSectionBlock(
				slackgo.NewTextBlockObject(slackgo.MarkdownType, evalText, false, false),
				nil, nil,
			),
		)
	} else {
		blocks = append(blocks,
			slackgo.NewSectionBlock(
				slackgo.NewTextBlockObject(slackgo.MarkdownType, "⏳ AI評価待ち...", false, false),
				nil, nil,
			),
		)
	}

	blocks = append(blocks,
		slackgo.NewActionBlock(
			fmt.Sprintf("alert_actions_%d", alert.ID),
			slackgo.NewButtonBlockElement(
				"approve",
				fmt.Sprintf("%d", alert.ID),
				slackgo.NewTextBlockObject(slackgo.PlainTextType, "✅ マージ承認", true, false),
			).WithStyle(slackgo.StylePrimary),
			slackgo.NewButtonBlockElement(
				"reject",
				fmt.Sprintf("%d", alert.ID),
				slackgo.NewTextBlockObject(slackgo.PlainTextType, "❌ 却下", true, false),
			).WithStyle(slackgo.StyleDanger),
			slackgo.NewButtonBlockElement(
				"open_github",
				alert.HTMLURL,
				slackgo.NewTextBlockObject(slackgo.PlainTextType, "🔗 GitHubで開く", true, false),
			),
		),
	)

	return blocks
}

// Notify はアラートをSlackに通知し、メッセージのTimestampを返す（eval nil可）
func (c *SlackClient) Notify(record *model.AlertRecord) (string, error) {
	if err := c.limiter.Wait(context.Background()); err != nil {
		return "", fmt.Errorf("slack通知レート制限待機失敗: %w", err)
	}

	alert := record.Alert
	blocks := buildBlocks(record)
	headerText := fmt.Sprintf("%s %s in %s/%s",
		severityToEmoji(alert.Severity), alert.PackageName, alert.Owner, alert.Repo)

	_, ts, err := c.api.PostMessage(
		c.channelID,
		slackgo.MsgOptionBlocks(blocks...),
		slackgo.MsgOptionText(headerText, false),
	)
	if err != nil {
		// 429 Too Many Requests: Retry-After ヘッダを読んでリミッターに伝える
		if rateLimitErr, ok := err.(*slackgo.RateLimitedError); ok {
			c.limiter.SetRetryAfter(rateLimitErr.RetryAfter)
			slog.Warn("Slack通知レート制限", "retryAfter", rateLimitErr.RetryAfter)
		}
		slog.Error("Slack通知送信失敗", "error", err)
		return "", fmt.Errorf("slack通知送信失敗: %w", err)
	}

	slog.Info("Slack通知送信完了", "alertID", alert.ID, "package", alert.PackageName)
	return ts, nil
}

// buildResolvedBlocks は対応済みアラートのブロックを生成する（ボタンなし、Done表示）
func buildResolvedBlocks(record *model.AlertRecord) []slackgo.Block {
	alert := record.Alert
	severityEmoji := severityToEmoji(alert.Severity)
	headerText := fmt.Sprintf("✅ %s %s in %s/%s", severityEmoji, alert.PackageName, alert.Owner, alert.Repo)

	blocks := []slackgo.Block{
		slackgo.NewHeaderBlock(
			slackgo.NewTextBlockObject(slackgo.PlainTextType, headerText, true, false),
		),
		slackgo.NewSectionBlock(
			slackgo.NewTextBlockObject(slackgo.MarkdownType,
				"✅ *対応済み* — GitHub側で解決済みのため一覧から削除されました",
				false, false,
			), nil, nil,
		),
	}

	if alert.HTMLURL != "" {
		blocks = append(blocks,
			slackgo.NewSectionBlock(
				slackgo.NewTextBlockObject(slackgo.MarkdownType,
					fmt.Sprintf("<%s|GitHubで確認>", alert.HTMLURL),
					false, false,
				), nil, nil,
			),
		)
	}

	return blocks
}

// NotifyResolved は対応済みアラートをSlackに通知する
// 1. 元メッセージを「✅ 対応済み」に編集（ボタン除去）
// 2. スレッドに解決メッセージを投稿
func (c *SlackClient) NotifyResolved(record *model.AlertRecord) error {
	if record.SlackMessageTS == "" {
		return nil
	}

	alert := record.Alert

	// 1. 元メッセージを対応済みブロックに編集
	if err := c.limiter.Wait(context.Background()); err != nil {
		return fmt.Errorf("slack resolved更新レート制限待機失敗: %w", err)
	}

	blocks := buildResolvedBlocks(record)
	headerText := fmt.Sprintf("✅ %s in %s/%s — 対応済み", alert.PackageName, alert.Owner, alert.Repo)

	_, _, _, err := c.api.UpdateMessage(
		c.channelID,
		record.SlackMessageTS,
		slackgo.MsgOptionBlocks(blocks...),
		slackgo.MsgOptionText(headerText, false),
	)
	if err != nil {
		if rateLimitErr, ok := err.(*slackgo.RateLimitedError); ok {
			c.limiter.SetRetryAfter(rateLimitErr.RetryAfter)
		}
		slog.Error("Slack対応済みメッセージ編集失敗", "alertID", alert.ID, "error", err)
		return fmt.Errorf("slack対応済みメッセージ編集失敗: %w", err)
	}

	// 2. スレッドに解決メッセージを投稿
	if err := c.limiter.Wait(context.Background()); err != nil {
		return fmt.Errorf("slack resolvedスレッド投稿レート制限待機失敗: %w", err)
	}

	threadText := fmt.Sprintf("✅ *対応済み*\nGitHub側で解決済みのため一覧から削除されました。\n<%s|GitHubで確認>", alert.HTMLURL)
	_, _, err = c.api.PostMessage(
		c.channelID,
		slackgo.MsgOptionText(threadText, false),
		slackgo.MsgOptionTS(record.SlackMessageTS),
	)
	if err != nil {
		if rateLimitErr, ok := err.(*slackgo.RateLimitedError); ok {
			c.limiter.SetRetryAfter(rateLimitErr.RetryAfter)
		}
		slog.Error("Slack対応済みスレッド投稿失敗", "alertID", alert.ID, "error", err)
		return fmt.Errorf("slack対応済みスレッド投稿失敗: %w", err)
	}

	slog.Info("Slack対応済み通知完了", "alertID", alert.ID, "ts", record.SlackMessageTS)
	return nil
}

// UpdateEvalMessage はAI評価完了後にSlackのメッセージを編集してeval結果を追加する
func (c *SlackClient) UpdateEvalMessage(record *model.AlertRecord) error {
	if record.SlackMessageTS == "" {
		return nil
	}

	if err := c.limiter.Wait(context.Background()); err != nil {
		return fmt.Errorf("slack更新レート制限待機失敗: %w", err)
	}

	alert := record.Alert
	blocks := buildBlocks(record)
	headerText := fmt.Sprintf("%s %s in %s/%s",
		severityToEmoji(alert.Severity), alert.PackageName, alert.Owner, alert.Repo)

	_, _, _, err := c.api.UpdateMessage(
		c.channelID,
		record.SlackMessageTS,
		slackgo.MsgOptionBlocks(blocks...),
		slackgo.MsgOptionText(headerText, false),
	)
	if err != nil {
		if rateLimitErr, ok := err.(*slackgo.RateLimitedError); ok {
			c.limiter.SetRetryAfter(rateLimitErr.RetryAfter)
			slog.Warn("Slack更新レート制限", "retryAfter", rateLimitErr.RetryAfter)
		}
		return fmt.Errorf("slackメッセージ更新失敗: %w", err)
	}
	slog.Info("SlackメッセージにAI評価を追記", "alertID", alert.ID, "ts", record.SlackMessageTS)
	return nil
}

func (c *SlackClient) UpdateMessage(channelID, timestamp, text string) error {
	_, _, _, err := c.api.UpdateMessage(
		channelID,
		timestamp,
		slackgo.MsgOptionText(text, false),
	)
	return err
}

func severityToEmoji(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "🔴"
	case model.SeverityHigh:
		return "🟠"
	case model.SeverityMedium:
		return "🟡"
	case model.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func recommendationToEmoji(rec string) string {
	switch rec {
	case "approve":
		return "✅"
	case "reject":
		return "❌"
	case "manual-review":
		return "👀"
	default:
		return "❓"
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
