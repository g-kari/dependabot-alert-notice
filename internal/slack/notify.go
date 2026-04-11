package slack

import (
	"fmt"
	"log/slog"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	slackgo "github.com/slack-go/slack"
)

func (c *SlackClient) Notify(record *model.AlertRecord) error {
	alert := record.Alert
	eval := record.Evaluation

	severityEmoji := severityToEmoji(alert.Severity)
	recEmoji := recommendationToEmoji(eval.Recommendation)

	headerText := fmt.Sprintf("%s %s in %s/%s", severityEmoji, alert.PackageName, alert.Owner, alert.Repo)

	blocks := []slackgo.Block{
		slackgo.NewHeaderBlock(
			slackgo.NewTextBlockObject(slackgo.PlainTextType, headerText, true, false),
		),
		slackgo.NewSectionBlock(
			slackgo.NewTextBlockObject(slackgo.MarkdownType,
				fmt.Sprintf("*Severity:* %s | *CVE:* %s | *CVSS:* %.1f\n*Fixed in:* %s",
					alert.Severity, alert.CVEID, alert.CVSSScore, alert.FixedIn),
				false, false,
			), nil, nil,
		),
		slackgo.NewDividerBlock(),
		slackgo.NewSectionBlock(
			slackgo.NewTextBlockObject(slackgo.MarkdownType,
				fmt.Sprintf("%s *AI評価:*\n*Risk:* %s | *Recommendation:* %s\n%s",
					recEmoji, eval.Risk, eval.Recommendation, eval.Reasoning),
				false, false,
			), nil, nil,
		),
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
	}

	_, _, err := c.api.PostMessage(
		c.channelID,
		slackgo.MsgOptionBlocks(blocks...),
		slackgo.MsgOptionText(headerText, false),
	)
	if err != nil {
		slog.Error("Slack通知送信失敗", "error", err)
		return fmt.Errorf("slack通知送信失敗: %w", err)
	}

	slog.Info("Slack通知送信完了", "alertID", alert.ID, "package", alert.PackageName)
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
