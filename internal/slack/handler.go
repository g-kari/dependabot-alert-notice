package slack

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/slack-go/slack/socketmode"
	slackgo "github.com/slack-go/slack"
)

func (c *SlackClient) handleEvents(ctx context.Context) {
	for evt := range c.socket.Events {
		switch evt.Type {
		case socketmode.EventTypeInteractive:
			callback, ok := evt.Data.(slackgo.InteractionCallback)
			if !ok {
				continue
			}
			c.handleInteraction(ctx, &callback)
			c.socket.Ack(*evt.Request)
		}
	}
}

func (c *SlackClient) handleInteraction(ctx context.Context, callback *slackgo.InteractionCallback) {
	for _, action := range callback.ActionCallback.BlockActions {
		switch action.ActionID {
		case "approve":
			c.handleApprove(ctx, action, callback)
		case "reject":
			c.handleReject(action, callback)
		case "open_github":
			// URLボタンは自動でブラウザが開くのでサーバー側処理は不要
		}
	}
}

func (c *SlackClient) handleApprove(ctx context.Context, action *slackgo.BlockAction, callback *slackgo.InteractionCallback) {
	alertID, err := strconv.Atoi(action.Value)
	if err != nil {
		slog.Error("alertIDパース失敗", "value", action.Value, "error", err)
		return
	}

	slog.Info("マージ承認", "alertID", alertID, "user", callback.User.Name)

	if err := c.merger.Approve(ctx, alertID); err != nil {
		slog.Error("マージ失敗", "alertID", alertID, "error", err)
		c.postReply(callback.Channel.ID, callback.Message.Timestamp,
			fmt.Sprintf("❌ マージ失敗: %v", err))
		return
	}

	c.postReply(callback.Channel.ID, callback.Message.Timestamp,
		fmt.Sprintf("✅ アラート #%d のPRをマージしました (%s)", alertID, callback.User.Name))
}

func (c *SlackClient) handleReject(action *slackgo.BlockAction, callback *slackgo.InteractionCallback) {
	alertID, err := strconv.Atoi(action.Value)
	if err != nil {
		slog.Error("alertIDパース失敗", "value", action.Value, "error", err)
		return
	}

	slog.Info("却下", "alertID", alertID, "user", callback.User.Name)

	if err := c.merger.Reject(alertID); err != nil {
		slog.Error("却下失敗", "alertID", alertID, "error", err)
		return
	}

	c.postReply(callback.Channel.ID, callback.Message.Timestamp,
		fmt.Sprintf("❌ アラート #%d を却下しました (%s)", alertID, callback.User.Name))
}

func (c *SlackClient) postReply(channelID, threadTS, text string) {
	if c.api == nil {
		return
	}
	_, _, err := c.api.PostMessage(
		channelID,
		slackgo.MsgOptionText(text, false),
		slackgo.MsgOptionTS(threadTS),
	)
	if err != nil {
		slog.Error("リプライ送信失敗", "error", err)
	}
}
