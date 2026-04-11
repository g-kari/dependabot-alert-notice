package slack

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	slackgo "github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
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
			_ = c.socket.Ack(*evt.Request)
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

// isAllowedUser はユーザーIDが承認許可リストに含まれるかを返す。
// 許可リストが空の場合は全員を許可する（後方互換）。
func (c *SlackClient) isAllowedUser(userID string) bool {
	if len(c.allowedUserIDs) == 0 {
		return true
	}
	for _, id := range c.allowedUserIDs {
		if id == userID {
			return true
		}
	}
	return false
}

func (c *SlackClient) handleApprove(ctx context.Context, action *slackgo.BlockAction, callback *slackgo.InteractionCallback) {
	if !c.isAllowedUser(callback.User.ID) {
		slog.Warn("承認権限なし", "userID", callback.User.ID, "userName", callback.User.Name)
		c.postReply(callback.Channel.ID, callback.Message.Timestamp,
			fmt.Sprintf("🚫 %s さんは承認権限がありません", callback.User.Name))
		return
	}

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
	if !c.isAllowedUser(callback.User.ID) {
		slog.Warn("却下権限なし", "userID", callback.User.ID, "userName", callback.User.Name)
		c.postReply(callback.Channel.ID, callback.Message.Timestamp,
			fmt.Sprintf("🚫 %s さんは却下権限がありません", callback.User.Name))
		return
	}

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
