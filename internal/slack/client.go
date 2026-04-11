package slack

import (
	"context"
	"log/slog"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/ratelimit"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	slackgo "github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"
)

type SlackClient struct {
	api            *slackgo.Client
	socket         *socketmode.Client
	channelID      string
	store          *store.Store
	merger         merger.Interface
	limiter        *ratelimit.Limiter
	allowedUserIDs []string // 承認・却下を許可するSlack User IDリスト（空=全員許可）
}

func New(cfg *config.Config, s *store.Store, m merger.Interface) *SlackClient {
	api := slackgo.New(
		cfg.Slack.BotToken,
		slackgo.OptionAppLevelToken(cfg.Slack.AppToken),
	)
	socket := socketmode.New(api)

	return &SlackClient{
		api:       api,
		socket:    socket,
		channelID: cfg.Slack.ChannelID,
		store:     s,
		merger:    m,
		// Slack: chat.postMessage は1メッセージ/秒/チャンネルが推奨
		limiter:        ratelimit.NewLimiter(1 * time.Second),
		allowedUserIDs: cfg.Slack.AllowedUserIDs,
	}
}

func (c *SlackClient) Start(ctx context.Context) {
	go c.handleEvents(ctx)

	slog.Info("Slack Socket Mode 開始")
	if err := c.socket.RunContext(ctx); err != nil {
		slog.Error("Slack Socket Mode エラー", "error", err)
	}
}

func (c *SlackClient) API() *slackgo.Client {
	return c.api
}
