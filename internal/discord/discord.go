package discord

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// Client はDiscord Webhook通知クライアント
type Client struct {
	webhookURL string
	httpClient *http.Client
}

// New はDiscord Webhookクライアントを生成する
func New(webhookURL string) *Client {
	return &Client{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Discordの色定数 (10進数)
const (
	colorCritical = 0xb91c1c // 赤
	colorHigh     = 0x92400e // オレンジ
	colorMedium   = 0x713f12 // 黄
	colorLow      = 0x166534 // 緑
	colorDefault  = 0xa39696 // グレー
)

type embedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type embed struct {
	Title  string       `json:"title"`
	Color  int          `json:"color"`
	URL    string       `json:"url,omitempty"`
	Fields []embedField `json:"fields"`
}

type webhookPayload struct {
	Embeds []embed `json:"embeds"`
}

// NotifyEval はAI評価完了をDiscord Webhookに追加通知する
func (c *Client) NotifyEval(record *model.AlertRecord) error {
	if record.Evaluation == nil {
		return nil
	}
	return c.Notify(record)
}

// Notify はDependabotアラートをDiscord Webhookに通知する
func (c *Client) Notify(record *model.AlertRecord) error {
	if c.webhookURL == "" {
		return fmt.Errorf("discord webhook URLが未設定です")
	}

	alert := record.Alert
	eval := record.Evaluation

	title := fmt.Sprintf("%s %s in %s/%s",
		severityToEmoji(alert.Severity), alert.PackageName, alert.Owner, alert.Repo)

	fields := []embedField{
		{Name: "Severity", Value: string(alert.Severity), Inline: true},
		{Name: "CVE", Value: nonEmpty(alert.CVEID, "N/A"), Inline: true},
		{Name: "CVSS", Value: fmt.Sprintf("%.1f", alert.CVSSScore), Inline: true},
		{Name: "Fixed in", Value: nonEmpty(alert.FixedIn, "N/A"), Inline: true},
	}

	if alert.Summary != "" {
		fields = append([]embedField{{Name: "タイトル", Value: alert.Summary, Inline: false}}, fields...)
	}

	if eval != nil {
		fields = append(fields,
			embedField{Name: "Risk", Value: nonEmpty(eval.Risk, "N/A"), Inline: true},
			embedField{Name: "Recommendation", Value: nonEmpty(eval.Recommendation, "N/A"), Inline: true},
			embedField{Name: "AI評価", Value: nonEmpty(eval.Reasoning, "N/A"), Inline: false},
		)
	}

	payload := webhookPayload{
		Embeds: []embed{
			{
				Title:  title,
				Color:  severityToColor(alert.Severity),
				URL:    alert.HTMLURL,
				Fields: fields,
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("discord payload JSONシリアライズ失敗: %w", err)
	}

	resp, err := c.httpClient.Post(c.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("discord webhook送信失敗: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook エラーレスポンス: %d", resp.StatusCode)
	}

	slog.Info("Discord通知送信完了", "alertID", alert.ID, "package", alert.PackageName)
	return nil
}

func severityToColor(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return colorCritical
	case model.SeverityHigh:
		return colorHigh
	case model.SeverityMedium:
		return colorMedium
	case model.SeverityLow:
		return colorLow
	default:
		return colorDefault
	}
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

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
