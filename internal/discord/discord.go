package discord

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/ratelimit"
)

// Client はDiscord Webhook通知クライアント
type Client struct {
	webhookURL string
	httpClient *http.Client
	limiter    *ratelimit.Limiter
}

// New はDiscord Webhookクライアントを生成する
func New(webhookURL string) *Client {
	return &Client{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		// Discord Webhook: レスポンスヘッダでレート制限を動的に制御。デフォルト500ms間隔
		limiter: ratelimit.NewLimiter(500 * time.Millisecond),
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
func (c *Client) NotifyEval(record *model.AlertRecord) (string, error) {
	if record.Evaluation == nil {
		return "", nil
	}
	return c.Notify(record)
}

// Notify はDependabotアラートをDiscord Webhookに通知し、メッセージIDを返す
func (c *Client) Notify(record *model.AlertRecord) (string, error) {
	if c.webhookURL == "" {
		return "", fmt.Errorf("discord webhook URLが未設定です")
	}

	if err := c.limiter.Wait(context.Background()); err != nil {
		return "", fmt.Errorf("discord通知レート制限待機失敗: %w", err)
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
			embedField{Name: "Recommendation", Value: nonEmpty(eval.Recommendation, "N/A"), Inline: true},
			embedField{Name: "侵害される内容", Value: nonEmpty(eval.Impact, "N/A"), Inline: false},
			embedField{Name: "侵害される使い方", Value: nonEmpty(eval.Reasoning, "N/A"), Inline: false},
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
		return "", fmt.Errorf("discord payload JSONシリアライズ失敗: %w", err)
	}

	// ?wait=true でメッセージIDを取得
	url := c.webhookURL + "?wait=true"
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("discord webhook送信失敗: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// レスポンスヘッダからレート制限情報を読み取る
	c.applyRateLimitHeaders(resp)

	if resp.StatusCode == http.StatusTooManyRequests {
		return "", fmt.Errorf("discord webhook レート制限 (429)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("discord webhook エラーレスポンス: %d", resp.StatusCode)
	}

	// レスポンスからメッセージIDを取得
	var msgResp struct {
		ID string `json:"id"`
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(respBody, &msgResp)

	slog.Info("Discord通知送信完了", "alertID", alert.ID, "package", alert.PackageName, "messageID", msgResp.ID)
	return msgResp.ID, nil
}

// UpdateEvalMessage はAI評価完了後に既存Discord Webhookメッセージをeval結果でPATCH編集する
func (c *Client) UpdateEvalMessage(record *model.AlertRecord) error {
	if record.DiscordMessageID == "" {
		return nil
	}

	if err := c.limiter.Wait(context.Background()); err != nil {
		return fmt.Errorf("discord eval更新レート制限待機失敗: %w", err)
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
			embedField{Name: "Recommendation", Value: nonEmpty(eval.Recommendation, "N/A"), Inline: true},
			embedField{Name: "侵害される内容", Value: nonEmpty(eval.Impact, "N/A"), Inline: false},
			embedField{Name: "侵害される使い方", Value: nonEmpty(eval.Reasoning, "N/A"), Inline: false},
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
		return fmt.Errorf("discord eval更新 payload JSONシリアライズ失敗: %w", err)
	}

	patchURL := c.webhookURL + "/messages/" + record.DiscordMessageID
	req, err := http.NewRequest(http.MethodPatch, patchURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("discord eval更新 PATCHリクエスト作成失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("discord eval更新 PATCH送信失敗: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	c.applyRateLimitHeaders(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord eval更新 PATCHエラー: %d", resp.StatusCode)
	}

	slog.Info("DiscordメッセージにAI評価を反映", "alertID", alert.ID, "messageID", record.DiscordMessageID)
	return nil
}

// NotifyResolved は対応済みアラートをDiscord Webhookメッセージに反映する（PATCHで編集）
func (c *Client) NotifyResolved(record *model.AlertRecord) error {
	if record.DiscordMessageID == "" {
		return nil
	}

	if err := c.limiter.Wait(context.Background()); err != nil {
		return fmt.Errorf("discord resolved通知レート制限待機失敗: %w", err)
	}

	alert := record.Alert
	title := fmt.Sprintf("✅ %s %s in %s/%s — 対応済み",
		severityToEmoji(alert.Severity), alert.PackageName, alert.Owner, alert.Repo)

	payload := webhookPayload{
		Embeds: []embed{
			{
				Title: title,
				Color: 0x22c55e, // 緑
				URL:   alert.HTMLURL,
				Fields: []embedField{
					{Name: "Status", Value: "✅ 対応済み — GitHub側で解決済み", Inline: false},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("discord resolved payload JSONシリアライズ失敗: %w", err)
	}

	// PATCH /webhooks/{id}/{token}/messages/{message_id}
	patchURL := c.webhookURL + "/messages/" + record.DiscordMessageID
	req, err := http.NewRequest(http.MethodPatch, patchURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("discord resolved PATCHリクエスト作成失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("discord resolved PATCH送信失敗: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	c.applyRateLimitHeaders(resp)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord resolved PATCHエラー: %d", resp.StatusCode)
	}

	slog.Info("Discord対応済み通知完了", "alertID", alert.ID, "messageID", record.DiscordMessageID)
	return nil
}

// applyRateLimitHeaders はDiscordのレスポンスヘッダからレート制限情報を抽出してLimiterに反映する
func (c *Client) applyRateLimitHeaders(resp *http.Response) {
	// 残りリクエスト数が0の場合はリセット時刻まで待機
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	resetAfter := resp.Header.Get("X-RateLimit-Reset-After")

	if remaining == "0" && resetAfter != "" {
		if secs, err := strconv.ParseFloat(resetAfter, 64); err == nil && secs > 0 {
			c.limiter.SetRetryAfter(time.Duration(secs * float64(time.Second)))
			slog.Debug("Discord レート制限ヘッダ適用", "resetAfter", secs)
		}
	}

	// 429 の場合は Retry-After ヘッダまたは JSON レスポンスから読む
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		if secs, err := strconv.ParseFloat(retryAfter, 64); err == nil && secs > 0 {
			c.limiter.SetRetryAfter(time.Duration(secs * float64(time.Second)))
			slog.Warn("Discord 429 レート制限", "retryAfterSec", secs)
			return
		}
		// ヘッダにない場合はレスポンスボディのJSONを試みる
		var retryBody struct {
			RetryAfter float64 `json:"retry_after"`
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(bodyBytes, &retryBody); err == nil && retryBody.RetryAfter > 0 {
			c.limiter.SetRetryAfter(time.Duration(retryBody.RetryAfter * float64(time.Second)))
			slog.Warn("Discord 429 レート制限（JSON）", "retryAfterSec", retryBody.RetryAfter)
		}
	}
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
