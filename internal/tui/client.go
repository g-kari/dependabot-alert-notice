// Package tui provides a terminal menu connected to the running application.
package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/control"
)

// Client talks only to the local control API, including SSH forwarded ports.
type Client struct {
	base string
	http *http.Client
	csrf string
}

// NewClient creates a bounded HTTP client without proxy or redirect forwarding.
func NewClient(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("TUI接続先はhttp://127.0.0.1:ポートの形式で指定してください")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("TUI接続先はローカル限定です。リモート環境にはSSHポート転送を使ってください")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("TUIセッション作成: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{base: strings.TrimRight(base, "/"), http: &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (c *Client) request(ctx context.Context, method, path string, body, response any) error {
	var data bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&data).Encode(body); err != nil {
			return fmt.Errorf("TUIリクエスト作成: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, &data)
	if err != nil {
		return fmt.Errorf("TUIリクエスト作成: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("アプリへの接続失敗（本体の起動・接続先を確認してください）: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusSeeOther && response == nil {
		return nil
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		raw, err := io.ReadAll(io.LimitReader(res.Body, 1024))
		if err != nil {
			return fmt.Errorf("TUIエラー応答取得: %w", err)
		}
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, clean(strings.TrimSpace(string(raw))))
	}
	if response != nil {
		if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(response); err != nil {
			return fmt.Errorf("TUI応答取得: %w", err)
		}
	}
	return nil
}

// Settings retrieves a redacted configuration and initializes the CSRF session.
func (c *Client) Settings(ctx context.Context) (control.Settings, error) {
	var result control.Settings
	err := c.request(ctx, "GET", "/api/tui/config", nil, &result)
	if err == nil {
		if result.CSRF == "" {
			return result, fmt.Errorf("TUIセッションがありません。この機能に対応するアプリへ更新してください")
		}
		c.csrf = result.CSRF
	}
	return result, err
}

// Save applies the settings only if their revision is still current.
func (c *Client) Save(ctx context.Context, settings control.Settings) (control.Saved, error) {
	var result control.Saved
	err := c.request(ctx, "PUT", "/api/tui/config", settings, &result)
	return result, err
}

// Status retrieves the bounded alert and log dashboard.
func (c *Client) Status(ctx context.Context) (control.Status, error) {
	var result control.Status
	err := c.request(ctx, "GET", "/api/tui/status", nil, &result)
	return result, err
}

// Action requests a manual fetch or an evaluation through the existing workers.
func (c *Client) Action(ctx context.Context, action string) error {
	if action != "poll" && !strings.HasPrefix(action, "evaluate/") {
		return fmt.Errorf("不明な操作です")
	}
	return c.request(ctx, "POST", "/api/tui/"+action, nil, nil)
}

// Credentials retrieves credential metadata without any secret values.
func (c *Client) Credentials(ctx context.Context) (control.CredentialsStatus, error) {
	var result control.CredentialsStatus
	err := c.request(ctx, "GET", "/api/tui/credentials", nil, &result)
	return result, err
}

// SaveCredentials saves explicit overrides and leaves running connections unchanged.
func (c *Client) SaveCredentials(ctx context.Context, changes control.CredentialChanges) (control.CredentialsStatus, error) {
	var result control.CredentialsStatus
	err := c.request(ctx, "PATCH", "/api/tui/credentials", changes, &result)
	return result, err
}
