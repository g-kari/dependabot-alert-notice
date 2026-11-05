package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrCredentialsConflict means another writer changed the credentials.
var ErrCredentialsConflict = errors.New("認証設定が変更されています。再読込してください")

// ErrInvalidCredentials means a credential update failed validation.
var ErrInvalidCredentials = errors.New("認証情報の形式が不正です")

// Credentials stores overrides separately from the public YAML configuration.
// Nil inherits environment/YAML; an empty string explicitly disables a credential.
type Credentials struct {
	Revision          uint64  `json:"revision"`
	SlackBotToken     *string `json:"slack_bot_token,omitempty"`
	SlackAppToken     *string `json:"slack_app_token,omitempty"`
	DiscordWebhookURL *string `json:"discord_webhook_url,omitempty"`
}

// ReadCredentials reads only an owner-private regular file, without exposing values in errors.
func ReadCredentials(path string) (Credentials, error) {
	var result Credentials
	if path == "" {
		return result, errors.New("設定ファイルの保存先がありません")
	}
	name := path + ".credentials.json"
	info, err := os.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("認証ファイル確認: %w", err)
	}
	if err = privateCredentialFile(info); err != nil {
		return result, err
	}
	f, err := os.Open(name)
	if err != nil {
		return result, fmt.Errorf("認証ファイル読込: %w", err)
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return result, fmt.Errorf("認証ファイル検証: %w", err)
	}
	if !os.SameFile(info, opened) {
		return result, errors.New("認証ファイルが変更されました")
	}
	if err = privateCredentialFile(opened); err != nil {
		return result, err
	}
	dec := json.NewDecoder(io.LimitReader(f, 65537))
	dec.DisallowUnknownFields()
	if dec.Decode(&result) != nil {
		return Credentials{}, errors.New("認証ファイルの形式が不正です")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return Credentials{}, errors.New("認証ファイルの形式が不正です")
	}
	return result, nil
}

var webhookPath = regexp.MustCompile(`^/api/(v[0-9]+/)?webhooks/[0-9]+/[A-Za-z0-9_-]+$`)

func validateCredential(key string, value *string) error {
	switch key {
	case "slack_bot_token", "slack_app_token", "discord_webhook_url":
	default:
		return ErrInvalidCredentials
	}
	if value == nil || *value == "" {
		return nil
	}
	s := *value
	if len(s) > 4096 {
		return ErrInvalidCredentials
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return ErrInvalidCredentials
		}
	}
	switch key {
	case "slack_bot_token":
		if !strings.HasPrefix(s, "xoxb-") && !strings.HasPrefix(s, "xoxe.xoxb-") {
			return ErrInvalidCredentials
		}
	case "slack_app_token":
		if !strings.HasPrefix(s, "xapp-") {
			return ErrInvalidCredentials
		}
	case "discord_webhook_url":
		u, err := url.Parse(s)
		if err != nil {
			return ErrInvalidCredentials
		}
		host := u.Hostname()
		if u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") || !webhookPath.MatchString(u.EscapedPath()) {
			return ErrInvalidCredentials
		}
		switch host {
		case "discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com":
		default:
			return ErrInvalidCredentials
		}
	}
	return nil
}

// UpdateCredentials atomically saves validated changes with revision conflict protection.
func UpdateCredentials(path string, expected uint64, values map[string]*string) (Credentials, error) {
	if path == "" {
		return Credentials{}, errors.New("設定ファイルの保存先がありません")
	}
	if len(values) == 0 {
		return Credentials{}, ErrInvalidCredentials
	}
	for key, value := range values {
		if err := validateCredential(key, value); err != nil {
			return Credentials{}, err
		}
	}
	if err := credentialStorageSupported(); err != nil {
		return Credentials{}, err
	}
	name := path + ".credentials.json"
	lock := name + ".lock"
	if err := os.Mkdir(lock, 0700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Credentials{}, ErrCredentialsConflict
		}
		return Credentials{}, fmt.Errorf("認証保存ロック: %w", err)
	}
	defer func() { _ = os.Remove(lock) }()
	next, err := ReadCredentials(path)
	if err != nil {
		return Credentials{}, err
	}
	if next.Revision != expected {
		return Credentials{}, ErrCredentialsConflict
	}
	for key, value := range values {
		if value != nil {
			copy := *value
			value = &copy
		}
		switch key {
		case "slack_bot_token":
			next.SlackBotToken = value
		case "slack_app_token":
			next.SlackAppToken = value
		case "discord_webhook_url":
			next.DiscordWebhookURL = value
		}
	}
	next.Revision++
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return Credentials{}, errors.New("認証保存形式の作成失敗")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".credentials-*.tmp")
	if err != nil {
		return Credentials{}, fmt.Errorf("認証保存準備: %w", err)
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		err = replaceFile(f.Name(), name)
	}
	if err != nil {
		return Credentials{}, fmt.Errorf("認証保存失敗: %w", err)
	}
	return next, nil
}

func (c Credentials) apply(cfg *Config) {
	if c.SlackBotToken != nil {
		cfg.Slack.BotToken = *c.SlackBotToken
	}
	if c.SlackAppToken != nil {
		cfg.Slack.AppToken = *c.SlackAppToken
	}
	if c.DiscordWebhookURL != nil {
		cfg.Discord.WebhookURL = *c.DiscordWebhookURL
	}
	cfg.CredentialsRevision = c.Revision
}
