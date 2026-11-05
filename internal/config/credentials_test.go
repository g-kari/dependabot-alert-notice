package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func credentialFixture(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows保存は未対応")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("targets: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func secretPointer(value string) *string { return &value }
func TestCredentialsLoadOverridesEnvironmentAndCanDisableOrInherit(t *testing.T) {
	path := credentialFixture(t)
	t.Setenv("SLACK_BOT_TOKEN", "xoxb-env-fixture")
	t.Setenv("SLACK_APP_TOKEN", "")
	t.Setenv("DISCORD_WEBHOOK_URL", "")
	next, err := UpdateCredentials(path, 0, map[string]*string{"slack_bot_token": secretPointer("xoxb-saved-fixture")})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Slack.BotToken != "xoxb-saved-fixture" || cfg.CredentialsRevision != next.Revision {
		t.Fatal("saved value not loaded")
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "xoxb-saved-fixture") || strings.Contains(string(raw), "credentials_revision") {
		t.Fatal("secret or private metadata written to YAML")
	}
	next, err = UpdateCredentials(path, next.Revision, map[string]*string{"slack_bot_token": secretPointer("")})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil || cfg.Slack.BotToken != "" {
		t.Fatal("saved disable did not override environment")
	}
	_, err = UpdateCredentials(path, next.Revision, map[string]*string{"slack_bot_token": nil})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil || cfg.Slack.BotToken != "xoxb-env-fixture" {
		t.Fatal("inherit did not restore environment")
	}
	info, err := os.Stat(path + ".credentials.json")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe credential permissions")
	}
}
func TestCredentialsRejectStaleRevisionAndInvalidValuesWithoutChangingFile(t *testing.T) {
	path := credentialFixture(t)
	_, err := UpdateCredentials(path, 0, map[string]*string{"slack_bot_token": secretPointer("xoxb-original-fixture")})
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path + ".credentials.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateCredentials(path, 0, map[string]*string{"slack_app_token": secretPointer("xapp-new-fixture")}); !errors.Is(err, ErrCredentialsConflict) {
		t.Fatalf("expected conflict: %v", err)
	}
	for _, values := range []map[string]*string{
		{"slack_app_token": secretPointer("invalid-private-secret")},
		{"discord_webhook_url": secretPointer("https://attacker.example/api/webhooks/123/private-secret")},
		{"discord_webhook_url": secretPointer("https://discord.com/api/webhooks/123/private-secret\n")},
		{"unknown": secretPointer("private-secret")},
	} {
		_, err := UpdateCredentials(path, 1, values)
		if !errors.Is(err, ErrInvalidCredentials) || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("unsafe validation error: %v", err)
		}
		after, err := os.ReadFile(path + ".credentials.json")
		if err != nil || string(after) != string(before) {
			t.Fatal("invalid update modified credentials")
		}
	}
}
func TestCredentialsRejectUnsafeFilesAndPreserveSymlinkTarget(t *testing.T) {
	path := credentialFixture(t)
	target := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(target, []byte("do not change"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+".credentials.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(path); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := UpdateCredentials(path, 0, map[string]*string{"slack_bot_token": secretPointer("xoxb-fixture")}); err == nil {
		t.Fatal("symlink overwritten")
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "do not change" {
		t.Fatal("target modified")
	}
	if err := os.Remove(path + ".credentials.json"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".credentials.json", []byte(`{"slack_bot_token":"private-secret"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path+".credentials.json", 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(path); err == nil {
		t.Fatal("publicly readable credential accepted")
	}
}

func TestCredentialsConcurrentWritersAndMalformedFile(t *testing.T) {
	path := credentialFixture(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := UpdateCredentials(path, 0, map[string]*string{"slack_app_token": secretPointer("xapp-fixture")})
			results <- err
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrCredentialsConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("concurrent writes were not serialized")
	}
	if _, err := os.Stat(path + ".credentials.json.lock"); !os.IsNotExist(err) {
		t.Fatal("lock leaked")
	}
	if err := os.WriteFile(path+".credentials.json", []byte(`{"revision":1,"slack_app_token":"xapp-fixture"} {}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(path); err == nil {
		t.Fatal("trailing data accepted")
	}
}
