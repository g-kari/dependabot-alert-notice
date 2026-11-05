package evaluator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func appleFixture(t *testing.T) *AppleEvaluator {
	t.Helper()
	home := t.TempDir()
	t.Setenv("CODEX_HOME", home)
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	if err := os.WriteFile(filepath.Join(home, "auth.json"), []byte(`{"tokens":{"access_token":"private-access-token"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	return &AppleEvaluator{cfg: config.Defaults().Evaluator, platform: func() (string, string) { return "darwin", "arm64" }}
}
func TestAppleEvaluationKeepsBoundaryAndCleansUp(t *testing.T) {
	e := appleFixture(t)
	e.cfg.Provider = "codex"
	var mounted string
	calls := 0
	e.run = func(ctx context.Context, c codexCommand) ([]byte, error) {
		calls++
		if c.Name == "sw_vers" {
			return []byte("26.3\n"), nil
		}
		if c.Args[0] == "delete" {
			if c.Args[1] != "--force" || !strings.HasPrefix(c.Args[2], "security-notice-eval-") {
				t.Fatal("unscoped cleanup")
			}
			return nil, nil
		}
		args := strings.Join(c.Args, " ")
		for _, flag := range []string{"--tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777", "--read-only", "--cap-drop ALL", "--cpus 1", "--memory 512m", "--network default", "--user 1000:1000", "--no-new-privs", "--sandbox read-only", "--ephemeral", "readonly"} {
			if !strings.Contains(args, flag) {
				t.Errorf("missing %q: %s", flag, args)
			}
		}
		if strings.Contains(args, "private-access-token") || strings.Contains(args, "pkg-input") || strings.Contains(args, "--network host") || strings.Contains(args, os.Getenv("CODEX_HOME")) {
			t.Fatal("host credentials, prompt or home in command")
		}
		if !strings.Contains(c.Input, "pkg-input") {
			t.Fatal("missing stdin prompt")
		}
		for i, a := range c.Args {
			if a == "--mount" {
				for _, part := range strings.Split(c.Args[i+1], ",") {
					if strings.HasPrefix(part, "source=") {
						mounted = strings.TrimPrefix(part, "source=")
					}
				}
			}
		}
		raw, err := os.ReadFile(filepath.Join(mounted, "auth.json"))
		if err != nil || !strings.Contains(string(raw), "private-access-token") {
			t.Fatal("credential stage missing")
		}
		files, err := os.ReadDir(mounted)
		if err != nil || len(files) != 1 {
			t.Fatal("unexpected credential exposure")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing timeout")
		}
		return []byte("{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"{\\\"impact\\\":\\\"private-access-token\\\",\\\"recommendation\\\":\\\"manual-review\\\",\\\"reasoning\\\":\\\"ok\\\"}\"}}\n{\"type\":\"turn.completed\"}\n"), nil
	}
	result, err := e.Evaluate(context.Background(), model.Alert{PackageName: "pkg-input"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || strings.Contains(result.Impact, "private-access-token") {
		t.Fatal("cleanup or redaction missing")
	}
	if _, err := os.Stat(mounted); !os.IsNotExist(err) {
		t.Fatal("credential stage survived")
	}
}
func TestAppleFailureNeverRunsDirectlyAndStillDeletesContainer(t *testing.T) {
	e := appleFixture(t)
	e.cfg.Provider = "codex"
	deleted := false
	e.run = func(ctx context.Context, c codexCommand) ([]byte, error) {
		if c.Name == "sw_vers" {
			return []byte("26.3"), nil
		}
		if c.Args[0] == "delete" {
			deleted = true
			return nil, nil
		}
		if c.Name != "container" {
			t.Fatal("fell back to unisolated CLI")
		}
		return nil, errors.New("runtime failed")
	}
	if result, err := e.Evaluate(context.Background(), model.Alert{}); err == nil || result != nil || !deleted {
		t.Fatal("failure not closed")
	}
}
func TestAppleRejectsUnsupportedPlatformBeforeExecution(t *testing.T) {
	e := appleFixture(t)
	e.platform = func() (string, string) { return "linux", "arm64" }
	e.run = func(context.Context, codexCommand) ([]byte, error) {
		t.Fatal("executed on unsupported platform")
		return nil, nil
	}
	if _, err := e.Evaluate(context.Background(), model.Alert{}); err == nil {
		t.Fatal("unsupported platform accepted")
	}
}
func TestAppleRejectsUnsupportedMacVersion(t *testing.T) {
	e := appleFixture(t)
	e.run = func(_ context.Context, c codexCommand) ([]byte, error) {
		if c.Name != "sw_vers" {
			t.Fatal("runtime executed on old Mac")
		}
		return []byte("15.7"), nil
	}
	if _, err := e.Evaluate(context.Background(), model.Alert{}); err == nil {
		t.Fatal("old macOS accepted")
	}
}
func TestAppleTimeoutAndCleanupAreBounded(t *testing.T) {
	e := appleFixture(t)
	e.cfg.Provider = "codex"
	e.cfg.Sandbox.Timeout = time.Millisecond
	e.run = func(ctx context.Context, c codexCommand) ([]byte, error) {
		if c.Name == "sw_vers" {
			return []byte("26.3"), nil
		}
		if c.Args[0] == "delete" {
			if ctx.Err() != nil {
				t.Fatal("cleanup used cancelled context")
			}
			return nil, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if _, err := e.Evaluate(context.Background(), model.Alert{}); err == nil {
		t.Fatal("timeout accepted")
	}
}
func TestNewExplicitAppleRuntimeCannotDisableIsolation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Evaluator.Sandbox.Runtime = "apple"
	cfg.Evaluator.Sandbox.Enabled = false
	e := New(cfg)
	if _, err := e.Evaluate(context.Background(), model.Alert{}); err == nil {
		t.Fatal("Apple isolation bypassed")
	}
}

func TestAppleErrorsNeverExposeCredentials(t *testing.T) {
	e := appleFixture(t)
	e.cfg.Provider = "codex"
	e.run = func(_ context.Context, c codexCommand) ([]byte, error) {
		if c.Name == "sw_vers" {
			return []byte("26.3"), nil
		}
		return nil, errors.New("failure with private-access-token")
	}
	result, err := e.Evaluate(context.Background(), model.Alert{})
	if result != nil || err == nil || strings.Contains(err.Error(), "private-access-token") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestAppleAuthStagesOnlySelectedCredentials(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			e := appleFixture(t)
			e.cfg.Provider = provider
			key := "test-private-api-key"
			if provider == "claude" {
				t.Setenv("ANTHROPIC_API_KEY", key)
			} else {
				t.Setenv("OPENAI_API_KEY", key)
			}
			work := t.TempDir()
			auth := filepath.Join(work, "auth")
			if err := os.Mkdir(auth, 0755); err != nil {
				t.Fatal(err)
			}
			secrets, envFile, err := e.stageAuth(work, auth)
			if err != nil {
				t.Fatal(err)
			}
			if len(secrets) != 1 || secrets[0] != key {
				t.Fatal("redaction secret missing")
			}
			path := filepath.Join(auth, "auth.json")
			perm := os.FileMode(0444)
			if provider == "claude" {
				path = envFile
				perm = 0600
			}
			info, err := os.Stat(path)
			if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != perm) {
				t.Fatal("incorrect credential permissions")
			}
			raw, err := os.ReadFile(path)
			if err != nil || !strings.Contains(string(raw), key) {
				t.Fatal("credential not staged")
			}
		})
	}
}

func TestAppleRejectsMissingOrSymlinkCredentialsBeforeVMStart(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(fmt.Sprint(symlink), func(t *testing.T) {
			e := appleFixture(t)
			e.cfg.Provider = "claude"
			e.cfg.Sandbox.ClaudeHome = t.TempDir()
			if symlink {
				target := filepath.Join(t.TempDir(), "private.json")
				if err := os.WriteFile(target, []byte(`{"accessToken":"fixture-private-token"}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(e.cfg.Sandbox.ClaudeHome, ".credentials.json")); err != nil {
					t.Skip(err)
				}
			}
			e.run = func(_ context.Context, c codexCommand) ([]byte, error) {
				if c.Name != "sw_vers" {
					t.Fatal("VM started without safe credentials")
				}
				return []byte("26.3"), nil
			}
			if _, err := e.Evaluate(context.Background(), model.Alert{}); err == nil {
				t.Fatal("invalid credential accepted")
			}
		})
	}
}

func TestAppleCleanupFailureDiscardsSuccessfulEvaluation(t *testing.T) {
	e := appleFixture(t)
	t.Setenv("ANTHROPIC_API_KEY", "fixture-api-secret")
	e.run = func(_ context.Context, c codexCommand) ([]byte, error) {
		if c.Name == "sw_vers" {
			return []byte("26.3"), nil
		}
		if c.Args[0] == "delete" {
			return nil, errors.New("delete failed")
		}
		return []byte(`{"impact":"ok","recommendation":"manual-review","reasoning":"ok"}`), nil
	}
	if result, err := e.Evaluate(context.Background(), model.Alert{}); result != nil || err == nil {
		t.Fatal("successful result accepted despite failed cleanup")
	}
}

func TestNewAppleAutoRuntimeFailsClosedWhenDisabled(t *testing.T) {
	cfg := config.Defaults()
	cfg.Evaluator.Sandbox.Enabled = false
	e := newEvaluator(cfg, "darwin", "arm64")
	if _, ok := e.(*AppleEvaluator); !ok {
		t.Fatalf("unsafe auto evaluator: %T", e)
	}
	if _, err := e.Evaluate(context.Background(), model.Alert{}); err == nil {
		t.Fatal("disabled isolation accepted")
	}
}
