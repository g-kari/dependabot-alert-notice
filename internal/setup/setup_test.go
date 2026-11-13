package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

func TestRunCreatesHeadlessConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	var out bytes.Buffer
	// targets, poll, paths x3, data, host, port, Slack channel/users,
	// notification severity, provider, automatic evaluation, RSS, confirmation.
	input := "acme/api,acme/*\n1h\n\n\n\n\n\n9000\nC123\nU123,U456\nhigh\nhermes\ny\ny\ny\n"
	if err := Run(path, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 2 || cfg.Targets[1].Repo != "" || cfg.PollInterval != time.Hour || cfg.Web.Host != "127.0.0.1" || cfg.Web.Port != 9000 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Slack.ChannelID != "C123" || len(cfg.Slack.AllowedUserIDs) != 2 || cfg.NotifyMinSeverity != "high" || cfg.Evaluator.Provider != "hermes" || !cfg.Evaluator.AutoEval || !cfg.Evaluator.Sandbox.Enabled || len(cfg.RSS.Feeds) != 6 {
		t.Fatalf("unexpected settings: %+v", cfg)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if !strings.Contains(out.String(), "SLACK_BOT_TOKEN") {
		t.Fatal("missing credential guidance")
	}
}

func TestRunKeepsExistingSettingsAndDoesNotPersistEnvironmentSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := "config_revision: 7\ntargets:\n  - owner: acme\n    excludes: [legacy]\nweb:\n  host: 127.0.0.1\n  port: 8999\nrss:\n  feeds: []\nevaluator:\n  sandbox:\n    memory_limit: 1g\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_WEBHOOK_URL"} {
		t.Setenv(key, "test-secret-value")
	}
	var out bytes.Buffer
	if err := Run(path, strings.NewReader(strings.Repeat("\n", 14)+"y\n"), &out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "test-secret-value") || strings.Contains(out.String(), "test-secret-value") {
		t.Fatal("secret leaked")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Targets) != 1 || len(cfg.Targets[0].Excludes) != 1 || len(cfg.RSS.Feeds) != 0 || cfg.Evaluator.Sandbox.MemoryLimit != "1g" || cfg.ConfigRevision != 8 {
		t.Fatalf("existing settings lost: %+v", cfg)
	}
}

func TestRunCancelOrEOFLeavesFileUntouched(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("\n", 14) + "n\n"} {
		t.Run(input, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			original := []byte("targets: []\n")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err := Run(path, strings.NewReader(input), &out)
			if input == "" && err == nil {
				t.Fatal("EOF must fail")
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("file changed before confirmation")
			}
		})
	}
}

func TestRunInvalidAnswersReprompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := "bad target\nacme/api\n0s\n30m\n\n\n\n\ninvalid-host\n127.0.0.1\n70000\n8999\n\n\nurgent\nhigh\ninvalid\nclaude\nmaybe\nn\ny\ny\n"
	var out bytes.Buffer
	if err := Run(path, strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "入力エラー") != 7 {
		t.Fatalf("reprompts: %s", out.String())
	}
}

func TestRunRejectsMalformedExistingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("web: [broken")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run(path, strings.NewReader("y\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("malformed config accepted")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("malformed file overwritten")
	}
}

// changeOnRead models another settings writer during the interaction.
type changeOnRead struct {
	reader  *strings.Reader
	path    string
	t       *testing.T
	changed bool
}

func (r *changeOnRead) Read(p []byte) (int, error) {
	r.t.Helper()
	if !r.changed {
		if err := os.WriteFile(r.path, []byte("poll_interval: 2h\n"), 0600); err != nil {
			r.t.Fatal(err)
		}
		r.changed = true
	}
	return r.reader.Read(p)
}

func TestRunDoesNotOverwriteConcurrentChanges(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(strconv.FormatBool(exists), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if exists {
				if err := os.WriteFile(path, []byte("targets: []\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			in := &changeOnRead{reader: strings.NewReader(strings.Repeat("\n", 14) + "y\n"), path: path, t: t}
			if err := Run(path, in, &bytes.Buffer{}); err == nil {
				t.Fatal("concurrent change accepted")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(raw) != "poll_interval: 2h\n" {
				t.Fatal("concurrent change overwritten")
			}
		})
	}
}
