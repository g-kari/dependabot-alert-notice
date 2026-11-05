package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"gopkg.in/yaml.v3"
)

func TestMacReleaseStarterIsSafeAndSelfContained(t *testing.T) {
	body, err := os.ReadFile("packaging/macos/Start.command")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{"#!/bin/bash", "Application Support/security-notice", "umask 077", "--web-url", "kill -0", "trap", "config.yaml.example"} {
		if !strings.Contains(text, required) {
			t.Errorf("starter missing %q", required)
		}
	}
	for _, forbidden := range []string{"curl |", "sudo", "xattr", "spctl", "go run", "gh auth login", "rm -rf"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("starter contains unsafe/unrequested action %q", forbidden)
		}
	}
	cfg, err := config.Load("packaging/macos/config.yaml.example")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Web.Host != "127.0.0.1" || cfg.Evaluator.AutoEval || !cfg.Evaluator.Sandbox.Enabled || !cfg.DisableApproval || len(cfg.Targets) != 0 || len(cfg.ServiceProfiles) != 0 || len(cfg.Assessments) != 0 || cfg.Slack.BotToken != "" || cfg.Discord.WebhookURL != "" {
		t.Fatal("distribution defaults must be local-only, unconfigured, isolated and read-only")
	}
}

func TestReleaseWorkflowUsesModuleGoVersionAndTestsMacArchives(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, required := range []string{"go-version-file: go.mod", "workflow_dispatch:", "go test", "macos-", "--version", "Start.command", "needs: [mac-build, mac-test]", "contents: write", "gh release upload"} {
		if !strings.Contains(text, required) {
			t.Errorf("release workflow missing %q", required)
		}
	}
	goreleaser, err := os.ReadFile(".goreleaser.yml")
	if err != nil {
		t.Fatal(err)
	}
	var releaseConfig struct {
		Release struct {
			Draft bool `yaml:"draft"`
		} `yaml:"release"`
	}
	if err := yaml.Unmarshal(goreleaser, &releaseConfig); err != nil {
		t.Fatal(err)
	}
	if !releaseConfig.Release.Draft {
		t.Fatal("release must remain draft until checks and asset upload complete")
	}
}

func TestReleaseWorkflowPublishesStableTagsOnlyAfterAssetUpload(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct{ Name, Run, If string }
		}
	}
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	upload, publish := -1, -1
	for i, step := range workflow.Jobs["release"].Steps {
		if strings.Contains(step.Run, "gh release upload") {
			upload = i
		}
		if strings.Contains(step.Run, "gh release edit") {
			publish = i
			for _, required := range []string{"--draft=false", "--prerelease=false", "--latest", "^v(0|[1-9][0-9]*)", "--notes-file"} {
				if !strings.Contains(step.Run, required) {
					t.Errorf("publication missing %q", required)
				}
			}
			if !strings.Contains(step.If, "github.event_name == 'push'") || !strings.Contains(step.If, "inputs.publish") {
				t.Error("publication must require tag push or explicit dispatch publish")
			}
		}
	}
	if upload < 0 || publish <= upload {
		t.Fatal("publication must follow successful asset upload")
	}
}

// TestMacStarterBrowserSelection mocks macOS commands so no GUI is launched.
func TestMacStarterBrowserSelection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unixシェル環境で検証する起動スクリプト（Linux/Macで実行）")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	body, err := os.ReadFile("packaging/macos/Start.command")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, manager           string
		env                     []string
		launchFailure, wantOpen bool
	}{
		{name: "local desktop", manager: "Aqua", wantOpen: true},
		{name: "explicit headless", manager: "Aqua", env: []string{"SECURITY_NOTICE_NO_BROWSER=1"}},
		{name: "SSH connection", manager: "Aqua", env: []string{"SSH_CONNECTION=remote local"}},
		{name: "SSH client", manager: "Aqua", env: []string{"SSH_CLIENT=remote"}},
		{name: "SSH terminal", manager: "Aqua", env: []string{"SSH_TTY=/dev/ttys000"}},
		{name: "background domain", manager: "Background"},
		{name: "system domain", manager: "System"},
		{name: "launchctl failure", manager: "Aqua", launchFailure: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, content string) string {
				t.Helper()
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(content), 0700); err != nil {
					t.Fatal(err)
				}
				return path
			}
			write("config.yaml.example", "web: {host: 127.0.0.1, port: 8999}\n")
			write("dependabot-alert-notice", `#!/bin/bash
for arg in "$@"; do
 if [ "$arg" = --web-url ]; then printf 'http://127.0.0.1:8999\n'; exit 0; fi
done
sleep 1
`)
			open := write("mock-open", "#!/bin/bash\nprintf called > \"$MOCK_OPEN_LOG\"\n")
			curl := write("mock-curl", "#!/bin/bash\nexit 0\n")
			exitCode := "0"
			if tt.launchFailure {
				exitCode = "1"
			}
			launchctl := write("mock-launchctl", "#!/bin/bash\nprintf '%s\\n' '"+tt.manager+"'\nexit "+exitCode+"\n")
			script := strings.NewReplacer("/usr/bin/open", open, "/usr/bin/curl", curl, "/bin/launchctl", launchctl).Replace(string(body))
			starter := write("Start.command", script)
			log := filepath.Join(dir, "open.log")
			cmd := exec.Command(bash, starter)
			for _, v := range os.Environ() {
				key, _, _ := strings.Cut(v, "=")
				switch key {
				case "SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "SECURITY_NOTICE_NO_BROWSER", "SECURITY_NOTICE_DATA_DIR", "SECURITY_NOTICE_AUTO_UPDATE", "MOCK_OPEN_LOG":
					continue
				}
				cmd.Env = append(cmd.Env, v)
			}
			cmd.Env = append(cmd.Env, "SECURITY_NOTICE_DATA_DIR="+filepath.Join(dir, "data"), "SECURITY_NOTICE_AUTO_UPDATE=0", "MOCK_OPEN_LOG="+log)
			cmd.Env = append(cmd.Env, tt.env...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("starter: %v\n%s", err, output)
			}
			_, err = os.Stat(log)
			opened := err == nil
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if opened != tt.wantOpen {
				t.Fatalf("browser opened = %t, want %t\n%s", opened, tt.wantOpen, output)
			}
		})
	}
}
