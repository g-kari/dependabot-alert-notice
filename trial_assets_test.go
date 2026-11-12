package main

import (
	"os"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"gopkg.in/yaml.v3"
)

func TestTrialConfigHasNoLiveSourcesOrApproval(t *testing.T) {
	for _, key := range []string{"SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_WEBHOOK_URL"} {
		t.Setenv(key, "")
	}
	cfg, err := config.Load("packaging/trial/trial-config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Web.BrowserURL() != "http://127.0.0.1:18999" || len(cfg.Targets) != 0 || cfg.RSS.Enabled || cfg.Threat.Enabled || cfg.Evaluator.AutoEval || !cfg.Evaluator.Sandbox.Enabled || !cfg.DisableApproval || cfg.DataPath != "store.db" || cfg.Slack.BotToken != "" || cfg.Slack.AppToken != "" || cfg.Discord.WebhookURL != "" {
		t.Fatal("trial must be empty, offline by default, local-only and approval-disabled")
	}
	if cfg.GhPath != "./disabled-gh" || cfg.ClaudePath != "./disabled-claude" || cfg.CodexPath != "./disabled-codex" || cfg.Evaluator.Sandbox.ContainerPath != "./disabled-container" {
		t.Fatal("trial must not resolve installed or authenticated CLIs")
	}
}

func TestTrialConsumersUseFrozenBuildArtifactIdentity(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/trial.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	jobs := workflow["jobs"].(map[string]any)
	build := jobs["build"].(map[string]any)
	outputs := build["outputs"].(map[string]any)
	if outputs["artifact_name"] != "${{ steps.source.outputs.artifact_name }}" || outputs["build_attempt"] != "${{ steps.source.outputs.build_attempt }}" {
		t.Fatal("artifact identity and generation attempt must be producer outputs")
	}
	uploads := 0
	for _, raw := range build["steps"].([]any) {
		step := raw.(map[string]any)
		uses, _ := step["uses"].(string)
		if strings.HasPrefix(uses, "actions/upload-artifact@") {
			uploads++
			with := step["with"].(map[string]any)
			if with["name"] != "${{ steps.source.outputs.artifact_name }}" {
				t.Fatal("producer upload must use the same frozen identity as consumers")
			}
		}
	}
	if uploads != 1 {
		t.Fatal("build must upload exactly one frozen candidate artifact")
	}
	for _, name := range []string{"mac-smoke", "windows-smoke", "ready"} {
		job := jobs[name].(map[string]any)
		downloads := 0
		for _, raw := range job["steps"].([]any) {
			step := raw.(map[string]any)
			uses, _ := step["uses"].(string)
			if !strings.HasPrefix(uses, "actions/download-artifact@") {
				continue
			}
			downloads++
			with := step["with"].(map[string]any)
			if with["name"] != "${{ needs.build.outputs.artifact_name }}" {
				t.Errorf("%s must reuse its producer artifact on failed-jobs retries", name)
			}
		}
		if downloads != 1 {
			t.Errorf("%s must consume exactly one frozen candidate artifact", name)
		}
	}
}

func TestTrialWorkflowIsTaglessReadOnlyAndPostMergeGated(t *testing.T) {
	body, err := os.ReadFile(".github/workflows/trial.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow map[string]any
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	permissions := workflow["permissions"].(map[string]any)
	if len(permissions) != 1 || permissions["contents"] != "read" {
		t.Fatal("trial workflow must request contents: read only")
	}
	triggers := workflow["on"].(map[string]any)
	if len(triggers) != 2 {
		t.Fatal("trial workflow must trigger only on pull_request and main push")
	}
	if _, ok := triggers["pull_request"]; !ok {
		t.Fatal("pull_request verification is required")
	}
	push := triggers["push"].(map[string]any)
	branches := push["branches"].([]any)
	if len(push) != 1 || len(branches) != 1 || branches[0] != "main" {
		t.Fatal("trial push must use exact main commits and no tag trigger")
	}
	jobs := workflow["jobs"].(map[string]any)
	for _, raw := range jobs {
		job := raw.(map[string]any)
		if _, ok := job["permissions"]; ok {
			t.Fatal("trial jobs must not elevate permissions")
		}
	}
	ready := jobs["ready"].(map[string]any)
	needs := ready["needs"].([]any)
	if len(needs) != 3 || needs[0] != "build" || needs[1] != "mac-smoke" || needs[2] != "windows-smoke" {
		t.Fatal("ready artifacts must wait for every native verification gate")
	}
	if ready["if"] != "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}" {
		t.Fatal("pull-request candidates must not become ready artifacts")
	}
	text := string(body)
	for _, forbidden := range []string{"secrets.", "contents: write", "pull_request_target", "workflow_dispatch", "gh release", "git tag ", "--allow-dirty"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("trial workflow contains forbidden operation %q", forbidden)
		}
	}
	for _, required := range []string{"github.event.pull_request.head.sha || github.sha", "persist-credentials: false", "goreleaser release --snapshot --clean", "version: v2.20.0", "go test ./... -race -count=1", "go test ./internal/updater/... -count=1", "go run ./cmd/package-macos", "retention-days: 1", "retention-days: 7", "python3 scripts/test_trial_tools.py", "native_binary_smoke", "'ui_runtime_verified': False", "shell: powershell", "$PSVersionTable.PSVersion.Major -ne 5"} {
		if !strings.Contains(text, required) {
			t.Errorf("trial workflow missing %q", required)
		}
	}
}
