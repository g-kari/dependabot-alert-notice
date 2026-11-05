package evaluator

import (
	"context"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestNew_SelectsCodexProvider(t *testing.T) {
	cfg := &config.Config{CodexPath: "codex", Evaluator: config.EvaluatorConfig{Provider: "codex", Sandbox: config.SandboxConfig{Enabled: true, CodexImage: "codex-evaluator:test"}}}
	if _, ok := New(cfg).(*CodexEvaluator); !ok {
		t.Fatalf("New() = %T, want *CodexEvaluator", New(cfg))
	}
}

func TestCodexEvaluator_EvaluatesInEmptyReadOnlyWorkspace(t *testing.T) {
	cfg := config.EvaluatorConfig{Provider: "codex", CodexModel: "gpt-6-sol", Sandbox: config.SandboxConfig{Enabled: false}}
	e := &CodexEvaluator{cfg: cfg, path: "codex"}
	e.run = func(_ context.Context, spec codexCommand) ([]byte, error) {
		if spec.Name != "codex" || spec.Dir == "" {
			t.Errorf("command name=%q, dir=%q", spec.Name, spec.Dir)
		}
		joined := strings.Join(spec.Args, " ")
		for _, flag := range []string{"exec", "--sandbox read-only", "--skip-git-repo-check", "--ephemeral", "--ignore-user-config", "--json", "-m gpt-6-sol", " -"} {
			if !strings.Contains(" "+joined, flag) {
				t.Errorf("missing %q in args: %s", flag, joined)
			}
		}
		if !strings.Contains(spec.Input, "pkg-test") || strings.Contains(joined, "pkg-test") {
			t.Error("alert should be sent through stdin, not command arguments")
		}
		return []byte("{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"{\\\"impact\\\":\\\"impact\\\",\\\"recommendation\\\":\\\"manual-review\\\",\\\"reasoning\\\":\\\"reason\\\"}\"}}\n{\"type\":\"turn.completed\"}\n"), nil
	}
	result, err := e.Evaluate(context.Background(), model.Alert{PackageName: "pkg-test"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Recommendation != "manual-review" {
		t.Fatalf("recommendation=%q", result.Recommendation)
	}
}

func TestCodexEvaluator_DockerKeepsIsolation(t *testing.T) {
	e := &CodexEvaluator{cfg: config.EvaluatorConfig{CodexModel: "gpt-6-sol", Sandbox: config.SandboxConfig{Enabled: true, CodexImage: "codex-evaluator:test", MemoryLimit: "512m", CPULimit: "0.5"}}}
	spec := e.dockerCommand("prompt", "C:/Users/test/.codex")
	joined := strings.Join(spec.Args, " ")
	for _, flag := range []string{"--read-only", "--security-opt=no-new-privileges", "--cap-drop=ALL", "--memory=512m", "--cpus=0.5", ":/home/node/.codex:ro", "codex-evaluator:test", "--sandbox read-only", "--ephemeral", "-m gpt-6-sol"} {
		if !strings.Contains(joined, flag) {
			t.Errorf("missing %q in Docker args: %s", flag, joined)
		}
	}
}

func TestParseCodexOutput_RequiresSuccessfulFinalMessage(t *testing.T) {
	for _, output := range []string{"{\"type\":\"turn.failed\"}\n", "{\"type\":\"turn.completed\"}\n", "not json\n"} {
		if _, err := parseCodexOutput([]byte(output)); err == nil {
			t.Errorf("parseCodexOutput(%q) should fail", output)
		}
	}
}
