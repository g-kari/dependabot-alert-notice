package evaluator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestPodmanCommandFailureNeverFallsBack(t *testing.T) {
	cfg := config.Defaults().Evaluator
	cfg.Sandbox.Runtime = "podman"
	calls := 0
	runner := func(_ context.Context, spec codexCommand) ([]byte, error) {
		calls++
		if spec.Name != "podman" {
			t.Errorf("fallback command=%s", spec.Name)
		}
		return nil, errors.New("fixture runtime failure")
	}
	claude := &DockerEvaluator{cfg: cfg, run: runner}
	if _, err := claude.Evaluate(context.Background(), model.Alert{}); err == nil || calls != 1 {
		t.Fatalf("claude calls=%d err=%v", calls, err)
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "auth.json"), []byte(`{"fixture":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", home)
	calls = 0
	codex := &CodexEvaluator{cfg: cfg, run: runner}
	if _, err := codex.Evaluate(context.Background(), model.Alert{}); err == nil || calls != 1 {
		t.Fatalf("codex calls=%d err=%v", calls, err)
	}
}

func TestPodmanSelectionIsolationAndIdentity(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Evaluator.Provider = provider
			cfg.Evaluator.ClaudeModel, cfg.Evaluator.CodexModel = "test-model", "test-model"
			cfg.Evaluator.Sandbox.Runtime = "podman"
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			selected := newEvaluator(cfg, "darwin", "arm64")
			var args []string
			switch e := selected.(type) {
			case *DockerEvaluator:
				args = e.buildDockerArgs("prompt", "/dummy/.claude")
			case *CodexEvaluator:
				spec := e.dockerCommand("prompt", "/dummy/.codex")
				if spec.Name != "podman" {
					t.Fatalf("command = %s", spec.Name)
				}
				args = spec.Args
			default:
				t.Fatalf("unexpected evaluator %T", selected)
			}
			joined := strings.Join(args, " ")
			for _, flag := range []string{"--userns=keep-id:uid=1000,gid=1000", "--user=1000:1000", ":ro", "--read-only", "--tmpfs", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=512m", "--cpus=0.5"} {
				if !strings.Contains(joined, flag) {
					t.Errorf("missing %s: %s", flag, joined)
				}
			}
			podman := Capture(selected, model.Alert{}).Provenance().CacheKey
			cfg.Evaluator.Sandbox.Runtime = "docker"
			if podman == Capture(newEvaluator(cfg, "darwin", "arm64"), model.Alert{}).Provenance().CacheKey {
				t.Fatal("runtime must change cache identity")
			}
			cfg.Evaluator.Sandbox.Runtime = "podman"
			cfg.Evaluator.Sandbox.Enabled = false
			if _, err := newEvaluator(cfg, "darwin", "arm64").Evaluate(context.Background(), model.Alert{}); err == nil {
				t.Fatal("disabled isolation accepted")
			}
		})
	}
}

func TestAWSPromptAndBackwardCompatibleResult(t *testing.T) {
	prompt := buildPrompt(model.Alert{})
	for _, word := range []string{"aws_risk", "実際のAWS構成は取得していません", "条件", "影響", "確認", "対策", "IAM", "メタデータ", "CI", "関係する"} {
		if !strings.Contains(prompt, word) {
			t.Errorf("prompt missing %q", word)
		}
	}
	if promptVersion == "dependabot-ja-v2" {
		t.Fatal("old prompt version reused")
	}
	cfg := config.Defaults()
	cfg.Evaluator.CodexModel = "fixture-model"
	cfg.Evaluator.Provider = "codex"
	current := Capture(New(cfg), model.Alert{}).Provenance()
	oldIdentity := *current
	oldIdentity.PromptVersion = "dependabot-ja-v2"
	if oldIdentity.Key() == current.CacheKey {
		t.Fatal("old AWS-less cache can be reused")
	}
	result, err := parseEvaluation([]byte(`{"impact":"a","reasoning":"b","aws_risk":"条件付きの評価"}`))
	if err != nil || result.AWSRisk != "条件付きの評価" {
		t.Fatalf("AWS result = %+v, %v", result, err)
	}
	old, err := parseEvaluation([]byte(`{"impact":"a","reasoning":"b"}`))
	if err != nil || old.AWSRisk != "" {
		t.Fatalf("legacy result = %+v, %v", old, err)
	}
}
