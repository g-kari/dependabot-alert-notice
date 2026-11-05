package evaluator

import (
	"context"
	"errors"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestEvaluationIdentityIncludesPromptInputAndExecutionSettings(t *testing.T) {
	cfg := config.Config{ClaudePath: "claude", CodexPath: "codex", Evaluator: config.EvaluatorConfig{Provider: "codex", CodexModel: "model-a", ClaudeModel: "model-a"}}
	alert := model.Alert{Owner: "org", Repo: "api", PackageName: "pkg", CVEID: "CVE-2026-1234", GHSAID: "GHSA-abcd", FixedIn: "2.0", Severity: model.SeverityHigh}
	base := Capture(New(&cfg), alert).Provenance()
	if base == nil || base.CacheKey == "" {
		t.Fatal("explicit model must have cache identity")
	}
	for _, field := range []string{"owner", "repo", "package", "ecosystem", "severity", "cve", "ghsa", "cvss", "cvss_known", "summary", "fixed", "range", "manifest", "scope", "provider", "model", "sandbox", "image", "path"} {
		t.Run(field, func(t *testing.T) {
			nextCfg, nextAlert := cfg, alert
			switch field {
			case "owner":
				nextAlert.Owner = "other"
			case "repo":
				nextAlert.Repo = "worker"
			case "package":
				nextAlert.PackageName = "other"
			case "ecosystem":
				nextAlert.PackageEcosystem = "npm"
			case "severity":
				nextAlert.Severity = model.SeverityCritical
			case "cve":
				nextAlert.CVEID = "CVE-2026-5678"
			case "ghsa":
				nextAlert.GHSAID = "GHSA-efgh"
			case "cvss":
				nextAlert.CVSSScore = 9.8
			case "cvss_known":
				nextAlert.CVSSKnown = true
			case "summary":
				nextAlert.Summary = "changed"
			case "fixed":
				nextAlert.FixedIn = "3.0"
			case "range":
				nextAlert.VulnerableVersionRange = "< 2.0"
			case "manifest":
				nextAlert.ManifestPath = "app/package.json"
			case "scope":
				nextAlert.DependencyScope = "runtime"
			case "provider":
				nextCfg.Evaluator.Provider = "claude"
			case "model":
				nextCfg.Evaluator.CodexModel = "model-b"
			case "sandbox":
				nextCfg.Evaluator.Sandbox.Enabled = true
			case "image":
				nextCfg.Evaluator.Sandbox.Enabled = true
				nextCfg.Evaluator.Sandbox.CodexImage = "image-b"
			case "path":
				nextCfg.CodexPath = "other-codex"
			}
			got := Capture(New(&nextCfg), nextAlert).Provenance()
			if got == nil || got.CacheKey == base.CacheKey {
				t.Fatalf("%s did not change cache identity: %+v", field, got)
			}
		})
	}
	alert.ID, alert.Number = 900, 12
	if got := Capture(New(&cfg), alert).Provenance(); got.CacheKey != base.CacheKey {
		t.Fatal("display IDs must not invalidate identical evaluation input")
	}
	cfg.Evaluator.CodexModel = ""
	if got := Capture(New(&cfg), alert).Provenance(); got == nil || got.CacheKey != "" {
		t.Fatalf("unresolved CLI default must not have reusable key: %+v", got)
	}
}

func TestCapturedEvaluatorDoesNotSwitchProviderMidEvaluation(t *testing.T) {
	s := NewSwitcher(stubEvaluator{recommendation: "approve"})
	bound := Capture(s, model.Alert{})
	s.Set(stubEvaluator{recommendation: "reject"})
	got, err := bound.Evaluate(context.Background(), model.Alert{})
	if err != nil || got.Recommendation != "approve" {
		t.Fatalf("captured provider switched: %+v err=%v", got, err)
	}
	called := false
	if err := bound.WithCurrent(func() error { called = true; return nil }); !errors.Is(err, ErrEvaluatorChanged) || called {
		t.Fatalf("stale generation published: called=%v err=%v", called, err)
	}
	if err := Capture(s, model.Alert{}).WithCurrent(func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("current generation failed: %v", err)
	}
}

type untrustedMetadataEvaluator struct{}

func (untrustedMetadataEvaluator) Evaluate(context.Context, model.Alert) (*model.Evaluation, error) {
	return &model.Evaluation{Recommendation: "approve", Provenance: &model.EvaluationProvenance{Provider: "spoofed"}}, nil
}

func TestUnknownEvaluatorCannotSupplyTrustedProvenance(t *testing.T) {
	s := Capture(untrustedMetadataEvaluator{}, model.Alert{})
	got, err := s.Evaluate(context.Background(), model.Alert{})
	if err != nil || got.Provenance != nil || s.Provenance() != nil {
		t.Fatalf("untrusted result supplied identity: %+v err=%v", got, err)
	}
}

func TestCapturedIdentityCannotBeUsedForDifferentInferenceInput(t *testing.T) {
	alert := model.Alert{Summary: "captured"}
	bound := Capture(stubEvaluator{recommendation: "approve"}, alert)
	alert.Summary = "different"
	if _, err := bound.Evaluate(context.Background(), alert); err == nil {
		t.Fatal("evaluation was labelled with identity for different input")
	}
}
