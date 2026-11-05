package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ErrEvaluatorChanged prevents a result from a replaced evaluator being
// published as a current evaluation.
var ErrEvaluatorChanged = errors.New("AI評価先が変更されました")

const promptVersion = "dependabot-ja-v3-aws"

// IdentitySource supplies application-owned identity, not model output.
// Evaluators without this interface remain usable but their results are not cached.
type IdentitySource interface {
	Identity(model.Alert) *model.EvaluationProvenance
}

// Session freezes the evaluator and identity used for one inference/cache lookup.
type Session struct {
	evaluator  Evaluator
	switcher   *Switcher
	generation uint64
	provenance *model.EvaluationProvenance
	inputHash  string
}

// Capture atomically binds the current provider before looking up its cache.
func Capture(e Evaluator, alert model.Alert) *Session {
	session := &Session{evaluator: e, inputHash: digest(buildPrompt(alert))}
	if switcher, ok := e.(*Switcher); ok {
		switcher.mu.RLock()
		session.evaluator = switcher.current
		session.generation = switcher.generation
		session.switcher = switcher
		switcher.mu.RUnlock()
	}
	if source, ok := session.evaluator.(IdentitySource); ok {
		if p := source.Identity(alert); p != nil {
			copy := *p
			copy.CacheKey = copy.Key()
			copy.EvaluatedAt, copy.Reused = time.Time{}, false
			session.provenance = &copy
		}
	}
	return session
}

// Provenance returns a detached identity. Empty CacheKey disables reuse.
func (s *Session) Provenance() *model.EvaluationProvenance {
	if s.provenance == nil {
		return nil
	}
	copy := *s.provenance
	return &copy
}

// Evaluate uses the frozen provider and replaces any model-supplied provenance.
func (s *Session) Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error) {
	if s.inputHash != digest(buildPrompt(alert)) {
		return nil, fmt.Errorf("固定したAI評価入力と実行入力が一致しません")
	}
	if s.evaluator == nil {
		return nil, fmt.Errorf("AI評価先が未設定です")
	}
	result, err := s.evaluator.Evaluate(ctx, alert)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("AI評価結果が未設定です")
	}
	copy := *result
	copy.Provenance = s.Provenance()
	if copy.Provenance != nil {
		copy.Provenance.EvaluatedAt = time.Now().UTC()
	}
	return &copy, nil
}

// WithCurrent protects a short publication against concurrent provider changes.
// It does not hold the lock during inference or external notifications.
func (s *Session) WithCurrent(publish func() error) error {
	if s.switcher == nil {
		return publish()
	}
	s.switcher.mu.RLock()
	defer s.switcher.mu.RUnlock()
	if s.generation != s.switcher.generation {
		return ErrEvaluatorChanged
	}
	return publish()
}

func identity(alert model.Alert, provider, selectedModel, mode, runtime string) *model.EvaluationProvenance {
	p := &model.EvaluationProvenance{Provider: provider, Model: selectedModel, Mode: mode, RuntimeHash: digest(runtime), PromptVersion: promptVersion, InputHash: digest(buildPrompt(alert))}
	p.CacheKey = p.Key()
	return p
}

func digest(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

// Identity identifies the direct Claude model and command.
func (e *DirectEvaluator) Identity(alert model.Alert) *model.EvaluationProvenance {
	return identity(alert, "claude", e.model, "direct", e.claudePath)
}

// Identity identifies the isolated Claude model and image/auth location.
func (e *DockerEvaluator) Identity(alert model.Alert) *model.EvaluationProvenance {
	return identity(alert, "claude", e.cfg.ClaudeModel, "sandbox", containerRuntime(e.cfg.Sandbox.Runtime)+"\x00"+e.cfg.Sandbox.Image+"\x00"+e.cfg.Sandbox.ClaudeHome)
}

// Identity identifies the Codex model and direct command or isolated image.
func (e *CodexEvaluator) Identity(alert model.Alert) *model.EvaluationProvenance {
	mode, runtime := "direct", e.path
	if e.cfg.Sandbox.Enabled {
		mode, runtime = "sandbox", e.cfg.Sandbox.CodexImage
		if runtime == "" {
			runtime = "dependabot-codex-evaluator:latest"
		}
		runtime = containerRuntime(e.cfg.Sandbox.Runtime) + "\x00" + runtime
	}
	return identity(alert, "codex", e.cfg.CodexModel, mode, runtime)
}
