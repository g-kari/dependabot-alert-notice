package evaluator

import (
	"context"
	"sync"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// Switcher は実行中のアプリでAI評価先を安全に切り替える。
type Switcher struct {
	mu         sync.RWMutex
	current    Evaluator
	generation uint64
}

// NewSwitcher は初期評価先を持つSwitcherを返す。
func NewSwitcher(initial Evaluator) *Switcher { return &Switcher{current: initial} }

// Set は次のAI評価から使う評価先を更新する。
func (s *Switcher) Set(next Evaluator) {
	s.mu.Lock()
	s.current = next
	s.generation++
	s.mu.Unlock()
}

// Evaluate は現在の評価先でアラートを評価する。
func (s *Switcher) Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error) {
	return Capture(s, alert).Evaluate(ctx, alert)
}
