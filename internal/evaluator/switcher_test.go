package evaluator

import (
	"context"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

type stubEvaluator struct{ recommendation string }

func (s stubEvaluator) Evaluate(_ context.Context, _ model.Alert) (*model.Evaluation, error) {
	return &model.Evaluation{Recommendation: s.recommendation}, nil
}

func TestSwitcher_UsesUpdatedProvider(t *testing.T) {
	s := NewSwitcher(stubEvaluator{recommendation: "approve"})
	s.Set(stubEvaluator{recommendation: "manual-review"})
	got, err := s.Evaluate(context.Background(), model.Alert{})
	if err != nil || got.Recommendation != "manual-review" {
		t.Fatalf("Evaluate() = %+v, %v", got, err)
	}
}
