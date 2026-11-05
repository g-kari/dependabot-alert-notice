package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/evaluator"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func evaluateResult(ctx context.Context, bound *evaluator.Session, s *store.Store, alert model.Alert, force bool) (*model.Evaluation, error) {
	if p := bound.Provenance(); !force && p != nil && p.CacheKey != "" {
		cached, err := s.FindEvaluationByKey(ctx, p.CacheKey, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		if cached != nil {
			slog.Info("一致するAI評価を再利用", "alertID", alert.ID, "provider", p.Provider, "model", p.Model, "inputHash", p.InputHash)
			return cached, nil
		}
	}
	return bound.Evaluate(ctx, alert)
}

func evaluationFailed(s *store.Store, alertID int, err error) error {
	slog.Error("AI評価失敗", "alertID", alertID, "error", err)
	s.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "error", AlertID: alertID, Message: fmt.Sprintf("AI評価失敗 (#%d): %v", alertID, err)})
	if statusErr := s.UpdateEvalStatus(alertID, model.EvalStatusFailed); statusErr != nil {
		return fmt.Errorf("AI評価失敗: %w", errors.Join(err, statusErr))
	}
	return fmt.Errorf("AI評価失敗: %w", err)
}
