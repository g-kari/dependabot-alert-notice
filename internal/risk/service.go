// Package risk coordinates pure scoring with persistence and deadlines.
package risk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/scoring"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// Service evaluates a frozen input snapshot and records its history.
type Service struct {
	Store    *store.Store
	Calendar scoring.BusinessCalendar
	Now      func() time.Time
}

// Evaluate calculates and, when configured with a store, persists a semantic
// history row. The semantic hash excludes display time but includes normalized
// outcomes so expiry boundaries create a new history row.
func (s *Service) Evaluate(ctx context.Context, input model.ScoreInput, profileID, repo, advisoryKey string) (model.ScoreResult, error) {
	if err := ctx.Err(); err != nil {
		return model.ScoreResult{}, fmt.Errorf("スコア評価取消: %w", err)
	}
	now := s.Now
	if now == nil {
		now = time.Now
	}
	if input.At.IsZero() {
		input.At = now().UTC()
	}
	result, err := scoring.Calculate(input)
	if err != nil {
		return result, err
	}
	if s.Store != nil {
		hash, err := semanticHash(input, result)
		if err != nil {
			return result, err
		}
		dueAt := s.Deadline(nil, result, input.At)
		if _, err := s.Store.SaveRiskEvaluation(ctx, profileID, repo, advisoryKey, hash, input, result, dueAt, false); err != nil {
			return result, err
		}
	}
	return result, nil
}

func semanticHash(input model.ScoreInput, result model.ScoreResult) (string, error) {
	encoded, err := json.Marshal(struct {
		Profile    model.ServiceProfile
		Assessment model.CVEAssessment
		Threat     model.ThreatSnapshot
		Technical  model.TechnicalImpact
		CVSS       float64
		CVSSKnown  bool
		Result     model.ScoreResult
	}{input.Profile, input.Assessment, input.Threat, input.Technical, input.CVSS, input.CVSSKnown, result})
	if err != nil {
		return "", fmt.Errorf("スコア入力hash作成失敗: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// Deadline delegates to the pure deadline calculation for callers that need
// a response target alongside a score.
func (s *Service) Deadline(previous *time.Time, result model.ScoreResult, now time.Time) time.Time {
	return scoring.Deadline(previous, result, now, s.Calendar)
}
