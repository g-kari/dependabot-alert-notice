package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ErrEvaluationInputsChanged rejects an in-flight result for changed alert data
// or a different reopened episode without discarding the previous evaluation.
var ErrEvaluationInputsChanged = errors.New("AI評価の入力が更新されました")

const evaluationCacheQuery = `SELECT eval_json FROM alert_records
	WHERE resolved_at IS NULL AND eval_status='done' AND eval_json IS NOT NULL
	AND json_extract(eval_json,'$.provenance.cache_key')=? ORDER BY id DESC LIMIT 1`

// FindEvaluationByKey reads one indexed, active result with matching trustworthy
// provenance and bounded age. Legacy rows stay readable but cannot be reused.
func (s *Store) FindEvaluationByKey(ctx context.Context, key string, now time.Time) (*model.Evaluation, error) {
	if key == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var body string
	err := s.db.QueryRowContext(ctx, evaluationCacheQuery, key).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("AI評価キャッシュ取得失敗: %w", err)
	}
	var result model.Evaluation
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return nil, fmt.Errorf("AI評価キャッシュ解析失敗: %w", err)
	}
	if result.Provenance == nil || result.Provenance.CacheKey != key || !result.Provenance.Reusable(now) {
		return nil, nil
	}
	result.Provenance.Reused = true
	return &result, nil
}

// SaveEvaluationIfCurrent atomically checks alert data and the episode before
// publishing evaluation columns only. Database display IDs are not input data.
func (s *Store) SaveEvaluationIfCurrent(ctx context.Context, expected *model.AlertRecord, evaluation *model.Evaluation) (bool, error) {
	if expected == nil || evaluation == nil {
		return false, fmt.Errorf("AI評価の入力または結果が未設定です")
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("AI評価保存中止: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.getUnlocked(expected.Alert.ID)
	if err != nil {
		return false, fmt.Errorf("AI評価保存前の入力取得失敗: %w", err)
	}
	if current.ResolvedAt != nil {
		return false, nil
	}
	before, after := expected.Alert, current.Alert
	before.ID, after.ID = 0, 0
	beforeJSON, err := json.Marshal(before)
	if err != nil {
		return false, fmt.Errorf("AI評価元入力の変換失敗: %w", err)
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		return false, fmt.Errorf("AI評価現在入力の変換失敗: %w", err)
	}
	if !bytes.Equal(beforeJSON, afterJSON) || !expected.NotifiedAt.Equal(current.NotifiedAt) {
		return false, ErrEvaluationInputsChanged
	}
	return s.saveEvaluationUnlocked(ctx, expected.Alert.ID, evaluation)
}
