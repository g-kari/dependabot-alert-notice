package store

import (
	"context"
	"fmt"
)

// ClaimEvaluation atomically reserves an active alert for one queued evaluation.
func (s *Store) ClaimEvaluation(ctx context.Context, id int, allowCompleted bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `UPDATE alert_records SET eval_status='evaluating' WHERE id=? AND resolved_at IS NULL`
	if allowCompleted {
		query += ` AND eval_status!='evaluating'`
	} else {
		query += ` AND eval_status IN ('pending','failed')`
	}
	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return false, fmt.Errorf("AI評価予約失敗: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("AI評価予約件数取得失敗: %w", err)
	}
	return count == 1, nil
}
