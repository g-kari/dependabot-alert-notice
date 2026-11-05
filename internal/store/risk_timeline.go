package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ScoreHistoryRecord is a frozen, persisted evaluation with its provenance.
type ScoreHistoryRecord struct {
	ID         int
	ProfileID  string
	ComputedAt time.Time
	Input      model.ScoreInput
	Result     model.ScoreResult
}

// RiskTimeline contains bounded recent evaluations and response episodes.
type RiskTimeline struct {
	History   []ScoreHistoryRecord
	Deadlines []DeadlineRecord
	More      bool
}

// LoadRiskTimeline reads a repository/advisory's history without recalculating
// or modifying it. Empty history is distinct from a failed database operation.
func (s *Store) LoadRiskTimeline(ctx context.Context, repo, advisoryKey string, limit int) (RiskTimeline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var timeline RiskTimeline
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,profile_id,computed_at,input_json,result_json FROM score_history WHERE repo=? COLLATE NOCASE AND advisory_key=? ORDER BY id DESC LIMIT ?`, repo, advisoryKey, limit+1)
	if err != nil {
		return timeline, fmt.Errorf("評価履歴取得失敗: %w", err)
	}
	defer func(rows *sql.Rows) { _ = rows.Close() }(rows)
	for rows.Next() {
		var record ScoreHistoryRecord
		var at, input, result string
		if err := rows.Scan(&record.ID, &record.ProfileID, &at, &input, &result); err != nil {
			return timeline, fmt.Errorf("評価履歴読込失敗: %w", err)
		}
		if record.ComputedAt, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return timeline, fmt.Errorf("評価履歴日時解析失敗: %w", err)
		}
		if err := json.Unmarshal([]byte(input), &record.Input); err != nil {
			return timeline, fmt.Errorf("評価履歴入力解析失敗: %w", err)
		}
		if err := json.Unmarshal([]byte(result), &record.Result); err != nil {
			return timeline, fmt.Errorf("評価履歴結果解析失敗: %w", err)
		}
		timeline.History = append(timeline.History, record)
	}
	if err := rows.Err(); err != nil {
		return timeline, fmt.Errorf("評価履歴走査失敗: %w", err)
	}
	if err := rows.Close(); err != nil {
		return timeline, fmt.Errorf("評価履歴読込終了失敗: %w", err)
	}
	if len(timeline.History) > limit {
		timeline.More = true
		timeline.History = timeline.History[:limit]
	}
	rows, err = s.db.QueryContext(ctx, `SELECT profile_id,episode,opened_at,due_at,priority,closed_at FROM risk_deadlines WHERE advisory_key=? AND profile_id IN (SELECT DISTINCT profile_id FROM score_history WHERE repo=? COLLATE NOCASE AND advisory_key=?) ORDER BY profile_id,episode DESC LIMIT 100`, advisoryKey, repo, advisoryKey)
	if err != nil {
		return timeline, fmt.Errorf("対応案件取得失敗: %w", err)
	}
	defer func(rows *sql.Rows) { _ = rows.Close() }(rows)
	for rows.Next() {
		record := DeadlineRecord{AdvisoryKey: advisoryKey}
		var opened, due string
		var closed sql.NullString
		if err := rows.Scan(&record.ProfileID, &record.Episode, &opened, &due, &record.Priority, &closed); err != nil {
			return timeline, fmt.Errorf("対応案件読込失敗: %w", err)
		}
		if record.OpenedAt, err = time.Parse(time.RFC3339Nano, opened); err != nil {
			return timeline, fmt.Errorf("対応案件開始時刻解析失敗: %w", err)
		}
		if record.DueAt, err = time.Parse(time.RFC3339Nano, due); err != nil {
			return timeline, fmt.Errorf("対応案件期限解析失敗: %w", err)
		}
		if closed.Valid {
			at, err := time.Parse(time.RFC3339Nano, closed.String)
			if err != nil {
				return timeline, fmt.Errorf("対応案件終了時刻解析失敗: %w", err)
			}
			record.ClosedAt = &at
		}
		timeline.Deadlines = append(timeline.Deadlines, record)
	}
	if err := rows.Err(); err != nil {
		return timeline, fmt.Errorf("対応案件走査失敗: %w", err)
	}
	return timeline, nil
}
