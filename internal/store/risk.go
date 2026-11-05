package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// DeadlineRecord is the persisted response target for one episode.
type DeadlineRecord struct {
	ProfileID   string
	AdvisoryKey string
	Episode     int
	OpenedAt    time.Time
	DueAt       time.Time
	Priority    string
	ClosedAt    *time.Time
}

// SaveRiskEvaluation persists a score and its response episode together.
func (s *Store) SaveRiskEvaluation(ctx context.Context, profileID, repo, advisoryKey, inputHash string, input model.ScoreInput, result model.ScoreResult, dueAt time.Time, resolved bool) (*DeadlineRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveRiskEvaluation(ctx, profileID, repo, advisoryKey, inputHash, input, result, dueAt, resolved)
}

func (s *Store) saveRiskEvaluation(ctx context.Context, profileID, repo, advisoryKey, inputHash string, input model.ScoreInput, result model.ScoreResult, dueAt time.Time, resolved bool) (*DeadlineRecord, error) {
	if input.At.IsZero() || (!resolved && dueAt.IsZero()) {
		return nil, fmt.Errorf("評価時刻または対応期限が未設定です")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("スコア保存トランザクション開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveScoreHistory(ctx, tx, profileID, repo, advisoryKey, inputHash, input, result); err != nil {
		return nil, err
	}
	record, err := latestDeadline(ctx, tx, profileID, advisoryKey)
	if err != nil {
		return nil, err
	}
	if resolved {
		if record != nil && record.ClosedAt == nil {
			closed := input.At.UTC()
			record.ClosedAt = &closed
		}
	} else if result.Status != "not_affected" && result.Status != "mitigated" {
		if record == nil || record.ClosedAt != nil {
			episode := 1
			if record != nil {
				episode = record.Episode + 1
			}
			record = &DeadlineRecord{ProfileID: profileID, AdvisoryKey: advisoryKey, Episode: episode, OpenedAt: input.At, DueAt: dueAt, Priority: result.Priority}
		} else {
			if dueAt.Before(record.DueAt) {
				record.DueAt = dueAt
			}
			record.Priority = result.Priority
		}
	}
	if record != nil {
		if err := saveDeadline(ctx, tx, *record); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("スコア保存確定失敗: %w", err)
	}
	return record, nil
}

func latestDeadline(ctx context.Context, tx *sql.Tx, profileID, advisoryKey string) (*DeadlineRecord, error) {
	record := DeadlineRecord{ProfileID: profileID, AdvisoryKey: advisoryKey}
	var opened, due string
	var closed sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT episode,opened_at,due_at,priority,closed_at FROM risk_deadlines WHERE profile_id=? AND advisory_key=? ORDER BY episode DESC LIMIT 1`, profileID, advisoryKey).Scan(&record.Episode, &opened, &due, &record.Priority, &closed)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("対応案件取得失敗: %w", err)
	}
	if record.OpenedAt, err = time.Parse(time.RFC3339Nano, opened); err != nil {
		return nil, fmt.Errorf("対応開始時刻解析失敗: %w", err)
	}
	if record.DueAt, err = time.Parse(time.RFC3339Nano, due); err != nil {
		return nil, fmt.Errorf("対応期限解析失敗: %w", err)
	}
	if closed.Valid {
		at, err := time.Parse(time.RFC3339Nano, closed.String)
		if err != nil {
			return nil, fmt.Errorf("対応終了時刻解析失敗: %w", err)
		}
		record.ClosedAt = &at
	}
	return &record, nil
}

// SaveDeadline preserves the earliest response target within an episode.
func (s *Store) SaveDeadline(ctx context.Context, record DeadlineRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("対応期限トランザクション開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveDeadline(ctx, tx, record); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("対応期限確定失敗: %w", err)
	}
	return nil
}

func saveDeadline(ctx context.Context, tx *sql.Tx, record DeadlineRecord) error {
	var previous string
	err := tx.QueryRowContext(ctx, `SELECT due_at FROM risk_deadlines WHERE profile_id=? AND advisory_key=? AND episode=?`, record.ProfileID, record.AdvisoryKey, record.Episode).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("既存対応期限取得失敗: %w", err)
	}
	if err == nil {
		due, err := time.Parse(time.RFC3339Nano, previous)
		if err != nil {
			return fmt.Errorf("既存対応期限解析失敗: %w", err)
		}
		if due.Before(record.DueAt) {
			record.DueAt = due
		}
	}
	var closed interface{}
	if record.ClosedAt != nil {
		closed = record.ClosedAt.UTC().Format(time.RFC3339Nano)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO risk_deadlines(profile_id,advisory_key,episode,opened_at,due_at,priority,closed_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(profile_id,advisory_key,episode) DO UPDATE SET due_at=excluded.due_at,priority=excluded.priority,closed_at=COALESCE(risk_deadlines.closed_at,excluded.closed_at)`, record.ProfileID, record.AdvisoryKey, record.Episode, record.OpenedAt.UTC().Format(time.RFC3339Nano), record.DueAt.UTC().Format(time.RFC3339Nano), record.Priority, closed)
	if err != nil {
		return fmt.Errorf("対応期限保存失敗: %w", err)
	}
	return nil
}

// SaveScoreHistory は直前と同じモデル・入力hashだけを省略し、状態遷移を保持する。
func (s *Store) SaveScoreHistory(ctx context.Context, profileID, repo, advisoryKey, inputHash string, input model.ScoreInput, result model.ScoreResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("スコア履歴トランザクション開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveScoreHistory(ctx, tx, profileID, repo, advisoryKey, inputHash, input, result); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("スコア履歴確定失敗: %w", err)
	}
	return nil
}

func saveScoreHistory(ctx context.Context, tx *sql.Tx, profileID, repo, advisoryKey, inputHash string, input model.ScoreInput, result model.ScoreResult) error {
	in, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("スコア入力シリアライズ失敗: %w", err)
	}
	out, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("スコア結果シリアライズ失敗: %w", err)
	}
	var previousVersion, previousHash string
	err = tx.QueryRowContext(ctx, `SELECT model_version,input_hash FROM score_history WHERE profile_id=? AND repo=? AND advisory_key=? ORDER BY id DESC LIMIT 1`, profileID, repo, advisoryKey).Scan(&previousVersion, &previousHash)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("スコア履歴重複確認失敗: %w", err)
	}
	if err == nil && previousVersion == result.ModelVersion && previousHash == inputHash {
		return nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO score_history(profile_id,repo,advisory_key,model_version,input_hash,computed_at,input_json,result_json) VALUES(?,?,?,?,?,?,?,?)`, profileID, repo, advisoryKey, result.ModelVersion, inputHash, input.At.UTC().Format(time.RFC3339Nano), string(in), string(out))
	if err != nil {
		return fmt.Errorf("スコア履歴保存失敗: %w", err)
	}
	return nil
}
