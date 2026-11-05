package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// RemoveResolvedAlerts preserves legacy callers while archiving, not deleting,
// alerts confirmed absent from a complete repository snapshot.
func (s *Store) RemoveResolvedAlerts(owner, repo string, openNumbers []int) []*model.AlertRecord {
	records, err := s.ResolveMissingAlerts(context.Background(), owner, repo, openNumbers, time.Now().UTC())
	if err != nil {
		slog.Error("解決済みアラート保存失敗", "error", err)
	}
	return records
}

// ResolveMissingAlerts atomically archives absent alerts and closes their risk
// episodes only when no other open alert for the same CVE remains. Callers must
// establish that the repository snapshot is complete and monitoring is enabled.
func (s *Store) ResolveMissingAlerts(ctx context.Context, owner, repo string, openNumbers []int, at time.Time) ([]*model.AlertRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" || at.IsZero() {
		return nil, fmt.Errorf("解決済み判定のリポジトリまたは時刻が未設定です")
	}
	if openNumbers == nil {
		openNumbers = []int{}
	}
	openJSON, err := json.Marshal(openNumbers)
	if err != nil {
		return nil, fmt.Errorf("取得済み番号の変換失敗: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("解決済み保存開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id,alert_json,eval_json,state,eval_status,notified_at,merged_at,slack_message_ts,discord_message_id FROM alert_records WHERE owner=? COLLATE NOCASE AND repo=? COLLATE NOCASE AND resolved_at IS NULL AND number NOT IN (SELECT value FROM json_each(?)) ORDER BY id`, owner, repo, string(openJSON))
	if err != nil {
		return nil, fmt.Errorf("解決対象取得失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var records []*model.AlertRecord
	var ids []int
	for rows.Next() {
		rec := &model.AlertRecord{}
		var id int
		var alertJSON, state, status string
		var evaluation sql.NullString
		var merged sql.NullTime
		if err := rows.Scan(&id, &alertJSON, &evaluation, &state, &status, &rec.NotifiedAt, &merged, &rec.SlackMessageTS, &rec.DiscordMessageID); err != nil {
			return nil, fmt.Errorf("解決対象読込失敗: %w", err)
		}
		if err := json.Unmarshal([]byte(alertJSON), &rec.Alert); err != nil {
			return nil, fmt.Errorf("解決対象アラート解析失敗: %w", err)
		}
		rec.Alert.ID = id
		rec.State = model.AlertState(state)
		rec.EvalStatus = model.EvalStatus(status)
		if evaluation.Valid {
			rec.Evaluation = &model.Evaluation{}
			if err := json.Unmarshal([]byte(evaluation.String), rec.Evaluation); err != nil {
				return nil, fmt.Errorf("解決対象評価解析失敗: %w", err)
			}
		}
		if merged.Valid {
			v := merged.Time
			rec.MergedAt = &v
		}
		closed := at.UTC()
		rec.ResolvedAt = &closed
		records = append(records, rec)
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("解決対象走査失敗: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("解決対象読込終了失敗: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	idJSON, err := json.Marshal(ids)
	if err != nil {
		return nil, fmt.Errorf("解決対象ID変換失敗: %w", err)
	}
	closedAt := at.UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `UPDATE alert_records SET resolved_at=? WHERE id IN (SELECT value FROM json_each(?))`, closedAt, string(idJSON)); err != nil {
		return nil, fmt.Errorf("解決日時保存失敗: %w", err)
	}
	for _, rec := range records {
		key := model.AdvisoryKey(rec.Alert)
		if cve := strings.ToUpper(strings.TrimSpace(rec.Alert.CVEID)); cve != "" {
			key = "cve:" + cve
			var active int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM alert_records WHERE owner=? COLLATE NOCASE AND repo=? COLLATE NOCASE AND resolved_at IS NULL AND UPPER(json_extract(alert_json,'$.CVEID'))=?`, owner, repo, cve).Scan(&active); err != nil {
				return nil, fmt.Errorf("未解決CVE確認失敗: %w", err)
			}
			if active > 0 {
				continue
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE risk_deadlines SET closed_at=? WHERE closed_at IS NULL AND advisory_key=? AND profile_id IN (SELECT profile_id FROM score_history WHERE repo=? COLLATE NOCASE AND advisory_key=?)`, closedAt, key, owner+"/"+repo, key); err != nil {
			return nil, fmt.Errorf("対応案件終了保存失敗: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("解決済み保存確定失敗: %w", err)
	}
	s.riskChangedLocked(RiskScope{Repos: []string{owner + "/" + repo}})
	return records, nil
}

// SaveEvaluationIfActive publishes an evaluation only while the alert is still
// unresolved. It never overwrites the alert payload or reopens an archived row.
func (s *Store) SaveEvaluationIfActive(ctx context.Context, alertID int, evaluation *model.Evaluation) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveEvaluationUnlocked(ctx, alertID, evaluation)
}

func (s *Store) saveEvaluationUnlocked(ctx context.Context, alertID int, evaluation *model.Evaluation) (bool, error) {
	if evaluation == nil {
		return false, fmt.Errorf("AI評価結果が未設定です")
	}
	body, err := json.Marshal(evaluation)
	if err != nil {
		return false, fmt.Errorf("AI評価結果の変換失敗: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE alert_records SET eval_json=?,eval_status='done' WHERE id=? AND resolved_at IS NULL`, string(body), alertID)
	if err != nil {
		return false, fmt.Errorf("AI評価結果保存失敗: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("AI評価結果保存件数確認失敗: %w", err)
	}
	return n > 0, nil
}
