package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

type Store struct {
	mu        sync.RWMutex
	db        *sql.DB
	logs      []model.LogEntry // ログはセッション限定のin-memory
	logSubs   []chan model.LogEntry
	logSubsMu sync.Mutex
}

// SubscribeLogs は新着ログを受け取るチャネルを登録する。呼び出し元はctx終了時に UnsubscribeLogs を呼ぶこと。
func (s *Store) SubscribeLogs() chan model.LogEntry {
	ch := make(chan model.LogEntry, 32)
	s.logSubsMu.Lock()
	s.logSubs = append(s.logSubs, ch)
	s.logSubsMu.Unlock()
	return ch
}

// UnsubscribeLogs はチャネルの登録を解除する。
func (s *Store) UnsubscribeLogs(ch chan model.LogEntry) {
	s.logSubsMu.Lock()
	defer s.logSubsMu.Unlock()
	for i, sub := range s.logSubs {
		if sub == ch {
			s.logSubs = append(s.logSubs[:i], s.logSubs[i+1:]...)
			close(ch)
			return
		}
	}
}

// New はin-memory SQLiteストアを返す（テスト用）
func New() *Store {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		panic(fmt.Sprintf("in-memory SQLite初期化失敗: %v", err))
	}
	// in-memoryはコネクション1本に固定しないと別コネクションから見えない
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		panic(fmt.Sprintf("マイグレーション失敗: %v", err))
	}
	return s
}

// NewWithPath はファイルベースのSQLiteストアを返す（起動後も状態を保持）
func NewWithPath(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("SQLiteオープン失敗: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("マイグレーション失敗: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS alert_records (
		id            INTEGER PRIMARY KEY,
		owner         TEXT NOT NULL,
		repo          TEXT NOT NULL,
		alert_json    TEXT NOT NULL,
		eval_json     TEXT,
		state         TEXT NOT NULL,
		eval_status   TEXT NOT NULL DEFAULT 'done',
		notified_at   DATETIME NOT NULL,
		merged_at     DATETIME
	)`)
	if err != nil {
		return err
	}
	// 既存DBへのカラム追加（エラーは無視: すでに存在する場合）
	_, _ = s.db.Exec(`ALTER TABLE alert_records ADD COLUMN eval_status TEXT NOT NULL DEFAULT 'done'`)
	return nil
}

func (s *Store) Save(record *model.AlertRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	alertJSON, _ := json.Marshal(record.Alert)

	var evalJSON sql.NullString
	if record.Evaluation != nil {
		b, _ := json.Marshal(record.Evaluation)
		evalJSON = sql.NullString{String: string(b), Valid: true}
	}

	var mergedAt sql.NullTime
	if record.MergedAt != nil {
		mergedAt = sql.NullTime{Time: *record.MergedAt, Valid: true}
	}

	evalStatus := string(record.EvalStatus)
	if evalStatus == "" {
		evalStatus = string(model.EvalStatusDone)
	}

	_, err := s.db.Exec(`INSERT OR REPLACE INTO alert_records
		(id, owner, repo, alert_json, eval_json, state, eval_status, notified_at, merged_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Alert.ID,
		record.Alert.Owner,
		record.Alert.Repo,
		string(alertJSON),
		evalJSON,
		string(record.State),
		evalStatus,
		record.NotifiedAt,
		mergedAt,
	)
	if err != nil {
		slog.Error("レコード保存失敗", "id", record.Alert.ID, "error", err)
	}
}

func (s *Store) Get(alertID int) (*model.AlertRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getUnlocked(alertID)
}

func (s *Store) getUnlocked(alertID int) (*model.AlertRecord, error) {
	row := s.db.QueryRow(`SELECT alert_json, eval_json, state, eval_status, notified_at, merged_at
		FROM alert_records WHERE id = ?`, alertID)

	var alertJSON string
	var evalJSON sql.NullString
	var state string
	var evalStatus string
	var notifiedAt time.Time
	var mergedAt sql.NullTime

	if err := row.Scan(&alertJSON, &evalJSON, &state, &evalStatus, &notifiedAt, &mergedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("アラートID %d が見つかりません", alertID)
		}
		return nil, err
	}

	var alert model.Alert
	_ = json.Unmarshal([]byte(alertJSON), &alert)

	var eval *model.Evaluation
	if evalJSON.Valid {
		eval = &model.Evaluation{}
		_ = json.Unmarshal([]byte(evalJSON.String), eval)
	}

	record := &model.AlertRecord{
		Alert:      alert,
		Evaluation: eval,
		State:      model.AlertState(state),
		EvalStatus: model.EvalStatus(evalStatus),
		NotifiedAt: notifiedAt,
	}
	if mergedAt.Valid {
		t := mergedAt.Time
		record.MergedAt = &t
	}
	return record, nil
}

func (s *Store) List() []*model.AlertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT alert_json, eval_json, state, eval_status, notified_at, merged_at FROM alert_records`)
	if err != nil {
		slog.Error("レコード一覧取得失敗", "error", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var records []*model.AlertRecord
	for rows.Next() {
		var alertJSON string
		var evalJSON sql.NullString
		var state string
		var evalStatus string
		var notifiedAt time.Time
		var mergedAt sql.NullTime

		if err := rows.Scan(&alertJSON, &evalJSON, &state, &evalStatus, &notifiedAt, &mergedAt); err != nil {
			continue
		}

		var alert model.Alert
		_ = json.Unmarshal([]byte(alertJSON), &alert)

		var eval *model.Evaluation
		if evalJSON.Valid {
			eval = &model.Evaluation{}
			_ = json.Unmarshal([]byte(evalJSON.String), eval)
		}

		record := &model.AlertRecord{
			Alert:      alert,
			Evaluation: eval,
			State:      model.AlertState(state),
			EvalStatus: model.EvalStatus(evalStatus),
			NotifiedAt: notifiedAt,
		}
		if mergedAt.Valid {
			t := mergedAt.Time
			record.MergedAt = &t
		}
		records = append(records, record)
	}
	return records
}

func (s *Store) Has(alertID int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM alert_records WHERE id = ?`, alertID).Scan(&count)
	return count > 0
}

func (s *Store) UpdateState(alertID int, state model.AlertState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var mergedAt sql.NullTime
	if state == model.AlertStateMerged {
		mergedAt = sql.NullTime{Time: time.Now(), Valid: true}
	}

	res, err := s.db.Exec(`UPDATE alert_records SET state = ?, merged_at = ? WHERE id = ?`,
		string(state), mergedAt, alertID)
	if err != nil {
		return fmt.Errorf("状態更新失敗: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("アラートID %d が見つかりません", alertID)
	}
	return nil
}

// ListPendingEvaluation はAI評価が必要なレコード（pending/failed）を最大limit件返す。
func (s *Store) ListPendingEvaluation(limit int) []*model.AlertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT alert_json, eval_json, state, eval_status, notified_at, merged_at
		FROM alert_records
		WHERE eval_status IN ('pending', 'failed')
		LIMIT ?`, limit)
	if err != nil {
		slog.Error("評価待ちレコード取得失敗", "error", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var records []*model.AlertRecord
	for rows.Next() {
		var alertJSON string
		var evalJSON sql.NullString
		var state, evalStatus string
		var notifiedAt time.Time
		var mergedAt sql.NullTime

		if err := rows.Scan(&alertJSON, &evalJSON, &state, &evalStatus, &notifiedAt, &mergedAt); err != nil {
			continue
		}
		var alert model.Alert
		_ = json.Unmarshal([]byte(alertJSON), &alert)

		record := &model.AlertRecord{
			Alert:      alert,
			State:      model.AlertState(state),
			EvalStatus: model.EvalStatus(evalStatus),
			NotifiedAt: notifiedAt,
		}
		if mergedAt.Valid {
			t := mergedAt.Time
			record.MergedAt = &t
		}
		records = append(records, record)
	}
	return records
}

func (s *Store) UpdateEvalStatus(alertID int, status model.EvalStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`UPDATE alert_records SET eval_status = ? WHERE id = ?`,
		string(status), alertID)
	if err != nil {
		return fmt.Errorf("eval_status更新失敗: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("アラートID %d が見つかりません", alertID)
	}
	return nil
}

// NeedsEvaluation はアラートがAI評価を必要とするかどうかを返す。
// レコードが存在しない場合、または評価失敗(failed)の場合にtrueを返す。
func (s *Store) NeedsEvaluation(alertID int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var evalStatus string
	err := s.db.QueryRow(`SELECT eval_status FROM alert_records WHERE id = ?`, alertID).Scan(&evalStatus)
	if err == sql.ErrNoRows {
		return true
	}
	if err != nil {
		return false
	}
	return model.EvalStatus(evalStatus) == model.EvalStatusFailed
}

func (s *Store) AddLog(entry model.LogEntry) {
	s.mu.Lock()
	s.logs = append(s.logs, entry)
	s.mu.Unlock()

	// 購読者に通知（ブロックしない）
	s.logSubsMu.Lock()
	for _, ch := range s.logSubs {
		select {
		case ch <- entry:
		default:
		}
	}
	s.logSubsMu.Unlock()
}

func (s *Store) ListLogs() []model.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.LogEntry, len(s.logs))
	copy(result, s.logs)
	return result
}
