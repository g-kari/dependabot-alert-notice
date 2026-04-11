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
	mu   sync.RWMutex
	db   *sql.DB
	logs []model.LogEntry // ログはセッション限定のin-memory
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
		notified_at   DATETIME NOT NULL,
		merged_at     DATETIME
	)`)
	return err
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

	_, err := s.db.Exec(`INSERT OR REPLACE INTO alert_records
		(id, owner, repo, alert_json, eval_json, state, notified_at, merged_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		record.Alert.ID,
		record.Alert.Owner,
		record.Alert.Repo,
		string(alertJSON),
		evalJSON,
		string(record.State),
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
	row := s.db.QueryRow(`SELECT alert_json, eval_json, state, notified_at, merged_at
		FROM alert_records WHERE id = ?`, alertID)

	var alertJSON string
	var evalJSON sql.NullString
	var state string
	var notifiedAt time.Time
	var mergedAt sql.NullTime

	if err := row.Scan(&alertJSON, &evalJSON, &state, &notifiedAt, &mergedAt); err != nil {
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

	rows, err := s.db.Query(`SELECT alert_json, eval_json, state, notified_at, merged_at FROM alert_records`)
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
		var notifiedAt time.Time
		var mergedAt sql.NullTime

		if err := rows.Scan(&alertJSON, &evalJSON, &state, &notifiedAt, &mergedAt); err != nil {
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

func (s *Store) AddLog(entry model.LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, entry)
}

func (s *Store) ListLogs() []model.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.LogEntry, len(s.logs))
	copy(result, s.logs)
	return result
}
