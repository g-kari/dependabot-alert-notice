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
	notificationMu sync.Mutex
	mu             sync.RWMutex
	db             *sql.DB
	logs           []model.LogEntry // ログはセッション限定のin-memory
	logSubs        []chan model.LogEntry
	logSubsMu      sync.Mutex
	riskRevision   uint64
	riskSubs       map[chan RiskScope]struct{}
}

// Close releases the SQLite connection and is safe to call once during
// shutdown or test cleanup.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
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
	if _, err := s.db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("foreign key有効化失敗: %w", err)
	}
	// 旧スキーマ検出: 既存データを暗黙に削除せず、未知の形状は明示的に停止する。
	var tableCount int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alert_records'`).Scan(&tableCount)
	var numberColCount int
	_ = s.db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('alert_records') WHERE name = 'number'`,
	).Scan(&numberColCount)
	if tableCount > 0 && numberColCount == 0 {
		return fmt.Errorf("alert_recordsの未知スキーマです: number列がありません（既存データを保護するため変換しません）")
	}

	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS alert_records (
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		owner            TEXT NOT NULL,
		repo             TEXT NOT NULL,
		number           INTEGER NOT NULL,
		alert_json       TEXT NOT NULL,
		eval_json        TEXT,
		state            TEXT NOT NULL,
		eval_status      TEXT NOT NULL DEFAULT 'done',
		notified_at      DATETIME NOT NULL,
		merged_at        DATETIME,
		slack_message_ts TEXT NOT NULL DEFAULT '',
		UNIQUE(owner, repo, number)
	)`); err != nil {
		return err
	}

	// 既存テーブルへのカラム追加（slack_message_tsが存在しない場合）
	var slackTSColCount int
	_ = s.db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('alert_records') WHERE name = 'slack_message_ts'`,
	).Scan(&slackTSColCount)
	if slackTSColCount == 0 {
		if _, err := s.db.Exec(`ALTER TABLE alert_records ADD COLUMN slack_message_ts TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("slack_message_tsカラム追加失敗: %w", err)
		}
	}
	var resolvedColCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('alert_records') WHERE name='resolved_at'`).Scan(&resolvedColCount); err != nil {
		return fmt.Errorf("解決日時カラム確認失敗: %w", err)
	}
	if resolvedColCount == 0 {
		if _, err := s.db.Exec(`ALTER TABLE alert_records ADD COLUMN resolved_at TEXT`); err != nil {
			return fmt.Errorf("解決日時カラム追加失敗: %w", err)
		}
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS rss_items (id INTEGER PRIMARY KEY AUTOINCREMENT, feed_url TEXT NOT NULL, external_id TEXT NOT NULL, title TEXT NOT NULL, link TEXT NOT NULL, summary TEXT NOT NULL, published_at TEXT, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, UNIQUE(feed_url, external_id))`); err != nil {
		return fmt.Errorf("RSS記事テーブル作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS rss_item_cves (item_id INTEGER NOT NULL REFERENCES rss_items(id) ON DELETE CASCADE, cve_id TEXT NOT NULL, PRIMARY KEY(item_id,cve_id))`); err != nil {
		return fmt.Errorf("RSS CVE索引作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS rss_cve_lookup ON rss_item_cves(cve_id,item_id)`); err != nil {
		return fmt.Errorf("RSS CVE索引作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS rss_feed_status (feed_url TEXT PRIMARY KEY, last_attempt_at TEXT, last_success_at TEXT, last_error TEXT NOT NULL DEFAULT '', item_count INTEGER NOT NULL DEFAULT 0, etag TEXT NOT NULL DEFAULT '', last_modified TEXT NOT NULL DEFAULT '', next_attempt_at TEXT)`); err != nil {
		return fmt.Errorf("RSS状態テーブル作成失敗: %w", err)
	}
	var nextAttemptColCount int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('rss_feed_status') WHERE name = 'next_attempt_at'`).Scan(&nextAttemptColCount)
	if nextAttemptColCount == 0 {
		if _, err := s.db.Exec(`ALTER TABLE rss_feed_status ADD COLUMN next_attempt_at TEXT`); err != nil {
			return fmt.Errorf("next_attempt_atカラム追加失敗: %w", err)
		}
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS score_history (id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id TEXT NOT NULL, repo TEXT NOT NULL, advisory_key TEXT NOT NULL, model_version TEXT NOT NULL, input_hash TEXT NOT NULL, computed_at TEXT NOT NULL, input_json TEXT NOT NULL, result_json TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("スコア履歴テーブル作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS score_history_lookup ON score_history(profile_id, advisory_key, id DESC)`); err != nil {
		return fmt.Errorf("スコア履歴索引作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS score_history_repo_lookup ON score_history(repo COLLATE NOCASE,advisory_key,id DESC)`); err != nil {
		return fmt.Errorf("リポジトリ評価履歴索引作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS app_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("migration管理テーブル作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS service_assessments (profile_id TEXT NOT NULL, advisory_key TEXT NOT NULL, config_revision INTEGER NOT NULL, body_json TEXT NOT NULL, PRIMARY KEY(profile_id, advisory_key))`); err != nil {
		return fmt.Errorf("assessmentテーブル作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS threat_snapshots (source TEXT NOT NULL, advisory_key TEXT NOT NULL, fetched_at TEXT NOT NULL, source_date TEXT, body_json TEXT NOT NULL, PRIMARY KEY(source, advisory_key))`); err != nil {
		return fmt.Errorf("脅威スナップショットテーブル作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS threat_advisory_lookup ON threat_snapshots(advisory_key)`); err != nil {
		return fmt.Errorf("脅威アドバイザリ索引作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS risk_deadlines (profile_id TEXT NOT NULL, advisory_key TEXT NOT NULL, episode INTEGER NOT NULL, opened_at TEXT NOT NULL, due_at TEXT NOT NULL, priority TEXT NOT NULL, closed_at TEXT, PRIMARY KEY(profile_id, advisory_key, episode))`); err != nil {
		return fmt.Errorf("期限テーブル作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO app_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("migration記録失敗: %w", err)
	}

	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS alert_cve_lookup ON alert_records(UPPER(json_extract(alert_json,'$.CVEID')))`); err != nil {
		return fmt.Errorf("アラートCVE索引作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS alert_evaluation_cache_lookup
		ON alert_records(json_extract(eval_json,'$.provenance.cache_key'),id DESC)
		WHERE resolved_at IS NULL AND eval_status='done' AND eval_json IS NOT NULL`); err != nil {
		return fmt.Errorf("AI評価キャッシュ索引作成失敗: %w", err)
	}

	// discord_message_id カラム追加
	var discordIDColCount int
	_ = s.db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('alert_records') WHERE name = 'discord_message_id'`,
	).Scan(&discordIDColCount)
	if discordIDColCount == 0 {
		if _, err := s.db.Exec(`ALTER TABLE alert_records ADD COLUMN discord_message_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("discord_message_idカラム追加失敗: %w", err)
		}
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS notification_groups (group_key TEXT PRIMARY KEY, message_id TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("通知グループテーブル作成失敗: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS notification_batches (group_key TEXT PRIMARY KEY, scope TEXT NOT NULL, owner TEXT NOT NULL, repo TEXT NOT NULL, fingerprint TEXT NOT NULL, sent_fingerprint TEXT NOT NULL DEFAULT '', due_at INTEGER)`); err != nil {
		return fmt.Errorf("通知待機テーブル作成失敗: %w", err)
	}
	return nil
}

// Save preserves resolved records against delayed evaluation writes.
func (s *Store) Save(record *model.AlertRecord) bool {
	return s.save(record, false)
}

// SaveObserved stores an alert confirmed open by a fresh GitHub fetch. A new
// or explicitly reopened record returns true and retains its stable database ID.
func (s *Store) SaveObserved(record *model.AlertRecord) bool {
	return s.save(record, true)
}

func (s *Store) save(record *model.AlertRecord, observed bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	var existingID int
	var resolved sql.NullString
	var existingBody string
	existingErr := s.db.QueryRow(`SELECT id,resolved_at,alert_json FROM alert_records WHERE owner=? AND repo=? AND number=?`, record.Alert.Owner, record.Alert.Repo, record.Alert.Number).Scan(&existingID, &resolved, &existingBody)
	if existingErr != nil && existingErr != sql.ErrNoRows {
		slog.Error("既存レコード確認失敗", "error", existingErr)
		return false
	}
	if resolved.Valid && !observed {
		return false
	}

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

	_, err := s.db.Exec(`INSERT INTO alert_records
		(owner, repo, number, alert_json, eval_json, state, eval_status, notified_at, merged_at, slack_message_ts, discord_message_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(owner, repo, number) DO UPDATE SET
			alert_json         = excluded.alert_json,
			eval_json          = excluded.eval_json,
			state              = excluded.state,
			eval_status        = excluded.eval_status,
			notified_at        = excluded.notified_at,
			merged_at          = excluded.merged_at,
			slack_message_ts   = excluded.slack_message_ts,
			discord_message_id = excluded.discord_message_id,
			resolved_at        = NULL`,
		record.Alert.Owner,
		record.Alert.Repo,
		record.Alert.Number,
		string(alertJSON),
		evalJSON,
		string(record.State),
		evalStatus,
		record.NotifiedAt,
		mergedAt,
		record.SlackMessageTS,
		record.DiscordMessageID,
	)
	if err != nil {
		slog.Error("レコード保存失敗", "owner", record.Alert.Owner, "repo", record.Alert.Repo, "number", record.Alert.Number, "error", err)
		return false
	}
	var dbID int
	if err2 := s.db.QueryRow(`SELECT id FROM alert_records WHERE owner = ? AND repo = ? AND number = ?`,
		record.Alert.Owner, record.Alert.Repo, record.Alert.Number).Scan(&dbID); err2 != nil {
		slog.Error("保存済みID取得失敗", "error", err2)
		return false
	}
	record.Alert.ID = dbID
	record.ResolvedAt = nil
	if existingErr == sql.ErrNoRows || resolved.Valid || existingBody != string(alertJSON) {
		s.riskChangedLocked(RiskScope{Repos: []string{record.Alert.Owner + "/" + record.Alert.Repo}})
	}
	return existingErr == sql.ErrNoRows || resolved.Valid
}

func (s *Store) Get(alertID int) (*model.AlertRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getUnlocked(alertID)
}

func (s *Store) getUnlocked(alertID int) (*model.AlertRecord, error) {
	row := s.db.QueryRow(`SELECT id, alert_json, eval_json, state, eval_status, notified_at, merged_at, slack_message_ts, discord_message_id, resolved_at
		FROM alert_records WHERE id = ?`, alertID)

	var dbID int
	var alertJSON string
	var evalJSON sql.NullString
	var state string
	var evalStatus string
	var notifiedAt time.Time
	var mergedAt sql.NullTime
	var slackTS string
	var discordMsgID string
	var resolved sql.NullString

	if err := row.Scan(&dbID, &alertJSON, &evalJSON, &state, &evalStatus, &notifiedAt, &mergedAt, &slackTS, &discordMsgID, &resolved); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("アラートID %d が見つかりません", alertID)
		}
		return nil, err
	}

	var alert model.Alert
	_ = json.Unmarshal([]byte(alertJSON), &alert)
	alert.ID = dbID

	var eval *model.Evaluation
	if evalJSON.Valid {
		eval = &model.Evaluation{}
		_ = json.Unmarshal([]byte(evalJSON.String), eval)
	}

	record := &model.AlertRecord{
		Alert:            alert,
		Evaluation:       eval,
		State:            model.AlertState(state),
		EvalStatus:       model.EvalStatus(evalStatus),
		NotifiedAt:       notifiedAt,
		SlackMessageTS:   slackTS,
		DiscordMessageID: discordMsgID,
	}
	if mergedAt.Valid {
		t := mergedAt.Time
		record.MergedAt = &t
	}
	if resolved.Valid {
		at, err := time.Parse(time.RFC3339Nano, resolved.String)
		if err != nil {
			return nil, fmt.Errorf("解決日時解析失敗: %w", err)
		}
		record.ResolvedAt = &at
	}
	return record, nil
}

func (s *Store) List() []*model.AlertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT id, alert_json, eval_json, state, eval_status, notified_at, merged_at, slack_message_ts, discord_message_id FROM alert_records WHERE resolved_at IS NULL`)
	if err != nil {
		slog.Error("レコード一覧取得失敗", "error", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var records []*model.AlertRecord
	for rows.Next() {
		var dbID int
		var alertJSON string
		var evalJSON sql.NullString
		var state string
		var evalStatus string
		var notifiedAt time.Time
		var mergedAt sql.NullTime
		var slackTS string
		var discordMsgID string

		if err := rows.Scan(&dbID, &alertJSON, &evalJSON, &state, &evalStatus, &notifiedAt, &mergedAt, &slackTS, &discordMsgID); err != nil {
			continue
		}

		var alert model.Alert
		_ = json.Unmarshal([]byte(alertJSON), &alert)
		alert.ID = dbID

		var eval *model.Evaluation
		if evalJSON.Valid {
			eval = &model.Evaluation{}
			_ = json.Unmarshal([]byte(evalJSON.String), eval)
		}

		record := &model.AlertRecord{
			Alert:            alert,
			Evaluation:       eval,
			State:            model.AlertState(state),
			EvalStatus:       model.EvalStatus(evalStatus),
			NotifiedAt:       notifiedAt,
			SlackMessageTS:   slackTS,
			DiscordMessageID: discordMsgID,
		}
		if mergedAt.Valid {
			t := mergedAt.Time
			record.MergedAt = &t
		}
		records = append(records, record)
	}
	return records
}

// HasByKey は (owner, repo, number) の未解決レコードが存在するか確認する。
func (s *Store) HasByKey(owner, repo string, number int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM alert_records WHERE owner = ? AND repo = ? AND number = ? AND resolved_at IS NULL`,
		owner, repo, number).Scan(&count)
	return count > 0
}

// UpdateAlertJSON は既存レコードの alert_json（GitHubから取得するアラートデータ）のみを更新する。
// state・eval_json・eval_status・notified_at 等の管理フィールドは変更しない。
func (s *Store) UpdateAlertJSON(owner, repo string, number int, alert model.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alertJSON, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("alert_json マーシャル失敗: %w", err)
	}
	result, err := s.db.Exec(`UPDATE alert_records SET alert_json = ? WHERE owner = ? AND repo = ? AND number = ? AND alert_json != ?`,
		string(alertJSON), owner, repo, number, string(alertJSON))
	if err != nil {
		return fmt.Errorf("alert_json 更新失敗: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("alert_json 更新件数確認失敗: %w", err)
	}
	if count > 0 {
		s.riskChangedLocked(RiskScope{Repos: []string{owner + "/" + repo}})
	}
	return nil
}

func (s *Store) UpdateState(alertID int, state model.AlertState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var mergedAt sql.NullTime
	if state == model.AlertStateMerged {
		mergedAt = sql.NullTime{Time: time.Now(), Valid: true}
	}

	res, err := s.db.Exec(`UPDATE alert_records SET state = ?, merged_at = ? WHERE id = ? AND resolved_at IS NULL`,
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
		SELECT id, alert_json, eval_json, state, eval_status, notified_at, merged_at
		FROM alert_records
		WHERE eval_status IN ('pending', 'failed') AND resolved_at IS NULL
		LIMIT ?`, limit)
	if err != nil {
		slog.Error("評価待ちレコード取得失敗", "error", err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var records []*model.AlertRecord
	for rows.Next() {
		var dbID int
		var alertJSON string
		var evalJSON sql.NullString
		var state, evalStatus string
		var notifiedAt time.Time
		var mergedAt sql.NullTime

		if err := rows.Scan(&dbID, &alertJSON, &evalJSON, &state, &evalStatus, &notifiedAt, &mergedAt); err != nil {
			continue
		}
		var alert model.Alert
		_ = json.Unmarshal([]byte(alertJSON), &alert)
		alert.ID = dbID

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

	res, err := s.db.Exec(`UPDATE alert_records SET eval_status = ? WHERE id = ? AND resolved_at IS NULL`,
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

// UpdateSlackMessageTS はSlack通知メッセージのタイムスタンプを保存する
func (s *Store) UpdateSlackMessageTS(alertID int, ts string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`UPDATE alert_records SET slack_message_ts = ? WHERE id = ?`, ts, alertID)
	if err != nil {
		return fmt.Errorf("slack_message_ts更新失敗: %w", err)
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

// FindEvalByCVE は同じCVE IDを持つ既存レコードのAI評価を返す。
// cveIDが空の場合はnilを返す（空CVE同士のマッチを防ぐ）。
// Deprecated: 履歴検索専用。AI評価の再利用にはFindEvaluationByKeyを使用する。
func (s *Store) FindEvalByCVE(cveID string) *model.Evaluation {
	if cveID == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var evalJSON sql.NullString
	err := s.db.QueryRow(`
		SELECT eval_json FROM alert_records
		WHERE json_extract(alert_json, '$.CVEID') = ?
		  AND eval_json IS NOT NULL
		  AND eval_status = 'done'
		ORDER BY id DESC
		LIMIT 1`, cveID).Scan(&evalJSON)
	if err != nil || !evalJSON.Valid {
		return nil
	}
	var eval model.Evaluation
	if err := json.Unmarshal([]byte(evalJSON.String), &eval); err != nil {
		return nil
	}
	return &eval
}

// FindEvalByAdvisory は CVE ID または GHSA ID で既存のAI評価を検索する。
// cveID が非空のときは CVE ID で検索する。cveID が空で ghsaID が非空のときは GHSA ID で検索する。
// 両方空の場合は nil を返す（空アドバイザリ同士のマッチを防ぐ）。
// Deprecated: 履歴検索専用。AI評価の再利用にはFindEvaluationByKeyを使用する。
func (s *Store) FindEvalByAdvisory(cveID, ghsaID string) *model.Evaluation {
	if cveID != "" {
		return s.FindEvalByCVE(cveID)
	}
	if ghsaID == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var evalJSON sql.NullString
	err := s.db.QueryRow(`
		SELECT eval_json FROM alert_records
		WHERE json_extract(alert_json, '$.GHSAID') = ?
		  AND eval_json IS NOT NULL
		  AND eval_status = 'done'
		ORDER BY id DESC
		LIMIT 1`, ghsaID).Scan(&evalJSON)
	if err != nil || !evalJSON.Valid {
		return nil
	}
	var eval model.Evaluation
	if err := json.Unmarshal([]byte(evalJSON.String), &eval); err != nil {
		return nil
	}
	return &eval
}

// ListReposByOwner はオーナー配下のリポジトリ名一覧をDBから取得する
func (s *Store) ListReposByOwner(owner string) []string {
	if owner == "" {
		return []string{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT DISTINCT json_extract(alert_json, '$.Repo')
		FROM alert_records
		WHERE json_extract(alert_json, '$.Owner') = ?`, owner)
	if err != nil {
		slog.Error("ListReposByOwner クエリ失敗", "owner", owner, "error", err)
		return []string{}
	}
	defer func() { _ = rows.Close() }()

	var repos []string
	for rows.Next() {
		var repo string
		if err := rows.Scan(&repo); err != nil {
			slog.Error("ListReposByOwner スキャン失敗", "error", err)
			continue
		}
		repos = append(repos, repo)
	}
	if repos == nil {
		return []string{}
	}
	return repos
}

// ListByPRNumber は同じ (owner, repo) で同じPR番号を持つアラートレコードを返す。
// prNumber が 0 の場合は空スライスを返す（PRNumber未設定のアラート同士をマッチさせない）。
func (s *Store) ListByPRNumber(owner, repo string, prNumber int) []*model.AlertRecord {
	if prNumber == 0 {
		return []*model.AlertRecord{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, alert_json, eval_json, state, eval_status, notified_at, merged_at, slack_message_ts, discord_message_id
		FROM alert_records
		WHERE owner = ? AND repo = ? AND resolved_at IS NULL AND json_extract(alert_json, '$.PRNumber') = ?`,
		owner, repo, prNumber)
	if err != nil {
		slog.Error("ListByPRNumber クエリ失敗", "owner", owner, "repo", repo, "prNumber", prNumber, "error", err)
		return []*model.AlertRecord{}
	}
	defer func() { _ = rows.Close() }()

	var records []*model.AlertRecord
	for rows.Next() {
		var dbID int
		var alertJSON string
		var evalJSON sql.NullString
		var state, evalStatus string
		var notifiedAt time.Time
		var mergedAt sql.NullTime
		var slackTS, discordMsgID string

		if err := rows.Scan(&dbID, &alertJSON, &evalJSON, &state, &evalStatus, &notifiedAt, &mergedAt, &slackTS, &discordMsgID); err != nil {
			slog.Error("ListByPRNumber スキャン失敗", "error", err)
			continue
		}
		var alert model.Alert
		_ = json.Unmarshal([]byte(alertJSON), &alert)
		alert.ID = dbID

		var eval *model.Evaluation
		if evalJSON.Valid {
			eval = &model.Evaluation{}
			_ = json.Unmarshal([]byte(evalJSON.String), eval)
		}

		record := &model.AlertRecord{
			Alert:            alert,
			Evaluation:       eval,
			State:            model.AlertState(state),
			EvalStatus:       model.EvalStatus(evalStatus),
			NotifiedAt:       notifiedAt,
			SlackMessageTS:   slackTS,
			DiscordMessageID: discordMsgID,
		}
		if mergedAt.Valid {
			t := mergedAt.Time
			record.MergedAt = &t
		}
		records = append(records, record)
	}
	if records == nil {
		return []*model.AlertRecord{}
	}
	return records
}

// UpdateDiscordMessageID はDiscord通知メッセージのIDを保存する
func (s *Store) UpdateDiscordMessageID(alertID int, messageID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`UPDATE alert_records SET discord_message_id = ? WHERE id = ?`, messageID, alertID)
	if err != nil {
		return fmt.Errorf("discord_message_id更新失敗: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("アラートID %d が見つかりません", alertID)
	}
	return nil
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
