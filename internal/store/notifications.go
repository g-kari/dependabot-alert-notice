package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// NotificationGroupKey は通知先の秘密を保存せず、サービス・通知先・リポジトリを分離する。
func NotificationGroupKey(provider, destination, owner, repo string) string {
	body, _ := json.Marshal([4]string{provider, destination, strings.ToLower(owner), strings.ToLower(repo)})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// WithNotificationLock は同一ストア内の親メッセージ作成・更新を直列化する。
// DBのロックとは分離し、API待機中も通常のレコード保存を妨げない。
func (s *Store) WithNotificationLock(fn func() error) error {
	s.notificationMu.Lock()
	defer s.notificationMu.Unlock()
	return fn()
}

// NotificationGroup は再起動後も利用できるまとめ先IDを返す。未作成は空文字。
func (s *Store) NotificationGroup(key string) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT message_id FROM notification_groups WHERE group_key=?`, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("通知グループ取得失敗: %w", err)
	}
	return id, nil
}

// SaveNotificationGroup はAPI成功後のまとめ先IDを保存する。
func (s *Store) SaveNotificationGroup(key, id string) error {
	if key == "" || id == "" {
		return fmt.Errorf("通知グループのキー・IDが未設定です")
	}
	_, err := s.db.Exec(`INSERT INTO notification_groups(group_key,message_id) VALUES(?,?) ON CONFLICT(group_key) DO UPDATE SET message_id=excluded.message_id`, key, id)
	if err != nil {
		return fmt.Errorf("通知グループ保存失敗: %w", err)
	}
	return nil
}

// NotificationRecords は集約用の未解決レコードを一貫した読取で取得する。
// 読取失敗を0件として送信しないため、エラーを呼出元に返す。
func (s *Store) NotificationRecords(owner, repo string) ([]*model.AlertRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT id,alert_json,eval_json,eval_status FROM alert_records WHERE resolved_at IS NULL AND owner=? COLLATE NOCASE AND repo=? COLLATE NOCASE`, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("集約アラート取得失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*model.AlertRecord{}
	for rows.Next() {
		var id int
		var alertJSON, status string
		var evalJSON sql.NullString
		if err := rows.Scan(&id, &alertJSON, &evalJSON, &status); err != nil {
			return nil, fmt.Errorf("集約アラート読込失敗: %w", err)
		}
		r := &model.AlertRecord{EvalStatus: model.EvalStatus(status)}
		if err := json.Unmarshal([]byte(alertJSON), &r.Alert); err != nil {
			return nil, fmt.Errorf("集約アラート解析失敗: %w", err)
		}
		r.Alert.ID = id
		if evalJSON.Valid {
			if err := json.Unmarshal([]byte(evalJSON.String), &r.Evaluation); err != nil {
				return nil, fmt.Errorf("集約AI評価解析失敗: %w", err)
			}
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("集約アラート走査失敗: %w", err)
	}
	return records, nil
}

// GetByKey は未解決アラートの現在の通知IDを含むレコードを返す。
func (s *Store) GetByKey(owner, repo string, number int) (*model.AlertRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var id int
	if err := s.db.QueryRow(`SELECT id FROM alert_records WHERE owner=? AND repo=? AND number=? AND resolved_at IS NULL`, owner, repo, number).Scan(&id); err != nil {
		return nil, fmt.Errorf("通知対象アラート取得失敗: %w", err)
	}
	return s.getUnlocked(id)
}
