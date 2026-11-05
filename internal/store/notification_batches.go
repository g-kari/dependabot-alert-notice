package store

import (
	"fmt"
	"time"
)

// NotificationBatch は通知接続先ごとに永続化された送信待ちリポジトリ。
type NotificationBatch struct{ Key, Owner, Repo, Fingerprint string }

// ScheduleNotification は変更をまとめ、最初の送信期限を後続の変更で延長しない。
func (s *Store) ScheduleNotification(scope, key, owner, repo, fingerprint string, due time.Time) error {
	_, err := s.db.Exec(`INSERT INTO notification_batches(scope,group_key,owner,repo,fingerprint,due_at) VALUES(?,?,?,?,?,?)
 ON CONFLICT(group_key) DO UPDATE SET fingerprint=excluded.fingerprint,
 due_at=CASE WHEN excluded.fingerprint=notification_batches.sent_fingerprint THEN NULL
 WHEN notification_batches.due_at IS NULL THEN excluded.due_at ELSE notification_batches.due_at END
 WHERE notification_batches.fingerprint<>excluded.fingerprint`, scope, key, owner, repo, fingerprint, due.UnixNano())
	if err != nil {
		return fmt.Errorf("通知待機保存失敗: %w", err)
	}
	return nil
}

// DueNotifications は対象接続先の期限を迎えた変更のみ返す。
func (s *Store) DueNotifications(scope string, now time.Time) ([]NotificationBatch, error) {
	rows, err := s.db.Query(`SELECT group_key,owner,repo,fingerprint FROM notification_batches WHERE scope=? AND due_at IS NOT NULL AND due_at<=? ORDER BY due_at,group_key`, scope, now.UnixNano())
	if err != nil {
		return nil, fmt.Errorf("通知待機取得失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()
	batches := []NotificationBatch{}
	for rows.Next() {
		var b NotificationBatch
		if err := rows.Scan(&b.Key, &b.Owner, &b.Repo, &b.Fingerprint); err != nil {
			return nil, fmt.Errorf("通知待機読込失敗: %w", err)
		}
		batches = append(batches, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("通知待機走査失敗: %w", err)
	}
	return batches, nil
}

// CompleteNotification は送信成功を記録し、送信中に届いた別の変更を保持する。
func (s *Store) CompleteNotification(key, fingerprint string, next time.Time) error {
	_, err := s.db.Exec(`UPDATE notification_batches SET sent_fingerprint=?,due_at=CASE WHEN fingerprint=? THEN NULL ELSE ? END WHERE group_key=?`, fingerprint, fingerprint, next.UnixNano(), key)
	if err != nil {
		return fmt.Errorf("通知完了保存失敗: %w", err)
	}
	return nil
}
