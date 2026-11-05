package notification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// Batcher は通知をリポジトリ単位でため、同じ一覧の再送を抑制する。
type Batcher struct {
	store  *store.Store
	scope  string
	source func() (config.Snapshot, error)
	key    func(string, string) string
	now    func() time.Time
	mu     sync.Mutex
}

// NewBatcher は接続先の秘密を含まないハッシュscopeと設定参照元を受け取る。
func NewBatcher(s *store.Store, scope string, source func() (config.Snapshot, error), key func(string, string) string) *Batcher {
	return &Batcher{store: s, scope: scope, source: source, key: key, now: time.Now}
}

// Defer はまとめ通知なら待機状態だけを保存する。即時モードではfalseを返す。
func (b *Batcher) Defer(owner, repo string) (bool, error) {
	snapshot, err := b.source()
	if err != nil {
		return true, fmt.Errorf("通知間隔設定取得失敗: %w", err)
	}
	if snapshot.Config.NotificationInterval == 0 {
		return false, nil
	}
	if !policy.IsMonitored(snapshot.Config.Targets, owner, repo) {
		return true, nil
	}
	records, err := b.store.NotificationRecords(owner, repo)
	if err != nil {
		return true, err
	}
	summary := Build(records, snapshot.Config, owner, repo)
	fingerprint, err := Fingerprint(summary)
	if err != nil {
		return true, err
	}
	return true, b.store.ScheduleNotification(b.scope, b.key(owner, repo), owner, repo, fingerprint, b.now().Add(snapshot.Config.NotificationInterval))
}

// Fingerprint は実際に表示する一覧の識別情報を生成する。
func Fingerprint(summary Summary) (string, error) {
	body, err := json.Marshal(summary.Records)
	if err != nil {
		return "", fmt.Errorf("通知変更識別失敗: %w", err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// Flush は期限を迎えたリポジトリを一度ずつ送信し、失敗分を再試行用に残す。
func (b *Batcher) Flush(ctx context.Context, now time.Time, send func(string, string) (string, error)) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	snapshot, err := b.source()
	if err != nil {
		return fmt.Errorf("まとめ通知設定取得失敗: %w", err)
	}
	dueBefore := now
	if snapshot.Config.NotificationInterval == 0 {
		dueBefore = time.Unix(0, 1<<63-1)
	}
	batches, err := b.store.DueNotifications(b.scope, dueBefore)
	if err != nil {
		return err
	}
	var failures []error
	for _, batch := range batches {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		current, err := b.source()
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !policy.IsMonitored(current.Config.Targets, batch.Owner, batch.Repo) {
			continue
		}
		sentFingerprint, err := send(batch.Owner, batch.Repo)
		if err != nil {
			if !errors.Is(err, policy.ErrNotMonitored) {
				failures = append(failures, err)
			}
			continue
		}
		if sentFingerprint == "" {
			continue
		}
		if err := b.store.CompleteNotification(batch.Key, sentFingerprint, now.Add(current.Config.NotificationInterval)); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
