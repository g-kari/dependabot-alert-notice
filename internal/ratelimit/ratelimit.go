package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter は最小インターバルを守りつつ、429応答時のRetry-Afterにも対応するレートリミッター。
type Limiter struct {
	mu          sync.Mutex
	minInterval time.Duration
	nextAllowed time.Time
}

// NewLimiter は最小インターバルを指定してLimiterを生成する。
func NewLimiter(minInterval time.Duration) *Limiter {
	return &Limiter{
		minInterval: minInterval,
		nextAllowed: time.Time{}, // ゼロ値 = すぐ実行可
	}
}

// Wait は次のリクエストを送信可能になるまで待機する。
// ctx がキャンセルされた場合は ctx.Err() を返す。
func (l *Limiter) Wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	wait := l.nextAllowed.Sub(now)
	// 次回のnextAllowedを更新（minInterval後）
	if wait > 0 {
		l.nextAllowed = l.nextAllowed.Add(l.minInterval)
	} else {
		l.nextAllowed = now.Add(l.minInterval)
		wait = 0
	}
	l.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	select {
	case <-time.After(wait):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetRetryAfter は429応答などのRetry-After期間を設定する。
// 次の Wait() 呼び出しは少なくともその期間待機する。
// d が0以下の場合はno-op。
func (l *Limiter) SetRetryAfter(d time.Duration) {
	if d <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	retryAt := time.Now().Add(d)
	if retryAt.After(l.nextAllowed) {
		l.nextAllowed = retryAt
	}
}
