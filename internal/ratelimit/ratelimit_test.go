package ratelimit

import (
	"context"
	"testing"
	"time"
)

// TestLimiter_Wait は最小インターバルが守られることを確認
func TestLimiter_Wait(t *testing.T) {
	l := NewLimiter(50 * time.Millisecond)

	// 1回目はすぐ通過
	start := time.Now()
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	firstElapsed := time.Since(start)
	if firstElapsed > 20*time.Millisecond {
		t.Errorf("first Wait() took %v, want < 20ms", firstElapsed)
	}

	// 2回目はインターバル分待機
	start = time.Now()
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 40*time.Millisecond {
		t.Errorf("second Wait() took %v, want >= 40ms (interval=50ms)", elapsed)
	}
}

// TestLimiter_ContextCancel はctxキャンセル時にエラーを返すことを確認
func TestLimiter_ContextCancel(t *testing.T) {
	l := NewLimiter(500 * time.Millisecond)
	_ = l.Wait(context.Background()) // 1回目は通過

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := l.Wait(ctx)
	if err == nil {
		t.Error("Wait() should return error when context is cancelled")
	}
}

// TestLimiter_SetRetryAfter はSetRetryAfter後に指定期間ブロックすることを確認
func TestLimiter_SetRetryAfter(t *testing.T) {
	l := NewLimiter(10 * time.Millisecond)
	_ = l.Wait(context.Background()) // 1回目消費

	retryDur := 60 * time.Millisecond
	l.SetRetryAfter(retryDur)

	start := time.Now()
	if err := l.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 50*time.Millisecond {
		t.Errorf("Wait() after SetRetryAfter took %v, want >= 50ms", elapsed)
	}
}

// TestLimiter_SetRetryAfterZero はSetRetryAfter(0)が最小インターバルに戻ることを確認
func TestLimiter_SetRetryAfterZero(t *testing.T) {
	l := NewLimiter(10 * time.Millisecond)
	l.SetRetryAfter(0) // 無効値はno-op
	start := time.Now()
	_ = l.Wait(context.Background())
	elapsed := time.Since(start)
	if elapsed > 20*time.Millisecond {
		t.Errorf("Wait() after SetRetryAfter(0) took %v, want < 20ms", elapsed)
	}
}
