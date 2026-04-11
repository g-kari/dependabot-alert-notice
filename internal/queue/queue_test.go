package queue

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQueue_EnqueueAndProcess(t *testing.T) {
	q := New(10, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var processed atomic.Int32
	q.Register("test_job", func(ctx context.Context, job Job) error {
		processed.Add(1)
		return nil
	})
	q.Start(ctx)

	q.Enqueue(Job{Type: "test_job"})
	q.Enqueue(Job{Type: "test_job"})

	// 処理完了を待つ
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if processed.Load() == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if processed.Load() != 2 {
		t.Errorf("processed = %d, want 2", processed.Load())
	}
}

func TestQueue_ConcurrentWorkers(t *testing.T) {
	const numJobs = 10
	const numWorkers = 3

	q := New(numJobs, numWorkers)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		processed     atomic.Int32
		mu            sync.Mutex
		maxConcurrent int32
		current       atomic.Int32
	)

	q.Register("concurrent_job", func(ctx context.Context, job Job) error {
		c := current.Add(1)
		mu.Lock()
		if c > maxConcurrent {
			maxConcurrent = c
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		current.Add(-1)
		processed.Add(1)
		return nil
	})
	q.Start(ctx)

	for i := 0; i < numJobs; i++ {
		q.Enqueue(Job{Type: "concurrent_job"})
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if int(processed.Load()) == numJobs {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if int(processed.Load()) != numJobs {
		t.Errorf("processed = %d, want %d", processed.Load(), numJobs)
	}
	mu.Lock()
	mc := maxConcurrent
	mu.Unlock()
	if mc < 2 {
		t.Errorf("maxConcurrent = %d, want at least 2 (workers=%d)", mc, numWorkers)
	}
}

func TestQueue_Stop(t *testing.T) {
	q := New(10, 2)
	ctx, cancel := context.WithCancel(context.Background())

	var processed atomic.Int32
	q.Register("slow_job", func(ctx context.Context, job Job) error {
		time.Sleep(50 * time.Millisecond)
		processed.Add(1)
		return nil
	})
	q.Start(ctx)

	q.Enqueue(Job{Type: "slow_job"})
	q.Enqueue(Job{Type: "slow_job"})

	// キャンセルしてStop
	cancel()
	done := make(chan struct{})
	go func() {
		q.Stop()
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() timed out")
	}
}

func TestQueue_UnknownJobType(t *testing.T) {
	q := New(10, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q.Start(ctx)

	// パニックしないことを確認
	q.Enqueue(Job{Type: "unknown_type"})
	time.Sleep(50 * time.Millisecond)
}

func TestQueue_HandlerError(t *testing.T) {
	q := New(10, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var callCount atomic.Int32
	q.Register("error_job", func(ctx context.Context, job Job) error {
		callCount.Add(1)
		return nil
	})
	q.Start(ctx)

	q.Enqueue(Job{Type: "error_job"})
	q.Enqueue(Job{Type: "error_job"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if callCount.Load() == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if callCount.Load() != 2 {
		t.Errorf("callCount = %d, want 2", callCount.Load())
	}
}

func TestQueue_Len(t *testing.T) {
	q := New(100, 0) // worker 0 = 処理しない
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx

	q.Enqueue(Job{Type: "job"})
	q.Enqueue(Job{Type: "job"})
	q.Enqueue(Job{Type: "job"})

	if q.Len() != 3 {
		t.Errorf("Len() = %d, want 3", q.Len())
	}
}
