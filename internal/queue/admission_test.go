package queue

import (
	"context"
	"testing"
	"time"
)

func TestTryEnqueueRejectsFullWithoutLeakingWaitCount(t *testing.T) {
	q := New(1, 1)
	if !q.TryEnqueue(Job{Type: JobFetchAlerts}) {
		t.Fatal("empty queue rejected job")
	}
	if q.TryEnqueue(Job{Type: JobFetchAlerts}) {
		t.Fatal("full queue accepted job")
	}
	q.Register(JobFetchAlerts, func(context.Context, Job) error { return nil })
	q.Start(context.Background())
	defer q.Stop()
	done := make(chan struct{})
	go func() { q.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rejected job leaked Wait count")
	}
}

func TestEnqueueRejectsJobsAfterStop(t *testing.T) {
	q := New(1, 1)
	q.Start(context.Background())
	q.Stop()
	q.Enqueue(Job{Type: JobFetchAlerts})
	if q.Len() != 0 {
		t.Fatal("shutdown accepted a job that no worker can finish")
	}
}

func TestStopReleasesBlockedEnqueue(t *testing.T) {
	q := New(1, 0)
	q.Start(context.Background())
	q.Enqueue(Job{Type: JobFetchAlerts})
	done := make(chan struct{})
	go func() { q.Enqueue(Job{Type: JobFetchAlerts}); close(done) }()
	stopped := make(chan struct{})
	go func() { q.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stop blocked on producer")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("producer survived shutdown")
	}
	if q.Len() != 0 {
		t.Fatal("shutdown left jobs queued")
	}
}
