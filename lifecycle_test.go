package main

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedSchedulersOnceSkipsAndNormalShutdownJoins(t *testing.T) {
	var calls atomic.Int32
	startManagedSchedulers(context.Background(), true, func(context.Context) { calls.Add(1) })()
	if calls.Load() != 0 {
		t.Fatal("periodic service started in once mode")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	stopped := make(chan struct{})
	wait := startManagedSchedulers(ctx, false, func(ctx context.Context) { close(started); <-ctx.Done(); close(stopped) })
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scheduler never started")
	}
	cancel()
	wait()
	select {
	case <-stopped:
	default:
		t.Fatal("wait returned before scheduler stopped")
	}
}

func TestOnceStepsAwaitInputsBeforeScoringAndRetainPartialErrors(t *testing.T) {
	var order []string
	partial := errors.New("fixture RSS partial failure")
	err := runOnceSteps(context.Background(),
		func(context.Context) error { order = append(order, "rss"); return partial },
		func(context.Context) error { order = append(order, "threat"); return nil },
		func(context.Context) error { order = append(order, "fetch/evaluate complete"); return nil },
		func(context.Context) error { order = append(order, "risk persisted"); return nil },
	)
	if !reflect.DeepEqual(order, []string{"rss", "threat", "fetch/evaluate complete", "risk persisted"}) || !errors.Is(err, partial) {
		t.Fatalf("order=%v err=%v", order, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := runOnceSteps(ctx, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled steps: called=%v err=%v", called, err)
	}
}
