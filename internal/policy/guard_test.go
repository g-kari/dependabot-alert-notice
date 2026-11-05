package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

func TestGuardRejectsUnknownAndCanceledEffects(t *testing.T) {
	g := NewGuard(func() (config.Snapshot, error) { return config.Snapshot{}, nil })
	called := false
	err := g.WithAllowed(context.Background(), "org", "api", func(config.Snapshot) error { called = true; return nil })
	if !errors.Is(err, ErrNotMonitored) || called {
		t.Fatalf("unknown effect called=%v err=%v", called, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = g.WithAllowed(ctx, "org", "api", func(config.Snapshot) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestGuardUpdateWaitsForEffectsWithoutBlockingOtherRepos(t *testing.T) {
	g := NewGuard(func() (config.Snapshot, error) {
		return config.Snapshot{Config: config.Config{Targets: []config.Target{{Owner: "org"}}}}, nil
	})
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- g.WithAllowed(context.Background(), "org", "api", func(config.Snapshot) error { close(entered); <-release; return nil })
	}()
	<-entered
	t.Cleanup(func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := g.WithAllowed(ctx, "org", "sdk", func(config.Snapshot) error { return nil }); err != nil {
		t.Fatalf("different repo blocked: %v", err)
	}
	unlock, err := g.LockUpdate(ctx)
	if err == nil {
		unlock()
		t.Fatal("configuration update passed an active effect")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("update cancellation=%v", err)
	}
	called := false
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	err = g.WithAllowed(ctx2, "ORG", "API", func(config.Snapshot) error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("same repo concurrent effect: called=%v err=%v", called, err)
	}
}
