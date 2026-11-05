package policy

import (
	"context"
	"errors"
	"fmt"
	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"sync"
)

// ErrNotMonitored identifies excluded or unconfigured repository operations.
var ErrNotMonitored = errors.New("監視対象外リポジトリです")

// Guard coordinates repository side effects and monitoring configuration writes.
type Guard struct {
	source  func() (config.Snapshot, error)
	barrier contextBarrier
	mu      sync.Mutex
	repos   map[string]*repositoryLease
}

type repositoryLease struct {
	token chan struct{}
	refs  int
}
type contextBarrier struct {
	mu                      sync.Mutex
	readers, waitingWriters int
	writer                  bool
	changed                 chan struct{}
}

func (b *contextBarrier) notifyLocked() {
	if b.changed != nil {
		close(b.changed)
	}
	b.changed = make(chan struct{})
}
func (b *contextBarrier) lock(ctx context.Context, write bool) (func(), error) {
	b.mu.Lock()
	if b.changed == nil {
		b.changed = make(chan struct{})
	}
	if write {
		b.waitingWriters++
	}
	for {
		if err := ctx.Err(); err != nil {
			if write {
				b.waitingWriters--
				b.notifyLocked()
			}
			b.mu.Unlock()
			return nil, err
		}
		available := !b.writer
		if write {
			available = available && b.readers == 0
		} else {
			available = available && b.waitingWriters == 0
		}
		if available {
			if write {
				b.waitingWriters--
				b.writer = true
			} else {
				b.readers++
			}
			b.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					b.mu.Lock()
					if write {
						b.writer = false
					} else {
						b.readers--
					}
					b.notifyLocked()
					b.mu.Unlock()
				})
			}, nil
		}
		wake := b.changed
		b.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-wake:
		}
		b.mu.Lock()
	}
}

func (g *Guard) lockRepo(ctx context.Context, key string) (func(), error) {
	g.mu.Lock()
	if g.repos == nil {
		g.repos = make(map[string]*repositoryLease)
	}
	lease := g.repos[key]
	if lease == nil {
		lease = &repositoryLease{token: make(chan struct{}, 1)}
		lease.token <- struct{}{}
		g.repos[key] = lease
	}
	lease.refs++
	g.mu.Unlock()
	releaseRef := func() {
		g.mu.Lock()
		lease.refs--
		if lease.refs == 0 {
			delete(g.repos, key)
		}
		g.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		releaseRef()
		return nil, ctx.Err()
	case <-lease.token:
		var once sync.Once
		return func() { once.Do(func() { lease.token <- struct{}{}; releaseRef() }) }, nil
	}
}

// NewGuard uses a detached, synchronized configuration snapshot source.
func NewGuard(source func() (config.Snapshot, error)) *Guard { return &Guard{source: source} }

// Snapshot returns the current detached configuration.
func (g *Guard) Snapshot() (config.Snapshot, error) {
	if g == nil || g.source == nil {
		return config.Snapshot{}, fmt.Errorf("監視設定sourceが未設定です")
	}
	return g.source()
}

// LockUpdate waits for existing effects and blocks new effects through publication.
func (g *Guard) LockUpdate(ctx context.Context) (func(), error) { return g.barrier.lock(ctx, true) }

// WithAllowed checks the current policy and guards the entire repository effect.
func (g *Guard) WithAllowed(ctx context.Context, owner, repo string, fn func(config.Snapshot) error) error {
	if fn == nil {
		return fmt.Errorf("監視操作が未設定です")
	}
	release, err := g.barrier.lock(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	unlock, err := g.lockRepo(ctx, NormalizeRepo(owner, repo))
	if err != nil {
		return err
	}
	defer unlock()
	snapshot, err := g.Snapshot()
	if err != nil {
		return err
	}
	if !IsMonitored(snapshot.Config.Targets, owner, repo) {
		return fmt.Errorf("%w (%s)", ErrNotMonitored, NormalizeRepo(owner, repo))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(snapshot)
}
