// Package policy centralizes repository monitoring decisions and exclusion
// updates so polling, evaluation and web actions cannot disagree.
package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

// NormalizeRepo returns a stable owner/repository key.
func NormalizeRepo(owner, repo string) string {
	return strings.ToLower(strings.TrimSpace(owner)) + "/" + strings.ToLower(strings.TrimSpace(repo))
}

// Policy serializes exclusion mutations and short repository side effects.
type Policy struct {
	manager *config.Manager
	guard   *Guard
}

// New creates a policy backed by a configuration manager.
func New(manager *config.Manager) *Policy {
	return &Policy{manager: manager, guard: NewGuard(func() (config.Snapshot, error) { return manager.Snapshot(), nil })}
}

// IsMonitored returns true only for a configured, non-excluded repository.
func (p *Policy) IsMonitored(s config.Snapshot, owner, repo string) bool {
	return IsMonitored(s.Config.Targets, owner, repo)
}

// Matches identifies owner-wide or repository-specific configured targets.
func Matches(target config.Target, owner, repo string) bool {
	return strings.EqualFold(strings.TrimSpace(target.Owner), strings.TrimSpace(owner)) && (strings.TrimSpace(target.Repo) == "" || NormalizeRepo(target.Owner, target.Repo) == NormalizeRepo(owner, repo))
}

// IsMonitored requires a matching target, with all matching exclusions dominant.
func IsMonitored(targets []config.Target, owner, repo string) bool {
	if strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
		return false
	}
	matched := false
	for _, target := range targets {
		if !Matches(target, owner, repo) {
			continue
		}
		if target.IsExcluded(repo) {
			return false
		}
		matched = true
	}
	return matched
}

// IsExcluded checks the latest manager snapshot.
func (p *Policy) IsExcluded(owner, repo string) bool {
	if p == nil || p.manager == nil {
		return true
	}
	return !p.IsMonitored(p.manager.Snapshot(), owner, repo)
}

// UpdateExclusion adds or removes an exclusion using optimistic revision
// control. A missing configured target is reported instead of silently adding
// an unmonitored repository.
func (p *Policy) UpdateExclusion(ctx context.Context, expected uint64, owner, repo string, excluded bool) error {
	if p == nil || p.manager == nil {
		return errors.New("policy manager is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	if owner == "" || repo == "" {
		return errors.New("owner and repo are required")
	}
	unlock, err := p.guard.LockUpdate(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return p.manager.Update(expected, func(cfg *config.Config) error {
		matched := false
		for i := range cfg.Targets {
			if !Matches(cfg.Targets[i], owner, repo) {
				continue
			}
			matched = true
			found := -1
			for j, ex := range cfg.Targets[i].Excludes {
				if strings.EqualFold(ex, repo) {
					found = j
					break
				}
			}
			if excluded {
				if found < 0 {
					cfg.Targets[i].Excludes = append(cfg.Targets[i].Excludes, repo)
				}
			} else if found >= 0 {
				cfg.Targets[i].Excludes = append(cfg.Targets[i].Excludes[:found], cfg.Targets[i].Excludes[found+1:]...)
			}
		}
		if !matched {
			return fmt.Errorf("target repository not found: %s/%s", owner, repo)
		}
		return nil
	})
}

// WithAllowed holds the repository guard through a short side effect. It is
// deliberately context-aware and re-checks the current snapshot immediately
// before invoking fn.
func (p *Policy) WithAllowed(repo string, fn func() error) error {
	if p == nil || p.manager == nil || fn == nil {
		return errors.New("invalid policy operation")
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("repository is not monitored: %s", repo)
	}
	return p.guard.WithAllowed(context.Background(), parts[0], parts[1], func(config.Snapshot) error { return fn() })
}
