package main

import (
	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
)

func jobPolicy(cfg *config.Config, guards []*policy.Guard) *policy.Guard {
	if len(guards) > 0 && guards[0] != nil {
		return guards[0]
	}
	return policy.NewGuard(func() (config.Snapshot, error) {
		clone, err := config.Clone(*cfg)
		return config.Snapshot{Revision: clone.ConfigRevision, Config: clone}, err
	})
}
