package web

import (
	"context"
	"fmt"
	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"net/http"
)

type riskSettingsSource struct{ server *Server }

func (source riskSettingsSource) Snapshot() (config.Snapshot, error) {
	s := source.server
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	clone, err := config.Clone(*s.cfg)
	if err != nil {
		return config.Snapshot{}, fmt.Errorf("緊急度設定複製: %w", err)
	}
	return config.Snapshot{Revision: s.cfg.ConfigRevision, Config: clone}, nil
}
func (source riskSettingsSource) WithRevision(revision uint64, save func() error) error {
	s := source.server
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	if revision != s.cfg.ConfigRevision {
		return store.ErrRiskInputsChanged
	}
	return save()
}
func (source riskSettingsSource) Changes() <-chan struct{} { return source.server.riskConfigChanged }

// RecalculateRisks awaits a complete local scoring sweep.
func (s *Server) RecalculateRisks(ctx context.Context) error { return s.riskWorker.RefreshOnce(ctx) }

// RunRiskScheduler processes scoring events until application cancellation.
func (s *Server) RunRiskScheduler(ctx context.Context) error { return s.riskWorker.Run(ctx) }

func (s *Server) notifyRiskConfigChanged() {
	select {
	case s.riskConfigChanged <- struct{}{}:
	default:
	}
}

// updateMonitoringSettings keeps legacy forms inside the same atomic revision
// contract as the new repository settings routes.
func (s *Server) updateMonitoringSettings(ctx context.Context, w http.ResponseWriter, mutate func(*config.Config)) bool {
	unlock, err := s.repositoryPolicy.LockUpdate(ctx)
	if err != nil {
		http.Error(w, "設定変更の待機を中止しました", http.StatusRequestTimeout)
		return false
	}
	defer unlock()
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	next, err := config.Clone(*s.cfg)
	if err != nil {
		http.Error(w, "設定複製失敗", http.StatusInternalServerError)
		return false
	}
	mutate(&next)
	if err := next.Validate(); err != nil {
		http.Error(w, "設定が不正です: "+err.Error(), http.StatusUnprocessableEntity)
		return false
	}
	next.ConfigRevision++
	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, &next); err != nil {
			http.Error(w, "設定保存失敗", http.StatusInternalServerError)
			return false
		}
	}
	*s.cfg = next
	s.notifyRiskConfigChanged()
	return true
}

// RepositoryPolicy returns the shared guard used by all repository effects.
func (s *Server) RepositoryPolicy() *policy.Guard { return s.repositoryPolicy }

// ConfigurationSnapshot returns a detached, synchronized current configuration.
func (s *Server) ConfigurationSnapshot() (config.Snapshot, error) {
	return riskSettingsSource{server: s}.Snapshot()
}
