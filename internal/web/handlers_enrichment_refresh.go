package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrefresh"
)

// SetManualEnrichmentController installs one explicitly created controller.
// Nil clearing and replacement with a different instance are rejected; repeating
// the same pointer is a no-op. It never constructs Service dependencies.
func (s *Server) SetManualEnrichmentController(controller *enrichmentrefresh.ManualController) error {
	if s == nil || controller == nil {
		return errors.New("manual enrichment API: controller is required")
	}
	s.manualRefreshMu.Lock()
	defer s.manualRefreshMu.Unlock()
	if s.manualRefreshController != nil && s.manualRefreshController != controller {
		return errors.New("manual enrichment API: controller already set")
	}
	s.manualRefreshController = controller
	return nil
}

func (s *Server) manualEnrichmentControllerSnapshot() *enrichmentrefresh.ManualController {
	s.manualRefreshMu.RLock()
	defer s.manualRefreshMu.RUnlock()
	return s.manualRefreshController
}

func (s *Server) registerManualEnrichmentAPI(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/tui/enrichment-refresh/operations", s.handleManualEnrichmentUnavailable)
	mux.HandleFunc("GET /api/tui/enrichment-refresh/operations/{operationID}", s.handleManualEnrichmentUnavailable)
	mux.HandleFunc("POST /api/tui/enrichment-refresh/operations/{operationID}/reconcile", s.handleManualEnrichmentUnavailable)
	mux.HandleFunc("GET /api/tui/enrichment-refresh", s.handleManualEnrichmentUnavailable)
	mux.HandleFunc("GET /api/tui/enrichment-refresh/", s.handleManualEnrichmentUnavailable)
}

// This Red checkpoint registers a real runtime seam without dispatching any
// controller work. Guards, strict decoding and closed-result projection wait for
// Green; no unavailable response authorizes collection or background execution.
func (s *Server) handleManualEnrichmentUnavailable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	if err := json.NewEncoder(w).Encode(struct {
		Code string `json:"code"`
	}{Code: "manual_api_unavailable"}); err != nil {
		slog.ErrorContext(r.Context(), "manual enrichment API unavailable response failed")
	}
}
