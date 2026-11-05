package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestEvaluatedDetailOffersExplicitReevaluation(t *testing.T) {
	srv, s, _ := newTestServer(t)
	t.Cleanup(func() { _ = s.Close() })
	saveAlert(s, 1, "pkg", model.SeverityCritical)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/alerts/1", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `action="/api/evaluate/1"`) || !strings.Contains(w.Body.String(), "再評価") {
		t.Fatalf("completed evaluation has no re-evaluation action: status=%d", w.Code)
	}
}
