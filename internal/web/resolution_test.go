package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestResolvedDetailIsReadOnlyAndRemainsAccessible(t *testing.T) {
	srv, s, m := newTestServer(t)
	t.Cleanup(func() { _ = s.Close() })
	saveAlert(s, 1, "retained-package", model.SeverityHigh)
	rec := s.List()[0]
	s.RemoveResolvedAlerts("testorg", "testrepo", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/alerts/%d", rec.Alert.ID), nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "解決済み") {
		t.Fatalf("history detail unavailable: status=%d", w.Code)
	}
	if strings.Contains(w.Body.String(), "マージ承認") || strings.Contains(w.Body.String(), "評価開始") {
		t.Fatal("resolved detail still exposes actions")
	}
	for _, path := range []string{fmt.Sprintf("/alerts/%d/approve", rec.Alert.ID), fmt.Sprintf("/alerts/%d/reject", rec.Alert.ID), fmt.Sprintf("/api/evaluate/%d", rec.Alert.ID)} {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
		if w.Code != http.StatusConflict {
			t.Errorf("resolved action %s status=%d", path, w.Code)
		}
	}
	if len(m.approved) != 0 || len(m.rejected) != 0 {
		t.Fatal("resolved action reached merger")
	}
}
