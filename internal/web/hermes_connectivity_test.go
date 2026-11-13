package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

func TestConnectivityTest_HermesProxyUsesModelsWithoutInference(t *testing.T) {
	var observed atomic.Value
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed.Store(r.Method + " " + r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"data":[{"id":"Hermes-4-70B"}]}`)); err != nil {
			t.Errorf("write model list: %v", err)
		}
	}))
	defer proxy.Close()

	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
		Evaluator: config.EvaluatorConfig{
			Provider:      "hermes",
			HermesBaseURL: proxy.URL + "/v1",
		},
	}
	t.Setenv("SLACK_BOT_TOKEN", "")
	w := httptest.NewRecorder()
	srv.handleConnectivityTest(w, httptest.NewRequest(http.MethodPost, "/api/connectivity-test", nil))

	var result map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode connectivity result: %v", err)
	}
	var hermes toolResult
	if err := json.Unmarshal(result["hermes"], &hermes); err != nil {
		t.Fatalf("decode Hermes result: %v", err)
	}
	if !hermes.OK || observed.Load() != "GET /v1/models" {
		t.Fatalf("Hermes status=%+v request=%v", hermes, observed.Load())
	}
}
