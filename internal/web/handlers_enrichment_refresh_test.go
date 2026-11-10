package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrefresh"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

const manualAPIContractCSV = "#model_version:synthetic-api,score_date:2026-11-10\ncve,epss,percentile\nCVE-2026-1234,0,0\n"

type manualAPIContractFixture struct {
	server     *Server
	controller *enrichmentrefresh.ManualController
	clock      int
	uuid       int
	fetch      int
}

type manualAPIContractFetcher struct {
	fixture *manualAPIContractFixture
}

func (f manualAPIContractFetcher) Fetch(ctx context.Context, source string) ([]byte, error) {
	f.fixture.fetch++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source != "epss" {
		return nil, fmt.Errorf("unexpected synthetic source")
	}
	return []byte(manualAPIContractCSV), nil
}

func newManualAPIContractFixture(t *testing.T) *manualAPIContractFixture {
	t.Helper()
	db, err := store.NewWithPath(filepath.Join(t.TempDir(), "synthetic-manual-api.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close owned synthetic database: %v", err)
		}
	})
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	if _, err := db.SaveObservedWithError(context.Background(), &model.AlertRecord{
		Alert: model.Alert{
			Owner: "example", Repo: "synthetic", Number: 1, State: "open",
			CVEID: "CVE-2026-1234", PackageName: "synthetic", PackageEcosystem: "npm",
			Summary: "Authored manual API fixture", Severity: model.SeverityHigh,
			CreatedAt: at, UpdatedAt: at,
			HTMLURL: "https://github.com/example/synthetic/security/dependabot/1",
		},
		NotifiedAt: at,
	}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Web: config.WebConfig{Port: 0}, Targets: []config.Target{{Owner: "example", Repo: "synthetic"}}}
	f := &manualAPIContractFixture{server: New(cfg, "", db, nil)}
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	service := enrichmentrefresh.Service{
		Store: db,
		Clock: func() time.Time {
			if f.clock >= 3 {
				t.Fatal("manual replay generated another business clock")
			}
			value := start.Add(time.Duration(f.clock) * time.Minute)
			f.clock++
			return value
		},
		NewUUID: func() (string, error) {
			f.uuid++
			return "30000000-0000-4000-8000-000000000301", nil
		},
		Fetcher: manualAPIContractFetcher{fixture: f},
	}
	f.controller, err = enrichmentrefresh.NewManualController(service)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.server.SetManualEnrichmentController(f.controller); err != nil {
		t.Fatal(err)
	}
	return f
}

func manualAPIContractRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Host = "localhost:8080"
	request.RemoteAddr = "127.0.0.1:54321"
	request.Header.Set("Origin", "http://localhost:8080")
	request.AddCookie(&http.Cookie{Name: "csrf_token", Value: "synthetic-manual-csrf"})
	request.Header.Set("X-CSRF-Token", "synthetic-manual-csrf")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

type manualAPIContractSummary struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	Replay      bool   `json:"replay"`
	Outcome     string `json:"outcome"`
	Code        string `json:"code"`
	RunID       string `json:"run_id"`
	NextAfter   string `json:"next_after"`
	Advance     bool   `json:"advance"`
}

func TestManualEnrichmentAPIContractCallReturnsOwnedControllerResult(t *testing.T) {
	f := newManualAPIContractFixture(t)
	id := "50000000-0000-4000-8000-000000000001"
	body := fmt.Sprintf(`{"operation_id":%q,"connector":"epss_feed","after":"","limit":200}`, id)
	request := manualAPIContractRequest(http.MethodPost, "/api/tui/enrichment-refresh/operations", body)
	response := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("manual API contract status=%d body=%s", response.Code, response.Body.String())
	}
	var out manualAPIContractSummary
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.OperationID != id || out.State != "resolved" || out.Replay || out.Outcome != "success" || out.RunID != "30000000-0000-4000-8000-000000000301" || !out.Advance || out.NextAfter == "" || f.clock != 3 || f.uuid != 1 || f.fetch != 1 {
		t.Fatalf("manual API did not return the owned result: %+v clock=%d uuid=%d fetch=%d", out, f.clock, f.uuid, f.fetch)
	}
	retained, ok := f.controller.Snapshot(id)
	if !ok || retained.Result.RunID != out.RunID || retained.Result.NextAfter != out.NextAfter {
		t.Fatal("HTTP result is not bound to injected controller retention")
	}
}

func TestManualEnrichmentAPIContractSnapshotReadsRetainedOutcomeWithoutIO(t *testing.T) {
	f := newManualAPIContractFixture(t)
	id := "50000000-0000-4000-8000-000000000002"
	operation, _, err := f.controller.Call(context.Background(), id, enrichmentrefresh.Request{Connector: "epss_feed", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(response, manualAPIContractRequest(http.MethodGet, "/api/tui/enrichment-refresh/operations/"+id, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("manual snapshot contract status=%d body=%s", response.Code, response.Body.String())
	}
	var out manualAPIContractSummary
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.OperationID != id || out.State != "resolved" || out.Outcome != "success" || out.RunID != operation.Result.RunID || out.NextAfter != operation.Result.NextAfter || f.clock != 3 || f.uuid != 1 || f.fetch != 1 {
		t.Fatalf("snapshot did not use retained state only: %+v", out)
	}
}
