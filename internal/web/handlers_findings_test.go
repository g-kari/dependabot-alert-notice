package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type findingAPIPage struct {
	Items  []model.Finding `json:"items"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
}

type assetAPIPage struct {
	Items  []model.Asset `json:"items"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit"`
	Offset int           `json:"offset"`
}

type findingAPIDetail struct {
	Finding      model.Finding       `json:"finding"`
	Asset        model.Asset         `json:"asset"`
	Observations []model.Observation `json:"observations"`
	Events       []model.Event       `json:"events"`
}

func newFindingsAPITestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	db, err := store.NewWithPath(filepath.Join(t.TempDir(), "findings.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close findings test store: %v", err)
		}
	})
	cfg := &config.Config{Web: config.WebConfig{Port: 0}, Targets: []config.Target{{Owner: "example"}}}
	return New(cfg, "", db, &mockMerger{}), db
}

func seedAPIFinding(t *testing.T, db *store.Store, repo string, number int, severity model.Severity, sourceState string) {
	t.Helper()
	at := time.Date(2026, 11, 5, 10, number, 0, 0, time.UTC)
	_, err := db.SaveObservedWithError(context.Background(), &model.AlertRecord{
		Alert: model.Alert{
			Owner: "example", Repo: repo, Number: number, State: sourceState,
			CVEID: fmt.Sprintf("CVE-2026-%04d", number), PackageName: "package-" + repo,
			PackageEcosystem: "npm", Summary: "Synthetic advisory " + repo,
			Severity: severity, CreatedAt: at, UpdatedAt: at,
			HTMLURL: fmt.Sprintf("https://github.com/example/%s/security/dependabot/%d", repo, number),
		},
		NotifiedAt: at,
	})
	if err != nil {
		t.Fatalf("seed %s/%d: %v", repo, number, err)
	}
}

func findingsAPIRequest(t *testing.T, srv *Server, method, target string, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(method, target, nil))
	if w.Code != wantStatus {
		t.Fatalf("%s %s: status=%d, want=%d; body=%s", method, target, w.Code, wantStatus, w.Body.String())
	}
	return w
}

func assertFindingsJSON(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if got := w.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type=%q, want application/json; charset=utf-8", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q, want no-store", got)
	}
	if !json.Valid(w.Body.Bytes()) {
		t.Errorf("response is not valid JSON: %s", w.Body.String())
	}
}

func decodeFindingPage(t *testing.T, w *httptest.ResponseRecorder) findingAPIPage {
	t.Helper()
	assertFindingsJSON(t, w)
	var page findingAPIPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func TestFindingsAPIEmptyPagesUseArraysAndBoundedDefaults(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	for _, path := range []string{"/api/v1/findings", "/api/v1/assets"} {
		t.Run(path, func(t *testing.T) {
			w := findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusOK)
			assertFindingsJSON(t, w)
			var page struct {
				Items  json.RawMessage `json:"items"`
				Total  int             `json:"total"`
				Limit  int             `json:"limit"`
				Offset int             `json:"offset"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if string(page.Items) != "[]" || page.Total != 0 || page.Limit != 50 || page.Offset != 0 {
				t.Fatalf("empty page=%s, want items=[] total=0 limit=50 offset=0", w.Body.String())
			}
		})
	}
}

func TestFindingsAPIFiltersPagingAndRetainedResolvedHistory(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "alpha", 1, model.SeverityHigh, "open")
	seedAPIFinding(t, db, "beta", 2, model.SeverityLow, "fixed")
	seedAPIFinding(t, db, "gamma", 3, model.SeverityHigh, "open")

	all := decodeFindingPage(t, findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings", http.StatusOK))
	if len(all.Items) != 3 || all.Total != 3 {
		t.Fatalf("findings=%+v, want all 3 including resolved", all)
	}
	var resolved model.Finding
	for _, f := range all.Items {
		if f.SourceStatus == model.SourceStatusResolved {
			resolved = f
		}
	}
	if resolved.ID == "" {
		t.Fatal("default findings list omitted retained resolved history")
	}

	for _, tc := range []struct {
		query string
		total int
		items int
	}{
		{"source=dependabot", 3, 3},
		{"source=trivy", 0, 0},
		{"severity=high", 2, 2},
		{"source_status=resolved", 1, 1},
		{"asset_id=" + url.QueryEscape(resolved.AssetID), 1, 1},
		{"q=" + url.QueryEscape("CVE-2026-0002"), 1, 1},
		{"source=dependabot&severity=low&source_status=resolved&q=" + url.QueryEscape("CVE-2026-0002") + "&asset_id=" + url.QueryEscape(resolved.AssetID), 1, 1},
		{"limit=1&offset=1", 3, 1},
		{"limit=200&offset=1000000", 3, 0},
		{"q=" + url.QueryEscape("%' OR 1=1 --"), 0, 0},
		{"q=" + url.QueryEscape("%"), 0, 0},
		{"q=" + url.QueryEscape("_"), 0, 0},
	} {
		t.Run(tc.query, func(t *testing.T) {
			page := decodeFindingPage(t, findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?"+tc.query, http.StatusOK))
			if page.Total != tc.total || len(page.Items) != tc.items {
				t.Fatalf("query=%q: page=%+v, want total=%d items=%d", tc.query, page, tc.total, tc.items)
			}
			if strings.Contains(tc.query, "limit=1&") && (page.Limit != 1 || page.Offset != 1 || page.Items[0].ID != all.Items[1].ID) {
				t.Errorf("page=%+v, want limit=1 offset=1 and stable second finding=%s", page, all.Items[1].ID)
			}
			if len(page.Items) == 0 && !strings.Contains(wrappedJSON(t, page), `"items":[]`) {
				t.Error("empty filter page items must not be null")
			}
		})
	}
}

func wrappedJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestFindingsAPIDetailContainsAssetAndSourceEvidence(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "alpha", 1, model.SeverityHigh, "open")
	page := decodeFindingPage(t, findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings", http.StatusOK))
	if len(page.Items) != 1 {
		t.Fatalf("findings=%+v, want one", page)
	}
	w := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/"+page.Items[0].ID, http.StatusOK)
	assertFindingsJSON(t, w)
	var detail findingAPIDetail
	if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Finding.ID != page.Items[0].ID || detail.Asset.ID != page.Items[0].AssetID || detail.Asset.NativeID != "example/alpha" {
		t.Errorf("detail=%+v, want matching finding and asset", detail)
	}
	if len(detail.Observations) != 1 || detail.Observations[0].Source != "dependabot" || detail.Observations[0].FindingID != detail.Finding.ID || len(detail.Events) == 0 {
		t.Errorf("detail=%+v, want retained observation and audit events", detail)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"observations_truncated", "events_truncated"} {
		if string(body[key]) != "false" {
			t.Errorf("detail[%q]=%s, want explicit false truncation flag", key, body[key])
		}
	}
}

func TestFindingsAPIAssetsArePagedWithoutDuplicates(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "alpha", 1, model.SeverityHigh, "open")
	seedAPIFinding(t, db, "alpha", 2, model.SeverityLow, "open")
	seedAPIFinding(t, db, "beta", 3, model.SeverityHigh, "open")
	var firstID string
	for offset := 0; offset < 3; offset++ {
		path := fmt.Sprintf("/api/v1/assets?limit=1&offset=%d", offset)
		w := findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusOK)
		assertFindingsJSON(t, w)
		var page assetAPIPage
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		wantItems := 1
		if offset == 2 {
			wantItems = 0
		}
		if page.Total != 2 || len(page.Items) != wantItems || page.Limit != 1 || page.Offset != offset {
			t.Fatalf("offset=%d page=%+v, want total=2 limit=1 offset=%d items=%d", offset, page, offset, wantItems)
		}
		if offset == 0 {
			firstID = page.Items[0].ID
		} else if offset == 1 && firstID == page.Items[0].ID {
			t.Error("second asset page repeats first asset")
		}
		if offset == 2 && !strings.Contains(w.Body.String(), `"items":[]`) {
			t.Error("empty asset page items must not be null")
		}
	}
}

func TestFindingsAPIRejectsInvalidQuery(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	queries := []string{
		"unknown=value", "q=x&q=y", "limit=1&limit=2", "offset=0&offset=1", "severity=high&severity=low",
		"source=dependabot&source=trivy", "source_status=active&source_status=resolved", "asset_id=x&asset_id=y",
		"limit=", "limit=0", "limit=-1", "limit=201", "limit=1.5", "limit=+1", "limit=999999999999999999999999999999",
		"offset=", "offset=-1", "offset=1000001", "offset=0.1", "offset=%2B1",
		"severity=urgent", "severity=HIGH", "severity=", "source_status=closed", "source_status=", "source=", "source=bad%20source",
		"q=%00", "q=%0A", "q=%FF", "q=%", "q=a;b", "q=" + strings.Repeat("a", 257),
		"source=" + strings.Repeat("a", 65), "asset_id=", "asset_id=" + strings.Repeat("a", 129), "asset_id=a%00b",
		"q=" + strings.Repeat("a", 4097),
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			w := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?"+query, http.StatusBadRequest)
			assertFindingsJSON(t, w)
			if strings.Contains(w.Body.String(), query) {
				t.Error("validation error must not reflect untrusted query")
			}
		})
	}
	for _, query := range []string{"q=anything", "source=trivy", "severity=high", "source_status=active", "asset_id=x", "limit=0", "offset=-1", "limit=1&limit=2", "unknown=x", "q=%"} {
		t.Run("assets_"+query, func(t *testing.T) {
			assertFindingsJSON(t, findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/assets?"+query, http.StatusBadRequest))
		})
	}
	assertFindingsJSON(t, findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/00000000-0000-0000-0000-000000000000?limit=1", http.StatusBadRequest))
}

func TestFindingsAPIUnknownOrInvalidPathsReturnJSONNotDashboard(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	for _, path := range []string{
		"/api/v1/findings/00000000-0000-0000-0000-000000000000",
		"/api/v1/findings/not-a-uuid", "/api/v1/findings/", "/api/v1/findings/id/extra",
		"/api/v1/findings/%00", "/api/v1/assets/extra", "/api/v1/unknown",
	} {
		t.Run(path, func(t *testing.T) {
			w := findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusNotFound)
			assertFindingsJSON(t, w)
			if strings.Contains(w.Body.String(), "<!DOCTYPE") || strings.Contains(w.Body.String(), "sqlite") {
				t.Error("missing API path must not render dashboard or expose storage details")
			}
		})
	}
}

func TestFindingsAPIReadOnlyRoutesRejectWrites(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, path := range []string{"/api/v1/findings", "/api/v1/findings/00000000-0000-0000-0000-000000000000", "/api/v1/assets"} {
			t.Run(method+"_"+path, func(t *testing.T) {
				w := findingsAPIRequest(t, srv, method, path, http.StatusMethodNotAllowed)
				if got := w.Header().Get("Allow"); !strings.Contains(got, http.MethodGet) {
					t.Errorf("Allow=%q, want GET", got)
				}
			})
		}
	}
	if got := len(db.List()); got != 0 {
		t.Errorf("write requests created %d legacy alerts", got)
	}
}

func TestFindingsAPIStorageErrorsAreSafeJSON(t *testing.T) {
	for _, path := range []string{"/api/v1/findings", "/api/v1/assets", "/api/v1/findings/00000000-0000-0000-0000-000000000000"} {
		t.Run(path, func(t *testing.T) {
			srv, db := newFindingsAPITestServer(t)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			w := findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusInternalServerError)
			assertFindingsJSON(t, w)
			if got := strings.TrimSpace(w.Body.String()); got != `{"error":"internal_error"}` {
				t.Errorf("error=%s, want bounded internal_error without DB error", got)
			}
		})
	}
}

func TestFindingsAPIRoutesKeepExistingHandlerPolicy(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	// New GET routes use the same Handler wrapper as existing UI routes. The
	// deployment's external authentication remains required; no bypass route or
	// listener is introduced. Existing write-side CSRF checks remain intact.
	for _, path := range []string{"/", "/logs", "/api/v1/findings", "/api/v1/assets"} {
		findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusOK)
	}
	findingsAPIRequest(t, srv, http.MethodPost, "/settings/repositories/exclude", http.StatusForbidden)
	findingsAPIRequest(t, srv, http.MethodPost, "/settings/repositories/include", http.StatusForbidden)
	findingsAPIRequest(t, srv, http.MethodPost, "/reports/vulnerabilities/refresh", http.StatusForbidden)
}
