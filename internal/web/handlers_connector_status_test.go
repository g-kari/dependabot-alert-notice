package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

const connectorStatusTestURL = "/api/v1/connectors/status?as_of=2026-11-09T12:00:00Z"

func TestConnectorStatusAPIShowsRecordedFailureWithoutHidingSuccess(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	at := time.Date(2026, 11, 9, 11, 0, 0, 0, time.UTC)
	var successID, failureID string
	for _, result := range []string{"success", "failed"} {
		run, err := db.StartIngestRun(context.Background(), "dependabot", "example/repo", at)
		if err != nil {
			t.Fatal(err)
		}
		coverage, code := "full", ""
		if result == "failed" {
			coverage, code, failureID = "unknown", "fetch_failed", run.ID
		} else {
			successID = run.ID
		}
		if err := db.FinishIngestRun(context.Background(), run.ID, result, coverage, code, at); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Minute)
	}
	w := findingsAPIRequest(t, srv, http.MethodGet, connectorStatusTestURL, http.StatusOK)
	assertFindingsJSON(t, w)
	var page store.ConnectorStatusPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].LatestAttempt.ID != failureID || page.Items[0].LastSuccess.ID != successID || page.Items[0].Status != "failed" {
		t.Fatalf("page=%+v", page)
	}
	for _, forbidden := range []string{"fetch_failed", `"error"`, "cursor", "body_json", "raw_ref"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("status leaked %q: %s", forbidden, w.Body.String())
		}
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("status endpoint expanded CORS")
	}
}

func TestConnectorStatusAPIEmptyAndStrictQueryValidation(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	w := findingsAPIRequest(t, srv, http.MethodGet, connectorStatusTestURL, http.StatusOK)
	if !strings.Contains(w.Body.String(), `"items":[]`) || !strings.Contains(w.Body.String(), `"configured_scopes":null`) || !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatalf("empty is unknown coverage, not scanned zero assets: %s", w.Body.String())
	}
	for _, query := range []string{
		"", "?as_of=", "?as_of=bad", "?as_of=2026-11-09", "?as_of=2026-11-09T12:00:00%2B24:00", "?as_of=0001-01-01T00:00:00Z",
		"?as_of=2026-11-09T12:00:00.1234567890Z", "?as_of=2026-11-09T12:00:00,1Z", "?as_of=2026-11-09T12:00:00%2B01:60",
		"?as_of=2026-11-09T12:00:00Z&as_of=2026-11-09T12:00:00Z", "?%zz=1", "?unknown=x", "?" + strings.Repeat("x", 4097),
	} {
		findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/connectors/status"+query, http.StatusBadRequest)
	}
	for _, suffix := range []string{"source=", "source=new-provider", "source=DEPENDABOT", "source=trivy&source=trivy", "scope=", "scope=%00", "scope=x%E2%80%8Bx", "scope=%20x", "scope=" + strings.Repeat("x", 257), "limit=0", "limit=201", "limit=-1", "offset=1000001", "offset=1.0", "status=failed", "id=bad"} {
		w := findingsAPIRequest(t, srv, http.MethodGet, connectorStatusTestURL+"&"+suffix, http.StatusBadRequest)
		if strings.TrimSpace(w.Body.String()) != `{"error":"invalid_query"}` {
			t.Fatalf("invalid query leaked details: %s", w.Body.String())
		}
	}
	for _, suffix := range []string{"source=trivy", "scope=example%2Frepo", "source=dependabot&scope=example%2Frepo", "limit=1&offset=1000000"} {
		findingsAPIRequest(t, srv, http.MethodGet, connectorStatusTestURL+"&"+suffix, http.StatusOK)
	}
	findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/connectors/status?as_of=2026-11-09T13:00:00%2B01:00", http.StatusOK)
}

func TestConnectorStatusAPIRejectsMethodsAndUnknownPaths(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	findingsAPIRequest(t, srv, http.MethodHead, connectorStatusTestURL, http.StatusOK)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect} {
		w := findingsAPIRequest(t, srv, method, connectorStatusTestURL, http.StatusMethodNotAllowed)
		assertFindingsJSON(t, w)
		if w.Header().Get("Allow") != "GET, HEAD" || strings.TrimSpace(w.Body.String()) != `{"error":"method_not_allowed"}` {
			t.Fatalf("method=%s headers=%v body=%s", method, w.Header(), w.Body.String())
		}
	}
	for _, path := range []string{"/api/v1/connectors/status/bad", "/api/v1/connectors/bad", "/api/v1/connectors/status/"} {
		findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusNotFound)
	}
	// Existing mutation protection remains in the enclosing Handler.
	findingsAPIRequest(t, srv, http.MethodPost, "/settings/rss/config", http.StatusForbidden)
}

func TestConnectorStatusAPIStorageErrorsAreSanitized(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	w := findingsAPIRequest(t, srv, http.MethodGet, connectorStatusTestURL, http.StatusInternalServerError)
	assertFindingsJSON(t, w)
	if strings.TrimSpace(w.Body.String()) != `{"error":"internal_error"}` {
		t.Fatalf("storage error leaked details: %s", w.Body.String())
	}
}

func TestConnectorStatusAPIInvalidSnapshotDoesNotLeakMetadata(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	at := time.Date(2026, 11, 9, 11, 0, 0, 0, time.UTC)
	if _, err := db.StartIngestRun(context.Background(), "private_unknown_source_sentinel", "scope", at); err != nil {
		t.Fatal(err)
	}
	w := findingsAPIRequest(t, srv, http.MethodGet, connectorStatusTestURL, http.StatusUnprocessableEntity)
	assertFindingsJSON(t, w)
	if strings.TrimSpace(w.Body.String()) != `{"error":"invalid_snapshot"}` {
		t.Fatalf("invalid snapshot leaked details: %s", w.Body.String())
	}
}
