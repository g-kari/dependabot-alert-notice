package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

const connectorStatusV2TestURL = "/api/v2/connectors/status?as_of=2026-11-10T12:00:00Z"

func decodeConnectorStatusVersionedPage(t *testing.T, srv *Server, target string) store.ConnectorStatusPage {
	t.Helper()
	w := findingsAPIRequest(t, srv, http.MethodGet, target, http.StatusOK)
	assertFindingsJSON(t, w)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("versioned status expanded CORS")
	}
	var page store.ConnectorStatusPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	return page
}

func TestConnectorStatusAPIVersionsKeepSourceFiltersTotalsAndPagesSeparate(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	at := time.Date(2026, 11, 10, 11, 0, 0, 0, time.UTC)
	sources := []string{"dependabot", "epss_feed", "epss_offline", "github_code_scanning", "github_secret_scanning", "kev_feed", "kev_offline", "trivy"}
	for _, source := range sources {
		run, err := db.StartIngestRun(context.Background(), source, "selection", at)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.FinishIngestRun(context.Background(), run.ID, "success", "partial", "", at); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []string{"v1", "v2"} {
		base := "/api/" + version + "/connectors/status?as_of=2026-11-10T12:00:00Z"
		want := sources
		if version == "v1" {
			want = []string{"dependabot", "epss_offline", "github_code_scanning", "github_secret_scanning", "kev_offline", "trivy"}
		}
		for _, suffix := range []string{"", "&scope=selection"} {
			page := decodeConnectorStatusVersionedPage(t, srv, base+suffix)
			if page.Total != len(want) || len(page.Items) != len(want) || page.Limit != 50 || page.Offset != 0 {
				t.Fatalf("%s default page=%+v", version, page)
			}
			for i, item := range page.Items {
				if item.Source != want[i] || item.Scope != "selection" {
					t.Fatalf("%s source/scope order=%+v, want sources=%v", version, page.Items, want)
				}
			}
		}
		page := decodeConnectorStatusVersionedPage(t, srv, base+"&limit=1&offset=1")
		if page.Total != len(want) || len(page.Items) != 1 || page.Items[0].Source != want[1] || page.Limit != 1 || page.Offset != 1 {
			t.Fatalf("%s bounded page=%+v", version, page)
		}
		page = decodeConnectorStatusVersionedPage(t, srv, base+"&limit=200&offset=1000000")
		if page.Total != len(want) || len(page.Items) != 0 || page.Items == nil {
			t.Fatalf("%s past end=%+v", version, page)
		}
		for _, source := range sources {
			if version == "v1" && (source == "epss_feed" || source == "kev_feed") {
				findingsAPIRequest(t, srv, http.MethodGet, base+"&source="+source, http.StatusBadRequest)
				continue
			}
			page := decodeConnectorStatusVersionedPage(t, srv, base+"&source="+source+"&scope=selection")
			if page.Total != 1 || len(page.Items) != 1 || page.Items[0].Source != source {
				t.Fatalf("%s source=%q page=%+v", version, source, page)
			}
		}
	}
}

func TestConnectorStatusV2APIEmptyFutureAndRunningRemainUnknown(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	w := findingsAPIRequest(t, srv, http.MethodGet, connectorStatusV2TestURL, http.StatusOK)
	for _, required := range []string{`"items":[]`, `"total":0`, `"configured_scopes":null`, `"unscanned_scopes":null`, `"asset_denominator":null`} {
		if !strings.Contains(w.Body.String(), required) {
			t.Fatalf("empty v2 missing %s: %s", required, w.Body.String())
		}
	}
	future := time.Date(2026, 11, 10, 12, 0, 0, 1, time.UTC)
	run, err := db.StartIngestRun(context.Background(), "epss_feed", "selection", future)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishIngestRun(context.Background(), run.ID, "success", "partial", "", future); err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartIngestRun(context.Background(), "kev_feed", "selection", future.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	page := decodeConnectorStatusVersionedPage(t, srv, connectorStatusV2TestURL)
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("v2 receipts=%+v", page)
	}
	f, running := page.Items[0], page.Items[1]
	if f.Status != "unknown" || f.Coverage != "unknown" || f.Liveness != "unknown" || !f.LatestAttempt.Future || f.LatestAttempt.AgeSeconds != nil || f.LastSuccess == nil || !f.LastSuccess.Future {
		t.Fatalf("future v2 receipt=%+v", f)
	}
	if running.Status != "running" || running.Liveness != "unknown" || running.LastSuccess != nil || running.LatestAttempt.FinishedAt != nil {
		t.Fatalf("running v2 receipt=%+v", running)
	}
}

func TestConnectorStatusV2APIKeepsStrictQueryAndMethodBoundary(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	for _, query := range []string{"", "?as_of=", "?as_of=bad", "?as_of=2026-11-10", "?as_of=0001-01-01T00:00:00Z", "?as_of=2026-11-10T12:00:00%2B24:00", "?as_of=2026-11-10T12:00:00%2B01:60", "?as_of=2026-11-10T12:00:00.1234567890Z", "?as_of=2026-11-10T12:00:00,1Z", "?%zz=1", "?" + strings.Repeat("x", 4097)} {
		findingsAPIRequest(t, srv, http.MethodGet, "/api/v2/connectors/status"+query, http.StatusBadRequest)
	}
	for _, suffix := range []string{"source=", "source=epss", "source=EPSS_FEED", "source=epss_feed%20", "source=new-provider", "source=kev_feed&source=kev_feed", "scope=", "scope=%20x", "scope=x%E2%80%8Bx", "scope=%00", "scope=" + strings.Repeat("x", 257), "limit=0", "limit=201", "limit=-1", "offset=-1", "offset=1000001", "offset=1.0", "status=success", "as_of=2026-11-10T12:00:00Z"} {
		w := findingsAPIRequest(t, srv, http.MethodGet, connectorStatusV2TestURL+"&"+suffix, http.StatusBadRequest)
		if strings.TrimSpace(w.Body.String()) != `{"error":"invalid_query"}` {
			t.Fatalf("v2 invalid query leaked details: %s", w.Body.String())
		}
	}
	findingsAPIRequest(t, srv, http.MethodGet, "/api/v2/connectors/status?as_of=2026-11-10T13:00:00%2B01:00&source=epss_feed&limit=200&offset=1000000", http.StatusOK)
	findingsAPIRequest(t, srv, http.MethodHead, connectorStatusV2TestURL, http.StatusOK)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect} {
		w := findingsAPIRequest(t, srv, method, connectorStatusV2TestURL, http.StatusMethodNotAllowed)
		assertFindingsJSON(t, w)
		if w.Header().Get("Allow") != "GET, HEAD" || strings.TrimSpace(w.Body.String()) != `{"error":"method_not_allowed"}` {
			t.Fatalf("v2 method=%s headers=%v body=%s", method, w.Header(), w.Body.String())
		}
	}
	for _, path := range []string{"/api/v2/connectors/status/", "/api/v2/connectors/status/bad", "/api/v2/connectors/bad", "/api/v2/findings"} {
		w := findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusNotFound)
		assertFindingsJSON(t, w)
	}
}

func TestConnectorStatusAPIVersionsRejectUnknownSnapshotsAndSanitizeErrors(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	at := time.Date(2026, 11, 10, 11, 0, 0, 0, time.UTC)
	if _, err := db.StartIngestRun(context.Background(), "private_unknown_source_sentinel", "selection", at); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{connectorStatusTestURL, connectorStatusV2TestURL} {
		for _, suffix := range []string{"", "&scope=selection"} {
			w := findingsAPIRequest(t, srv, http.MethodGet, target+suffix, http.StatusUnprocessableEntity)
			if strings.TrimSpace(w.Body.String()) != `{"error":"invalid_snapshot"}` {
				t.Fatalf("unknown retained source leaked metadata: %s", w.Body.String())
			}
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	w := findingsAPIRequest(t, srv, http.MethodGet, connectorStatusV2TestURL, http.StatusInternalServerError)
	if strings.TrimSpace(w.Body.String()) != `{"error":"internal_error"}` {
		t.Fatalf("v2 storage error leaked details: %s", w.Body.String())
	}
}

func TestConnectorStatusV2ReadLeavesExistingFindingAndAssetAPIsUnchanged(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "synthetic", 1, model.SeverityHigh, "open")
	paths := []string{"/api/v1/findings", "/api/v1/assets"}
	var before []string
	for _, path := range paths {
		before = append(before, findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusOK).Body.String())
	}
	if _, err := db.StartIngestRun(context.Background(), "epss_feed", "selection", time.Date(2026, 11, 10, 11, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	decodeConnectorStatusVersionedPage(t, srv, connectorStatusV2TestURL)
	for i, path := range paths {
		if after := findingsAPIRequest(t, srv, http.MethodGet, path, http.StatusOK).Body.String(); after != before[i] {
			t.Fatalf("v2 receipt/read changed existing API %s: before=%s after=%s", path, before[i], after)
		}
	}
}
