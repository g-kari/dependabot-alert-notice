package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func nativeConsoleRequest(t *testing.T, srv *Server, method, target string, status int) string {
	t.Helper()
	w := findingsAPIRequest(t, srv, method, target, status)
	for key, want := range map[string]string{"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"} {
		if got := w.Header().Get(key); got != want {
			t.Errorf("%s %s: %s=%q, want %q", method, target, key, got, want)
		}
	}
	body := w.Body.String()
	if method == http.MethodHead {
		if body != "" {
			t.Fatal("HEAD response contains a body")
		}
		return body
	}
	for _, bad := range []string{"<script", "fonts.googleapis.com", "fonts.gstatic.com", "EventSource", `method="post"`, "/approve", "/reject", "#ZgotmplZ"} {
		if strings.Contains(body, bad) {
			t.Errorf("native page contains forbidden or invalid content %q", bad)
		}
	}
	return body
}

func nativeSnapshot(t *testing.T, db *store.Store) string {
	t.Helper()
	ctx := context.Background()
	findings, err := db.QueryFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assets, err := db.QueryAssets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := db.QueryIngestRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshots, err := db.ListThreatSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{db.List(), findings, assets, runs, snapshots}
	for _, finding := range findings {
		observations, err := db.QueryObservations(ctx, finding.ID)
		if err != nil {
			t.Fatal(err)
		}
		events, err := db.QueryEvents(ctx, finding.ID)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, observations, events)
	}
	body, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestNativeConsoleListFiltersProvenanceAndPagingAreReadOnly(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	anchor := seedConsoleDependabot(t, db, "service", 1, "CVE-2099-0001")
	trivy, nativeID := seedConsoleTrivy(t, db)
	seedAPIFinding(t, db, "resolved", 2, model.SeverityLow, "fixed")
	detail, err := db.GetFindingDetail(context.Background(), anchor)
	if err != nil {
		t.Fatal(err)
	}
	before := nativeSnapshot(t, db)
	for _, tc := range []struct {
		query string
		want  string
		omit  string
	}{
		{"", anchor, ""},
		{"source=dependabot", anchor, trivy},
		{"source=trivy", trivy, anchor},
		{"source_status=resolved", "package-resolved", anchor},
		{"severity=low", "package-resolved", anchor},
		{"asset_id=" + url.QueryEscape(detail.Asset.ID), anchor, trivy},
		{"cve=cve-2099-0001", trivy, "package-resolved"},
		{"q=" + url.QueryEscape(nativeID), trivy, anchor},
		{"q=example%2Fservice%3A1&source=dependabot&severity=high&source_status=active&cve=CVE-2099-0001&asset_id=" + url.QueryEscape(detail.Asset.ID), anchor, trivy},
		{"q=%25", "一致する Finding がありません", anchor},
		{"q=%27%20OR%201%3D1%20--", "一致する Finding がありません", anchor},
		{"source=&severity=&source_status=&asset_id=&cve=&q=&limit=50", anchor, ""},
		{"limit=200&offset=1000000", "一致する Finding がありません", anchor},
	} {
		t.Run(tc.query, func(t *testing.T) {
			body := nativeConsoleRequest(t, srv, http.MethodGet, "/findings?"+tc.query, http.StatusOK)
			if !strings.Contains(body, tc.want) || tc.omit != "" && strings.Contains(body, tc.omit) {
				t.Fatalf("filter %q missing %q or contains excluded %q", tc.query, tc.want, tc.omit)
			}
		})
	}
	body := nativeConsoleRequest(t, srv, http.MethodGet, "/findings?source=dependabot&limit=1", http.StatusOK)
	if !strings.Contains(body, `rel="next" href="/findings?limit=1&amp;offset=1&amp;source=dependabot"`) {
		t.Fatal("next page did not preserve filter or escape its URL")
	}
	body = nativeConsoleRequest(t, srv, http.MethodGet, "/findings?source=dependabot&limit=1&offset=1", http.StatusOK)
	if !strings.Contains(body, `rel="prev" href="/findings?limit=1&amp;offset=0&amp;source=dependabot"`) {
		t.Fatal("previous page did not preserve filter")
	}
	body = nativeConsoleRequest(t, srv, http.MethodGet, "/findings", http.StatusOK)
	for _, text := range []string{"検出元の状態", "ローカルトリアージ", "このページの Active", "このページの Resolved", "表示中の検出元", "example/service:1", html.EscapeString(nativeID)} {
		if !strings.Contains(body, text) {
			t.Errorf("native list missing %q", text)
		}
	}
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("native list changed source/triage/evidence/ingestion/legacy state")
	}
}

func TestNativeConsoleDetailShowsIndependentEvidenceAndRelatedLinks(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	anchor := seedConsoleDependabot(t, db, "service", 1, "CVE-2099-0001")
	other := seedConsoleDependabot(t, db, "other", 2, "CVE-2099-0001")
	trivy, _ := seedConsoleTrivy(t, db)
	before := nativeSnapshot(t, db)
	body := nativeConsoleRequest(t, srv, http.MethodGet, "/findings/"+anchor, http.StatusOK)
	for _, text := range []string{"example/service:1", "検出元の状態", "active", "ローカルトリアージ", "new", "Asset", "証拠参照", "Fingerprint:", "finding.created", "同じ CVE", `href="/findings/` + other + `"`, `href="/findings/` + trivy + `"`, `action="/api/v1/findings/` + anchor + `/priority-preview"`, `name="as_of"`, "/related?limit=20"} {
		if !strings.Contains(body, text) {
			t.Errorf("native detail missing %q", text)
		}
	}
	if strings.Contains(body, `href="/alerts/`+anchor) {
		t.Fatal("normalized finding ID used in legacy approval flow")
	}
	body = nativeConsoleRequest(t, srv, http.MethodGet, "/findings/"+anchor+"?limit=1", http.StatusOK)
	if !strings.Contains(body, `offset=1#related`) || strings.Count(body, `class="finding-item"`) != 1 {
		t.Fatal("related findings are not bounded/paged")
	}
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("native detail or related reads changed source/triage/evidence/legacy state")
	}
}

func TestNativeConsoleEnrichmentKeepsZeroUnknownAndSeparateFreshness(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "signals", 1, model.SeverityHigh, "open")
	now := time.Now().UTC()
	old := now.Add(-120 * time.Hour)
	input := "#model_version:synthetic.1,score_date:" + old.Format("2006-01-02") + "\ncve,epss,percentile\nCVE-2026-0001,0,0\n"
	importAPIEnrichment(t, db, "epss", input, old, 801)
	page, err := db.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 50})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("findings=%+v err=%v", page, err)
	}
	path := "/findings/" + page.Items[0].ID
	body := nativeConsoleRequest(t, srv, http.MethodGet, path, http.StatusOK)
	for _, text := range []string{"0%", "Stale / 時点外", "証拠なし", "synthetic.1", old.Format(time.RFC3339Nano)} {
		if !strings.Contains(body, text) {
			t.Errorf("EPSS zero / KEV unknown missing %q", text)
		}
	}
	kev := fmt.Sprintf(`{"catalogVersion":"synthetic.2","dateReleased":%q,"count":1,"vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":%q}]}`, now.Add(-time.Minute).Format(time.RFC3339Nano), old.Format("2006-01-02"))
	importAPIEnrichment(t, db, "kev", kev, now, 802)
	before := nativeSnapshot(t, db)
	body = nativeConsoleRequest(t, srv, http.MethodGet, path, http.StatusOK)
	for _, text := range []string{"0%", "Stale / 時点外", "Fresh", "掲載あり", "synthetic.2", old.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)} {
		if !strings.Contains(body, text) {
			t.Errorf("independent evidence missing %q", text)
		}
	}
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("rendering enrichments changed stored source or legacy data")
	}
	// KEV false is not evidence of non-membership.
	_, signal := nativeFindingSignals(&model.FindingEnrichment{KEV: &model.SecurityEnrichmentEvidence{KEV: false, Fresh: true}})
	if signal.Value != "不明" {
		t.Fatal("KEV false was treated as a verified negative")
	}
}

func TestNativeConsoleNoCVEEmptyMissingAndInvalidRequests(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	nativeConsoleRequest(t, srv, http.MethodGet, "/findings", http.StatusOK)
	anchor := seedConsoleDependabot(t, db, "ghsa", 1, "GHSA-synthetic-example")
	body := nativeConsoleRequest(t, srv, http.MethodGet, "/findings/"+anchor, http.StatusOK)
	if !strings.Contains(body, "明示的な CVE がないため関連付けしません") || strings.Contains(body, `class="finding-item"`) {
		t.Fatal("non-CVE finding was correlated")
	}
	for _, query := range []string{"unknown=x", "q=x&q=y", "source=&source=trivy", "severity=urgent", "source_status=closed", "source=bad+source", "cve=GHSA-example", "cve=CVE-2026-0001&cve=CVE-2026-0002", "q=%00", "q=%FF", "q=%", "limit=", "limit=0", "limit=201", "offset=1000001", "asset_id=" + strings.Repeat("a", 129), "q=" + strings.Repeat("a", 257), "q=" + strings.Repeat("a", 4097)} {
		t.Run(query, func(t *testing.T) {
			nativeConsoleRequest(t, srv, http.MethodGet, "/findings?"+query, http.StatusBadRequest)
		})
	}
	for _, query := range []string{"cve=CVE-2099-0001", "source=trivy", "q=x", "limit=201", "limit=0", "offset=1000001", "offset=0&offset=1", "limit=%FF"} {
		nativeConsoleRequest(t, srv, http.MethodGet, "/findings/"+anchor+"?"+query, http.StatusBadRequest)
	}
	for _, path := range []string{"/findings/", "/findings/not-a-uuid", "/findings/00000000-0000-0000-0000-000000000000", "/findings/" + anchor + "/approve"} {
		nativeConsoleRequest(t, srv, http.MethodGet, path, http.StatusNotFound)
	}
	before := nativeSnapshot(t, db)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, "BREW"} {
		for _, path := range []string{"/findings", "/findings/" + anchor} {
			nativeConsoleRequest(t, srv, method, path, http.StatusMethodNotAllowed)
		}
	}
	nativeConsoleRequest(t, srv, http.MethodHead, "/findings", http.StatusOK)
	nativeConsoleRequest(t, srv, http.MethodHead, "/findings/"+anchor, http.StatusOK)
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("invalid methods or HEAD changed persisted data")
	}
}

func TestNativeConsoleEscapesUntrustedTextAndNeverLinksEvidenceURLs(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	malicious := `<script>alert("synthetic")</script><img src=x onerror=alert(1)>`
	at := time.Now().UTC()
	record := &model.AlertRecord{Alert: model.Alert{Owner: "example", Repo: "escaping", Number: 1, State: "open", Summary: malicious, PackageName: malicious, CVEID: "CVE-2026-0001", Severity: model.SeverityHigh, HTMLURL: "javascript:alert(1)", CreatedAt: at, UpdatedAt: at}, NotifiedAt: at}
	if _, err := db.SaveObservedWithError(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	page, err := db.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 50})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	for _, path := range []string{"/findings", "/findings?q=" + url.QueryEscape(malicious), "/findings/" + page.Items[0].ID} {
		body := nativeConsoleRequest(t, srv, http.MethodGet, path, http.StatusOK)
		if !strings.Contains(body, "&lt;script&gt;") || strings.Contains(body, malicious) || strings.Contains(body, `href="javascript:`) || strings.Contains(body, `src="x"`) {
			t.Fatalf("unsafe or missing escaped content on %s", path)
		}
	}
}

func TestNativeConsoleEvidenceHistoryIsBoundedAndTruncationIsVisible(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	at := time.Now().UTC().Add(-time.Hour)
	record := &model.AlertRecord{Alert: model.Alert{Owner: "example", Repo: "history", Number: 1, State: "open", CVEID: "CVE-2026-0001", Severity: model.SeverityHigh, CreatedAt: at}, NotifiedAt: at}
	for i := 0; i < 201; i++ {
		record.Alert.Summary = fmt.Sprintf("Synthetic change %d", i)
		record.Alert.UpdatedAt = at.Add(time.Duration(i) * time.Second)
		if _, err := db.SaveObservedWithError(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	page, err := db.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 50})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	id := page.Items[0].ID
	detail, err := db.GetFindingDetail(context.Background(), id)
	if err != nil || !detail.EventsTruncated || !detail.ObservationsTruncated || len(detail.Events) != 200 || len(detail.Observations) != 200 {
		t.Fatalf("truncation observation=%d event=%d flags=%v/%v err=%v", len(detail.Observations), len(detail.Events), detail.ObservationsTruncated, detail.EventsTruncated, err)
	}
	before := nativeSnapshot(t, db)
	body := nativeConsoleRequest(t, srv, http.MethodGet, "/findings/"+id, http.StatusOK)
	if strings.Count(body, "最新 200 件のみ表示しています") != 2 || strings.Count(body, "Fingerprint:") != 200 {
		t.Fatal("bounded evidence or separate truncation messages missing")
	}
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("history render mutated retained evidence")
	}
}

func TestNativeConsoleStorageErrorsAreBoundedAndLegacyPolicyIsPreserved(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	anchor := seedConsoleDependabot(t, db, "service", 1, "CVE-2099-0001")
	body := findingsAPIRequest(t, srv, http.MethodGet, "/", http.StatusOK).Body.String()
	if !strings.Contains(body, `href="/findings"`) || !strings.Contains(body, "EventSource") || !strings.Contains(body, `class="findings-console legacy-console"`) {
		t.Fatal("legacy navigation or live update shell changed unexpectedly")
	}
	for _, path := range []string{"/settings/repositories/exclude", "/reports/vulnerabilities/refresh"} {
		findingsAPIRequest(t, srv, http.MethodPost, path, http.StatusForbidden)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/findings", "/findings/" + anchor} {
		body := nativeConsoleRequest(t, srv, http.MethodGet, path, http.StatusInternalServerError)
		if strings.Contains(body, "sql:") || strings.Contains(body, "database is closed") || strings.Contains(body, anchor) {
			t.Fatal("storage failure exposed internal details or request data")
		}
	}
}

func TestNativeConsoleTemplateUsesScopedResponsiveTokensAndProductionHandler(t *testing.T) {
	layout, err := templateFS.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{".findings-console {", "--color-bg: var(--md-sys-color-surface)", "@media (max-width: 760px)", "@media (max-width: 440px)", "prefers-reduced-motion", ":focus-visible"} {
		if !strings.Contains(string(layout), text) {
			t.Errorf("responsive/accessibility contract missing %q", text)
		}
	}
	for _, name := range []string{"findings.html", "finding_detail.html", "findings_shell.html", "findings_error.html"} {
		body, err := templateFS.ReadFile("templates/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `style=`) || strings.Contains(string(body), "<script") {
			t.Errorf("%s added inline decoration or scripts", name)
		}
	}
	server, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	start := string(server)[strings.Index(string(server), "func (s *Server) Start("):]
	if !strings.Contains(start, "Handler: s.Handler()") || strings.Contains(start, "http.NewServeMux()") {
		t.Fatal("production Start diverged from the tested common Handler")
	}
	// Direct renderer test also covers the empty evidence state without a DB.
	srv := &Server{}
	w := httptest.NewRecorder()
	srv.renderNativeFindings(w, httptest.NewRequest(http.MethodGet, "/findings/example", nil), http.StatusOK, "finding_detail.html", nativeFindingDetailPage{Title: "Finding 詳細"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "観測証拠はありません") || !strings.Contains(w.Body.String(), "履歴はありません") {
		t.Fatal("empty detail template failed")
	}
}
