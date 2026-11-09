package web

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestSecurityOverviewFixedClockGlobalCountsAndPartialCollection(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	id := seedConsoleDependabot(t, db, "service", 1, "CVE-2099-0001")
	seedConsoleTrivy(t, db)
	at := time.Date(2026, 11, 9, 12, 34, 56, 123, time.UTC)
	calls := 0
	srv.consoleNow = func() time.Time { calls++; return at }
	before := nativeSnapshot(t, db)
	body := nativeConsoleRequest(t, srv, http.MethodGet, "/security", http.StatusOK)
	for _, want := range []string{"すべての保存済み共通 Findings", at.Format(time.RFC3339Nano), id, "Active Findings", "保存済み Assets", "稼働状況は不明", "未集計"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview missing %q", want)
		}
	}
	if calls != 1 {
		t.Fatalf("overview clock called %d times", calls)
	}
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("overview changed persisted records")
	}
	nativeConsoleRequest(t, srv, http.MethodHead, "/security", http.StatusOK)
	nativeConsoleRequest(t, srv, http.MethodGet, "/security?limit=1", http.StatusBadRequest)
}

func TestConsoleAssetsFiltersLinksAndNoMutation(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	id := seedConsoleDependabot(t, db, "service", 1, "CVE-2099-0001")
	seedConsoleDependabot(t, db, "other", 2, "CVE-2099-0002")
	seedConsoleTrivy(t, db)
	detail, err := db.GetFindingDetail(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	before := nativeSnapshot(t, db)
	body := nativeConsoleRequest(t, srv, http.MethodGet, "/assets?provider=github&limit=1", http.StatusOK)
	for _, want := range []string{`rel="next" href="/assets?limit=1&amp;offset=1&amp;provider=github"`, "assets_query=", "Account", "未管理・未検査"} {
		if !strings.Contains(body, want) {
			t.Errorf("assets missing %q", want)
		}
	}
	target := "/assets/" + detail.Asset.ID + "?" + url.Values{"source": {"dependabot"}, "assets_query": {"q=example&provider=github&limit=1&offset=1"}}.Encode()
	body = nativeConsoleRequest(t, srv, http.MethodGet, target, http.StatusOK)
	for _, want := range []string{id, detail.Asset.NativeID, `href="/findings?asset_id=` + detail.Asset.ID, `source=dependabot`, "offset=1&amp;provider=github", `aria-current="page">Assets`} {
		if !strings.Contains(body, want) {
			t.Errorf("asset detail missing %q", want)
		}
	}
	nativeConsoleRequest(t, srv, http.MethodHead, target, http.StatusOK)
	for _, path := range []string{"/assets?limit=201", "/assets?q=x&q=y", "/assets?provider=%00", "/assets/" + detail.Asset.ID + "?assets_query=" + url.QueryEscape("https://evil.test")} {
		nativeConsoleRequest(t, srv, http.MethodGet, path, http.StatusBadRequest)
	}
	for _, path := range []string{"/assets/not-an-id", "/assets/", "/assets/extra/path", "/security/unknown", "/integrations/unknown"} {
		nativeConsoleRequest(t, srv, http.MethodGet, path, http.StatusNotFound)
	}
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("asset reads changed persisted records")
	}
}

func TestRecordedIntegrationsExplicitClockFailureFutureAndAllSources(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for _, source := range []string{"dependabot", "trivy", "github_code_scanning", "github_secret_scanning", "epss_offline", "kev_offline"} {
		run, err := db.StartIngestRun(ctx, source, "example/<scope>&identity", at.Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := db.FinishIngestRun(ctx, run.ID, "success", "partial", "", at.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	failed, err := db.StartIngestRun(ctx, "dependabot", "example/<scope>&identity", at.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishIngestRun(ctx, failed.ID, "failed", "unknown", "private_error_sentinel", at); err != nil {
		t.Fatal(err)
	}
	future, err := db.StartIngestRun(ctx, "trivy", "future", at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishIngestRun(ctx, future.ID, "success", "partial", "", at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartIngestRun(ctx, "trivy", "running", at.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	before := nativeSnapshot(t, db)
	body := nativeConsoleRequest(t, srv, http.MethodGet, "/integrations", http.StatusOK)
	if !strings.Contains(body, "評価時点を指定してください") || strings.Contains(body, failed.ID) {
		t.Fatal("integrations chose an implicit clock")
	}
	target := "/integrations?as_of=" + at.Format(time.RFC3339Nano)
	body = nativeConsoleRequest(t, srv, http.MethodGet, target, http.StatusOK)
	for _, want := range []string{failed.ID, future.ID, "記録状態: failed", "記録状態: unknown", "記録状態: running", "最後の成功 receipt", "オフライン receipt 経路", "liveness", "全リクエスト数・全失敗数ではありません", html.EscapeString("example/<scope>&identity"), "epss_offline", "kev_offline", "github_code_scanning", "github_secret_scanning"} {
		if !strings.Contains(body, want) {
			t.Errorf("recorded integrations missing %q", want)
		}
	}
	if strings.Contains(body, "private_error_sentinel") {
		t.Fatal("recorded view leaked error")
	}
	body = nativeConsoleRequest(t, srv, http.MethodGet, target+"&limit=1", http.StatusOK)
	if !strings.Contains(body, `as_of=2026-11-09T12%3A00%3A00Z&amp;limit=1&amp;offset=1`) {
		t.Fatal("integration paging lost explicit clock")
	}
	for _, suffix := range []string{"?as_of=bad", "?as_of=2026-11-09T12:00:00%2B24:00", "?as_of=2026-11-09T12:00:00,1Z", "?source=trivy", "?as_of=2026-11-09T12:00:00Z&scope=%20bad", "?as_of=2026-11-09T12:00:00Z&source=unknown", "?as_of=2026-11-09T12:00:00Z&limit=201"} {
		nativeConsoleRequest(t, srv, http.MethodGet, "/integrations"+suffix, http.StatusBadRequest)
	}
	nativeConsoleRequest(t, srv, http.MethodHead, target, http.StatusOK)
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("recorded integrations changed persisted records")
	}
}

func TestSecurityConsoleMethodsSharedShellAndTemplateEscaping(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	for _, path := range []string{"/security", "/assets", "/integrations"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions, http.MethodTrace, http.MethodConnect} {
			nativeConsoleRequest(t, srv, method, path, http.StatusMethodNotAllowed)
		}
	}
	body := findingsAPIRequest(t, srv, http.MethodGet, "/", http.StatusOK).Body.String()
	for _, want := range []string{`class="findings-console legacy-console"`, `href="/security"`, `href="/assets"`, `href="/integrations"`, "Alerts / 承認", "EventSource"} {
		if !strings.Contains(body, want) {
			t.Errorf("shared legacy shell missing %q", want)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/security", "/assets", "/integrations?as_of=2026-11-09T12:00:00Z"} {
		body := nativeConsoleRequest(t, srv, http.MethodGet, path, http.StatusInternalServerError)
		if strings.Contains(body, "database is closed") || strings.Contains(body, "sql:") {
			t.Fatal("storage error leaked internals")
		}
	}
}

func TestConsoleTemplatesEscapeSavedIdentityAndScope(t *testing.T) {
	bad := `javascript:alert('<img src=x onerror=alert(1)>')`
	data := nativeAssetsPage{Title: "Assets", Query: store.ConsoleAssetQuery{Limit: 50}, Page: store.ConsoleAssetPage{Items: []store.ConsoleAssetItem{{Asset: model.Asset{ID: "00000000-0000-4000-8000-000000000001", NativeID: bad, Account: bad}}}, Total: 1, Limit: 50}}
	srv := &Server{}
	w := httptest.NewRecorder()
	srv.renderNativeFindings(w, httptest.NewRequest(http.MethodGet, "/assets", nil), http.StatusOK, "assets.html", data)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, html.EscapeString(bad)) || strings.Contains(body, `href="javascript:`) || strings.Contains(body, "<img") || strings.Contains(body, "#ZgotmplZ") {
		t.Fatalf("asset identity not escaped: status=%d", w.Code)
	}
}

func TestSecurityOverviewCollectionFailureIsExplicitPartialError(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	id := seedConsoleDependabot(t, db, "partial", 1, "CVE-2099-0001")
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	srv.consoleNow = func() time.Time { return at }
	// Synthetic invalid scalar metadata exercises an independent K269 summary
	// failure without breaking the correctly retained Finding/Asset snapshot.
	if _, err := db.StartIngestRun(context.Background(), "synthetic_unknown_source", "synthetic-scope", at); err != nil {
		t.Fatal(err)
	}
	before := nativeSnapshot(t, db)
	body := nativeConsoleRequest(t, srv, http.MethodGet, "/security", http.StatusOK)
	if !strings.Contains(body, id) || !strings.Contains(body, "部分エラー") || strings.Contains(body, "synthetic_unknown_source") {
		t.Fatal("collection error hid valid findings or leaked invalid metadata")
	}
	if after := nativeSnapshot(t, db); after != before {
		t.Fatal("partial summary read mutated records")
	}
}

func TestNativeConsoleShowsEveryActualFindingSourceAndAssetIdentity(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	seedConsoleDependabot(t, db, "multi", 1, "CVE-2099-0001")
	seedConsoleTrivy(t, db)
	for i, source := range []string{"github_code_scanning", "github_secret_scanning"} {
		runID := fmt.Sprintf("00000000-0000-4000-8000-%012d", 201+i)
		var items []model.SecurityFinding
		var err error
		if source == "github_code_scanning" {
			items, err = adapter.ParseCodeScanningJSON(strings.NewReader(`[{"number":1,"state":"open","rule":{"id":"synthetic/rule","security_severity_level":"high"},"tool":{"name":"Synthetic"},"most_recent_instance":{"location":{"path":"src/synthetic.go","start_line":1}}}]`), adapter.CodeScanningOptions{Repository: "example/multi", RunID: runID, ObservedAt: at})
		} else {
			items, err = adapter.ParseSecretScanningJSON(strings.NewReader(`[{"number":1,"state":"open","secret_type":"synthetic_example","secret":null}]`), adapter.SecretScanningOptions{Repository: "example/multi", RunID: runID, ObservedAt: at})
		}
		if err != nil {
			t.Fatal(err)
		}
		run := model.IngestRun{ID: runID, Connector: source, Scope: "example/multi", StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + strings.Repeat("a", 64)}
		if _, err := db.ImportSecurityFindings(ctx, run, items); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{"dependabot", "trivy", "github_code_scanning", "github_secret_scanning"} {
		page, err := db.QueryFindingsPage(ctx, store.FindingQuery{Source: source, Limit: 200})
		if err != nil || page.Total == 0 {
			t.Fatalf("source fixture %s missing: %+v %v", source, page, err)
		}
		body := nativeConsoleRequest(t, srv, http.MethodGet, "/findings?source="+source, http.StatusOK)
		for _, item := range page.Items {
			if !strings.Contains(body, item.ID) || !strings.Contains(body, html.EscapeString(item.SourceFindingID)) {
				t.Errorf("%s lost source-native Finding identity", source)
			}
		}
		body = nativeConsoleRequest(t, srv, http.MethodGet, "/assets?source="+source, http.StatusOK)
		assetLink := consoleTemplateFuncs("assets.html")["consoleAssetURL"].(func(string, store.ConsoleAssetQuery) string)(page.Items[0].AssetID, store.ConsoleAssetQuery{Source: source, Limit: 50})
		linked, err := url.Parse(assetLink)
		if err != nil || linked.Query().Get("source") != source {
			t.Fatalf("asset link lost source %s: %s", source, assetLink)
		}
		detailBody := nativeConsoleRequest(t, srv, http.MethodGet, assetLink, http.StatusOK)
		if !strings.Contains(detailBody, "source="+source) {
			t.Errorf("%s lost common Finding filter link", source)
		}
		if !strings.Contains(body, page.Items[0].AssetID) {
			t.Errorf("%s lost Asset association", source)
		}
	}
}

func TestConsoleAssetGeneratedLongQueriesReachDetailAndBack(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	id := seedConsoleDependabot(t, db, "roundtrip", 1, "CVE-2099-0001")
	detail, err := db.GetFindingDetail(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{strings.Repeat("#", 256), strings.Repeat("界", 85) + "#"} {
		input := url.Values{"q": {value}, "provider": {value}, "account": {value}, "region": {value}, "source": {"dependabot"}, "limit": {"50"}, "offset": {"0"}}
		query, err := parseConsoleAssetQuery(input.Encode())
		if err != nil {
			t.Fatal(err)
		}
		link := consoleTemplateFuncs("assets.html")["consoleAssetURL"].(func(string, store.ConsoleAssetQuery) string)(detail.Asset.ID, query)
		parsed, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		if len(parsed.RawQuery) <= findingsAPIMaxRawQuery {
			t.Fatal("fixture did not exercise the expanded outer budget")
		}
		if _, err := parseFindingsAPIValues(parsed.RawQuery, "assets_query", "source"); err == nil {
			t.Fatal("existing API query limit was widened")
		}
		body := nativeConsoleRequest(t, srv, http.MethodGet, link, http.StatusOK)
		back := "/assets?" + consoleAssetValues(query).Encode()
		if !strings.Contains(body, `href="`+html.EscapeString(back)+`"`) || !strings.Contains(body, id) {
			t.Fatal("generated detail/Back round trip lost canonical filters or Finding")
		}
		nativeConsoleRequest(t, srv, http.MethodGet, back, http.StatusOK)
	}
	// Clearing the outer Finding source must not inherit the original list's
	// trivy source. A retained Dependabot Finding must still be shown.
	list := url.Values{"source": {"trivy"}, "limit": {"50"}, "offset": {"0"}}
	for _, blank := range []bool{false, true} {
		parsed, _ := url.Parse(consoleAssetDetailURL(detail.Asset.ID, list, ""))
		outer := parsed.Query()
		if blank {
			outer.Set("source", "")
		}
		body := nativeConsoleRequest(t, srv, http.MethodGet, parsed.Path+"?"+outer.Encode(), http.StatusOK)
		if !strings.Contains(body, id) {
			t.Fatal("cleared Finding source was re-bound to the Back list's source")
		}
		if !strings.Contains(body, `href="/findings?asset_id=`+detail.Asset.ID+`&amp;limit=50&amp;offset=0"`) {
			t.Fatal("all-sources common Finding link was re-bound")
		}
	}
	rawValue := strings.Repeat("界", 85) + "x"
	raw := "q=" + rawValue + "&provider=" + rawValue + "&account=" + rawValue + "&region=" + rawValue + "&environment=" + rawValue + "&criticality=" + rawValue
	if _, err := parseConsoleAssetQuery(raw); err == nil {
		t.Fatal("noncanonical list query can still generate an oversized Back link")
	}
}

func TestSharedConsoleLegacyHandlersKeepProductionDataShapesSSEAndCSRF(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "legacy-shape", 1, model.SeverityHigh, "open")
	records := db.List()
	if len(records) != 1 {
		t.Fatal("legacy fixture missing")
	}
	db.AddLog(model.LogEntry{Timestamp: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC), Level: "info", Message: "synthetic <legacy log>"})
	for _, target := range []string{"/", "/?view=repo", "/alerts/" + fmt.Sprint(records[0].Alert.ID), "/logs", "/settings", "/settings/connectivity", "/reports/vulnerabilities"} {
		body := findingsAPIRequest(t, srv, http.MethodGet, target, http.StatusOK).Body.String()
		if !strings.Contains(body, `class="findings-console legacy-console"`) || !strings.Contains(body, `href="/security"`) || !strings.Contains(body, `href="/assets"`) {
			t.Errorf("legacy production DTO/shell failed for %s", target)
		}
		if strings.Contains(body, "#ZgotmplZ") {
			t.Errorf("legacy URL escaping failed for %s", target)
		}
	}
	for _, target := range []string{"/settings/repositories/exclude", "/settings/rss/config", "/reports/vulnerabilities/refresh"} {
		findingsAPIRequest(t, srv, http.MethodPost, target, http.StatusForbidden)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/logs-stream", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatal("legacy log SSE routing changed")
	}
}
