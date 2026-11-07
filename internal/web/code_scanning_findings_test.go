package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestCodeScanningOfflineImportAppearsInReadAPIWithoutChangingDependabot(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "repo", 42, model.SeverityHigh, "open")
	at := time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	id := "00000000-0000-8000-8000-000000000001"
	input := `[{"number":42,"state":"dismissed","rule":{"id":"go/example","security_severity_level":"high","description":"PRIVATE-TOKEN"},"tool":{"name":"CodeQL"},"most_recent_instance":{"location":{"path":"src/example.go","start_line":12},"message":{"text":"PRIVATE-TOKEN"}}}]`
	items, err := adapter.ParseCodeScanningJSON(strings.NewReader(input), adapter.CodeScanningOptions{Repository: "example/repo", RunID: id, ObservedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	run := model.IngestRun{ID: id, Connector: "github_code_scanning", Scope: "example/repo", StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + strings.Repeat("a", 64)}
	if _, err := db.ImportSecurityFindings(context.Background(), run, items); err != nil {
		t.Fatal(err)
	}
	w := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?source=github_code_scanning&q=src%2Fexample.go&source_status=suppressed", http.StatusOK)
	page := decodeFindingPage(t, w)
	if page.Total != 1 || page.Items[0].RuleID != "go/example" || page.Items[0].StartLine != 12 {
		t.Fatalf("page=%+v", page)
	}
	detailResponse := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/"+items[0].Finding.ID, http.StatusOK)
	assertFindingsJSON(t, detailResponse)
	var detail findingAPIDetail
	if err := json.Unmarshal(detailResponse.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Observations) != 1 || len(detail.Events) != 1 || detail.Observations[0].Source != "github_code_scanning" || strings.Contains(detailResponse.Body.String(), "PRIVATE-TOKEN") {
		t.Fatalf("detail=%s", detailResponse.Body.String())
	}
	assets := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/assets", http.StatusOK)
	var assetPage assetAPIPage
	if err := json.Unmarshal(assets.Body.Bytes(), &assetPage); err != nil {
		t.Fatal(err)
	}
	if assetPage.Total != 1 {
		t.Fatal("same GitHub repository duplicated as asset")
	}
	if len(db.List()) != 1 || db.List()[0].Alert.State != "open" {
		t.Fatal("Dependabot native state modified")
	}
}
