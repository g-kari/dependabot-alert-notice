package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestTrivyImportAndDependabotRemainSeparateThroughFindingsAPI(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	ctx := context.Background()
	body, err := os.ReadFile("../adapter/testdata/trivy-v2-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	runID := "00000000-0000-8000-8000-000000000001"
	items, err := adapter.ParseTrivyJSON(strings.NewReader(string(body)), adapter.TrivyOptions{Scope: "example-project", RunID: runID, ObservedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	run := model.IngestRun{ID: runID, Connector: "trivy", Scope: "example-project", StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + hex.EncodeToString(digest[:])}
	if _, err := db.ImportSecurityFindings(ctx, run, items); err != nil {
		t.Fatal(err)
	}
	if result, err := db.ImportSecurityFindings(ctx, run, items); err != nil || !result.Replay {
		t.Fatalf("replay=%+v err=%v", result, err)
	}
	legacy := &model.AlertRecord{Alert: model.Alert{Owner: "example", Repo: "service", Number: 1, CVEID: "CVE-2099-0001", PackageName: "synthetic-package", Severity: model.SeverityHigh, CreatedAt: at}, State: model.AlertStateApproved, EvalStatus: model.EvalStatusDone, NotifiedAt: at, SlackMessageTS: "retained", Evaluation: &model.Evaluation{Recommendation: "approve"}}
	if _, err := db.SaveObservedWithError(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	all := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?q=CVE-2099-0001", http.StatusOK)
	var page findingAPIPage
	if err := json.Unmarshal(all.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || page.Items[0].ID == page.Items[1].ID {
		t.Fatalf("source identities merged: %+v", page)
	}
	scoped := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?source=trivy&q=synthetic-package", http.StatusOK)
	if err := json.Unmarshal(scoped.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Items[0].SourceStatus != "active" || page.Items[0].FixedVersion != "1.0.1" {
		t.Fatalf("Trivy metadata/lifecycle=%+v", page)
	}
	detailResponse := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/"+page.Items[0].ID, http.StatusOK)
	var detail findingAPIDetail
	if err := json.Unmarshal(detailResponse.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Asset.Type != "container_image" || len(detail.Observations) != 1 || detail.Observations[0].Source != "trivy" || len(detail.Events) != 1 || detail.Events[0].Actor != "trivy" {
		t.Fatalf("Trivy evidence=%+v", detail)
	}
	got, err := db.Get(legacy.Alert.ID)
	if err != nil || got.State != model.AlertStateApproved || got.EvalStatus != model.EvalStatusDone || got.Evaluation == nil || got.SlackMessageTS != "retained" || len(db.List()) != 1 {
		t.Fatalf("legacy workflow changed: %+v %v", got, err)
	}
}
