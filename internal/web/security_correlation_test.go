package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/adapter"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

type consoleFinding struct {
	model.Finding
	Source          string `json:"source"`
	SourceFindingID string `json:"source_finding_id"`
}
type consolePage struct {
	Items       []consoleFinding                   `json:"items"`
	Total       int                                `json:"total"`
	Limit       int                                `json:"limit"`
	Offset      int                                `json:"offset"`
	Enrichments map[string]model.FindingEnrichment `json:"enrichments"`
}
type relatedConsolePage struct {
	consolePage
	AnchorID     string `json:"anchor_id"`
	CVEID        string `json:"cve_id"`
	Relationship string `json:"relationship"`
}

func seedConsoleDependabot(t *testing.T, db *store.Store, repo string, number int, advisory string) string {
	t.Helper()
	at := time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	record := model.AlertRecord{Alert: model.Alert{Owner: "example", Repo: repo, Number: number, State: "open", PackageName: "synthetic-package", Severity: model.SeverityHigh, CreatedAt: at, UpdatedAt: at}, State: model.AlertStateApproved, EvalStatus: model.EvalStatusDone, NotifiedAt: at, SlackMessageTS: "retained"}
	if strings.HasPrefix(advisory, "CVE-") {
		record.Alert.CVEID = advisory
	} else {
		record.Alert.GHSAID = advisory
	}
	if _, err := db.SaveObservedWithError(context.Background(), &record); err != nil {
		t.Fatal(err)
	}
	normalized, err := adapter.NormalizeDependabot(record, "synthetic", at)
	if err != nil {
		t.Fatal(err)
	}
	return normalized.Finding.ID
}
func seedConsoleTrivy(t *testing.T, db *store.Store) (string, string) {
	t.Helper()
	body, err := os.ReadFile("../adapter/testdata/trivy-v2-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)
	id := "00000000-0000-8000-8000-000000000099"
	items, err := adapter.ParseTrivyJSON(strings.NewReader(string(body)), adapter.TrivyOptions{Scope: "console-synthetic", RunID: id, ObservedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	run := model.IngestRun{ID: id, Connector: "trivy", Scope: "console-synthetic", StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + hex.EncodeToString(digest[:])}
	if _, err := db.ImportSecurityFindings(context.Background(), run, items); err != nil {
		t.Fatal(err)
	}
	return items[0].Finding.ID, items[0].Observation.SourceFindingID
}
func decodeConsolePage(t *testing.T, body []byte) consolePage {
	t.Helper()
	var p consolePage
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFindingsConsoleReceivesUnifiedProvenanceAndNativeIDSearch(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	anchor := seedConsoleDependabot(t, db, "service", 1, "CVE-2099-0001")
	trivyID, nativeID := seedConsoleTrivy(t, db)
	page := decodeConsolePage(t, findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?cve=cve-2099-0001", http.StatusOK).Body.Bytes())
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("page=%+v", page)
	}
	for _, f := range page.Items {
		switch f.ID {
		case anchor:
			if f.Source != "dependabot" || f.SourceFindingID != "example/service:1" {
				t.Fatalf("native=%+v", f)
			}
		case trivyID:
			if f.Source != "trivy" || f.SourceFindingID != nativeID {
				t.Fatalf("native=%+v", f)
			}
		default:
			t.Fatal("finding identity changed")
		}
	}
	for native, want := range map[string]string{"example/service:1": anchor, nativeID: trivyID} {
		r := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?q="+url.QueryEscape(native), http.StatusOK)
		p := decodeConsolePage(t, r.Body.Bytes())
		if p.Total != 1 || p.Items[0].ID != want {
			t.Fatalf("native search=%s", r.Body.String())
		}
	}
	response := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/"+anchor, http.StatusOK)
	var detail struct {
		Finding consoleFinding `json:"finding"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Finding.Source != "dependabot" || detail.Finding.SourceFindingID != "example/service:1" {
		t.Fatal("detail provenance missing")
	}
	assertFindingsJSON(t, response)
}

func TestRelatedFindingsArePaginatedAssociationsWithoutMergingSourcesOrChangingLegacy(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	anchor := seedConsoleDependabot(t, db, "service", 1, "CVE-2099-0001")
	other := seedConsoleDependabot(t, db, "other", 2, "CVE-2099-0001")
	seedConsoleDependabot(t, db, "different", 3, "CVE-2099-0002")
	trivyID, _ := seedConsoleTrivy(t, db)
	before, err := json.Marshal(db.List())
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/findings/" + anchor + "/related"
	var seen = map[string]bool{}
	for offset := 0; offset < 3; offset++ {
		response := findingsAPIRequest(t, srv, http.MethodGet, base+"?limit=1&offset="+string(rune('0'+offset)), http.StatusOK)
		assertFindingsJSON(t, response)
		var p relatedConsolePage
		if err := json.Unmarshal(response.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		if p.AnchorID != anchor || p.CVEID != "CVE-2099-0001" || p.Relationship != "same_cve" || p.Total != 2 || p.Limit != 1 || p.Offset != offset {
			t.Fatalf("page=%s", response.Body.String())
		}
		if offset < 2 {
			if len(p.Items) != 1 || p.Items[0].ID == anchor || seen[p.Items[0].ID] {
				t.Fatal("anchor, duplicate or missing related ID")
			}
			seen[p.Items[0].ID] = true
		} else if len(p.Items) != 0 || !strings.Contains(response.Body.String(), `"items":[]`) {
			t.Fatal("empty page must be []")
		}
	}
	if !seen[other] || !seen[trivyID] {
		t.Fatal("cross-source relationships missing")
	}
	for query, want := range map[string]string{"source=trivy": trivyID, "source=dependabot&severity=high&source_status=active&q=example%2Fother%3A2": other} {
		r := findingsAPIRequest(t, srv, http.MethodGet, base+"?"+query, http.StatusOK)
		p := decodeConsolePage(t, r.Body.Bytes())
		if p.Total != 1 || p.Items[0].ID != want {
			t.Fatalf("filter=%s response=%s", query, r.Body.String())
		}
	}
	after, err := json.Marshal(db.List())
	if err != nil || string(after) != string(before) {
		t.Fatal("legacy approval/notification changed")
	}
}

func TestRelatedFindingsNonCVEAnchorIsEmptyAndCannotOverrideScope(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	anchor := seedConsoleDependabot(t, db, "ghsa", 1, "GHSA-synthetic-example")
	seedConsoleDependabot(t, db, "service", 2, "CVE-2099-0001")
	base := "/api/v1/findings/" + anchor + "/related"
	r := findingsAPIRequest(t, srv, http.MethodGet, base, http.StatusOK)
	var p relatedConsolePage
	if err := json.Unmarshal(r.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Total != 0 || len(p.Items) != 0 || p.CVEID != "" || p.Relationship != "none" || !strings.Contains(r.Body.String(), `"items":[]`) {
		t.Fatalf("non-CVE=%s", r.Body.String())
	}
	for _, query := range []string{"cve=CVE-2099-0001", "cve=", "limit=0", "limit=201", "q=x&q=y", "source=trivy&source=dependabot", "unknown=x", "offset=1000001", "q=%FF"} {
		assertFindingsJSON(t, findingsAPIRequest(t, srv, http.MethodGet, base+"?"+query, http.StatusBadRequest))
	}
	findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/00000000-0000-0000-0000-000000000000/related", http.StatusNotFound)
	findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/not-a-uuid/related", http.StatusNotFound)
	findingsAPIRequest(t, srv, http.MethodPost, base, http.StatusMethodNotAllowed)
	findingsAPIRequest(t, srv, http.MethodGet, base+"/extra", http.StatusNotFound)
}

func TestFindingsCVEFilterRejectsInvalidEmptyAndDuplicateValues(t *testing.T) {
	srv, _ := newFindingsAPITestServer(t)
	for _, q := range []string{"cve=", "cve=GHSA-synthetic-example", "cve=CVE-2099-0001&cve=CVE-2099-0002", "cve=CVE-2099-0001%00", "cve=%FF", "cve=CVE-2099-0001,CVE-2099-0002", "cve=prefixCVE-2099-0001"} {
		assertFindingsJSON(t, findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings?"+q, http.StatusBadRequest))
	}
}

func TestRelatedFindingsKeepOnlyReturnedEnrichmentsAndPropagateStorageFailure(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	anchor := seedConsoleDependabot(t, db, "service", 1, "CVE-2099-0001")
	seedConsoleDependabot(t, db, "other", 2, "CVE-2099-0001")
	seedConsoleTrivy(t, db)
	at := time.Now().UTC()
	input := "#model_version:synthetic.1,score_date:" + at.Format("2006-01-02") + "\ncve,epss,percentile\nCVE-2099-0001,0,0\n"
	feed, err := threat.ParseOfflineThreat(strings.NewReader(input), "epss", threat.OfflineOptions{CVEs: []string{"CVE-2099-0001"}, ObservedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := threat.OfflineSelectionScope(feed.SelectedCVEs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(input))
	run := model.IngestRun{ID: "00000000-0000-8000-8000-000000000777", Connector: "epss_offline", Scope: scope, StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + hex.EncodeToString(digest[:])}
	if _, err := db.ImportSecurityEnrichment(context.Background(), run, feed); err != nil {
		t.Fatal(err)
	}
	r := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/"+anchor+"/related?limit=1", http.StatusOK)
	p := decodeConsolePage(t, r.Body.Bytes())
	if p.Total != 2 || len(p.Items) != 1 || len(p.Enrichments) != 1 {
		t.Fatalf("page=%s", r.Body.String())
	}
	e, ok := p.Enrichments[p.Items[0].ID]
	if !ok || e.EPSS == nil || e.EPSS.EPSS == nil || *e.EPSS.EPSS != 0 || !e.EPSS.Fresh {
		t.Fatal("returned-ID enrichment missing or zero lost")
	}
	if _, ok := p.Enrichments[anchor]; ok {
		t.Fatal("anchor enrichment leaked into related page")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	failure := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/"+anchor+"/related", http.StatusInternalServerError)
	assertFindingsJSON(t, failure)
	if strings.Contains(failure.Body.String(), "database") || strings.Contains(failure.Body.String(), anchor) {
		t.Fatal("storage error exposed internal/source details")
	}
}
