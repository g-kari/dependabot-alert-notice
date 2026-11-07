package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

func importAPIEnrichment(t *testing.T, s *store.Store, source, input string, at time.Time, seq int) {
	t.Helper()
	feed, err := threat.ParseOfflineThreat(strings.NewReader(input), source, threat.OfflineOptions{CVEs: []string{"CVE-2026-0001"}, ObservedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := threat.OfflineSelectionScope(feed.SelectedCVEs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(input))
	id := fmt.Sprintf("00000000-0000-8000-8000-%012d", seq)
	run := model.IngestRun{ID: id, Connector: source + "_offline", Scope: scope, StartedAt: at, FinishedAt: &at, Result: "success", Coverage: "partial", Cursor: "sha256:" + hex.EncodeToString(digest[:])}
	if _, err := s.ImportSecurityEnrichment(context.Background(), run, feed); err != nil {
		t.Fatal(err)
	}
}

func TestOfflineEnrichmentAppearsInCommonReadAPIWithoutChangingAuthoritativeData(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "repo", 1, model.SeverityHigh, "open")
	seedAPIFinding(t, db, "other", 2, model.SeverityLow, "open")
	before, err := json.Marshal(db.List())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	epss := "#model_version:v2026.01.01,score_date:" + at.Format("2006-01-02") + "\ncve,epss,percentile\nCVE-2026-0001,0,0\nCVE-2026-9999,0.99,0.99\n"
	importAPIEnrichment(t, db, "epss", epss, at, 100)
	kev := fmt.Sprintf(`{"catalogVersion":"synthetic.1","dateReleased":%q,"count":1,"vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":%q,"notes":"PRIVATE-SYNTHETIC-MARKER","requiredAction":"PRIVATE-SYNTHETIC-MARKER","vendorProject":"PRIVATE-SYNTHETIC-MARKER"}]}`, at.Add(-time.Minute).Format(time.RFC3339Nano), at.AddDate(0, 0, -1).Format("2006-01-02"))
	importAPIEnrichment(t, db, "kev", kev, at, 101)
	response := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings", http.StatusOK)
	var page struct {
		Items       []model.Finding                    `json:"items"`
		Enrichments map[string]model.FindingEnrichment `json:"enrichments"`
		Total       int                                `json:"total"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Enrichments) != 1 {
		t.Fatalf("page=%s", response.Body.String())
	}
	var id string
	for key, value := range page.Enrichments {
		id = key
		if value.CVEID != "CVE-2026-0001" || value.EPSS == nil || value.EPSS.EPSS == nil || *value.EPSS.EPSS != 0 || value.KEV == nil || !value.KEV.KEV || !value.EPSS.Fresh || !value.KEV.Fresh {
			t.Fatalf("enrichment=%+v", value)
		}
	}
	detailResponse := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/"+id, http.StatusOK)
	var detail struct {
		Finding    model.Finding            `json:"finding"`
		Enrichment *model.FindingEnrichment `json:"enrichment"`
	}
	if err := json.Unmarshal(detailResponse.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Enrichment == nil || detail.Finding.Severity != model.SeverityHigh || detail.Finding.SourceStatus != model.SourceStatusActive || detail.Finding.TriageStatus != model.TriageStatusNew {
		t.Fatalf("detail=%s", detailResponse.Body.String())
	}
	if strings.Contains(detailResponse.Body.String(), "PRIVATE-SYNTHETIC-MARKER") {
		t.Fatal("feed free text leaked")
	}
	for _, f := range page.Items {
		if f.ID != id {
			other := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings/"+f.ID, http.StatusOK)
			if strings.Contains(other.Body.String(), `"enrichment"`) {
				t.Fatal("unselected CVE inherited evidence")
			}
		}
	}
	after, err := json.Marshal(db.List())
	if err != nil || string(after) != string(before) {
		t.Fatal("native alerts/evaluation/approval mutated")
	}
	legacy, err := db.ListThreatSnapshots(context.Background())
	if err != nil || len(legacy) != 0 {
		t.Fatal("legacy risk threat data mutated")
	}
	findingsAPIRequest(t, srv, http.MethodPost, "/api/v1/findings", http.StatusMethodNotAllowed)
}

func TestNewKEVAndMissingEPSSDoNotRefreshStaleEPSSInAPI(t *testing.T) {
	srv, db := newFindingsAPITestServer(t)
	seedAPIFinding(t, db, "repo", 1, model.SeverityHigh, "open")
	now := time.Now().UTC()
	old := now.Add(-120 * time.Hour)
	epss := "#model_version:v2026.01.01,score_date:" + old.Format("2006-01-02") + "\ncve,epss,percentile\nCVE-2026-0001,0.01,0.1\n"
	importAPIEnrichment(t, db, "epss", epss, old, 110)
	missing := "#model_version:v2026.01.01,score_date:" + now.Format("2006-01-02") + "\ncve,epss,percentile\nCVE-2026-0002,0.9,0.9\n"
	importAPIEnrichment(t, db, "epss", missing, now, 111)
	kev := fmt.Sprintf(`{"catalogVersion":"synthetic.2","dateReleased":%q,"count":1,"vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":%q}]}`, now.Add(-time.Minute).Format(time.RFC3339Nano), old.Format("2006-01-02"))
	importAPIEnrichment(t, db, "kev", kev, now, 112)
	response := findingsAPIRequest(t, srv, http.MethodGet, "/api/v1/findings", http.StatusOK)
	var page struct {
		Enrichments map[string]model.FindingEnrichment `json:"enrichments"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Enrichments) != 1 {
		t.Fatal("missing enrichment")
	}
	for _, e := range page.Enrichments {
		if e.EPSS == nil || e.EPSS.Fresh || !e.EPSS.ObservedAt.Equal(old) || e.KEV == nil || !e.KEV.Fresh || !e.KEV.KEV {
			t.Fatalf("freshness=%s", response.Body.String())
		}
	}
}
