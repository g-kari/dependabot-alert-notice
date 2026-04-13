package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func makeSearchRecord(owner, repo, pkg, cveID, ghsaID, summary string) *model.AlertRecord {
	return &model.AlertRecord{
		Alert: model.Alert{
			Owner:       owner,
			Repo:        repo,
			PackageName: pkg,
			CVEID:       cveID,
			GHSAID:      ghsaID,
			Summary:     summary,
			Severity:    model.SeverityHigh,
			CreatedAt:   time.Now(),
		},
		State: model.AlertStatePending,
	}
}

// TestFilterBySearch_EmptyQuery は空クエリで全件返却されることを確認
func TestFilterBySearch_EmptyQuery(t *testing.T) {
	records := []*model.AlertRecord{
		makeSearchRecord("org", "repo-a", "lodash", "CVE-2024-0001", "", ""),
		makeSearchRecord("org", "repo-b", "axios", "CVE-2024-0002", "", ""),
	}
	got := filterBySearch(records, "")
	if len(got) != 2 {
		t.Errorf("len = %d, want 2 (empty query returns all)", len(got))
	}
}

// TestFilterBySearch_ByPackage はパッケージ名で絞り込めることを確認
func TestFilterBySearch_ByPackage(t *testing.T) {
	records := []*model.AlertRecord{
		makeSearchRecord("org", "repo-a", "lodash", "CVE-2024-0001", "", ""),
		makeSearchRecord("org", "repo-b", "axios", "CVE-2024-0002", "", ""),
	}
	got := filterBySearch(records, "lodash")
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Alert.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want lodash", got[0].Alert.PackageName)
	}
}

// TestFilterBySearch_ByRepo はリポジトリ名で絞り込めることを確認
func TestFilterBySearch_ByRepo(t *testing.T) {
	records := []*model.AlertRecord{
		makeSearchRecord("org", "my-repo", "lodash", "", "", ""),
		makeSearchRecord("org", "other-repo", "axios", "", "", ""),
	}
	got := filterBySearch(records, "my-repo")
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Alert.Repo != "my-repo" {
		t.Errorf("Repo = %q, want my-repo", got[0].Alert.Repo)
	}
}

// TestFilterBySearch_ByCVE はCVE IDで絞り込めることを確認
func TestFilterBySearch_ByCVE(t *testing.T) {
	records := []*model.AlertRecord{
		makeSearchRecord("org", "repo-a", "pkg-a", "CVE-2024-0001", "", ""),
		makeSearchRecord("org", "repo-b", "pkg-b", "CVE-2024-0002", "", ""),
	}
	got := filterBySearch(records, "CVE-2024-0001")
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Alert.CVEID != "CVE-2024-0001" {
		t.Errorf("CVEID = %q, want CVE-2024-0001", got[0].Alert.CVEID)
	}
}

// TestFilterBySearch_ByGHSA はGHSA IDで絞り込めることを確認
func TestFilterBySearch_ByGHSA(t *testing.T) {
	records := []*model.AlertRecord{
		makeSearchRecord("org", "repo-a", "pkg-a", "", "GHSA-xxxx-yyyy-zzzz", ""),
		makeSearchRecord("org", "repo-b", "pkg-b", "", "", ""),
	}
	got := filterBySearch(records, "GHSA-xxxx")
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
}

// TestFilterBySearch_BySummary はSummaryで絞り込めることを確認
func TestFilterBySearch_BySummary(t *testing.T) {
	records := []*model.AlertRecord{
		makeSearchRecord("org", "repo-a", "pkg", "", "", "Prototype Pollution in lodash"),
		makeSearchRecord("org", "repo-b", "pkg", "", "", "Remote code execution"),
	}
	got := filterBySearch(records, "prototype pollution")
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
}

// TestFilterBySearch_CaseInsensitive は大文字小文字を区別しないことを確認
func TestFilterBySearch_CaseInsensitive(t *testing.T) {
	records := []*model.AlertRecord{
		makeSearchRecord("org", "repo", "LODASH", "", "", ""),
	}
	got := filterBySearch(records, "lodash")
	if len(got) != 1 {
		t.Errorf("len = %d, want 1 (case insensitive)", len(got))
	}
}

// TestFilterBySearch_NoMatch は一致なしで空スライスを返すことを確認
func TestFilterBySearch_NoMatch(t *testing.T) {
	records := []*model.AlertRecord{
		makeSearchRecord("org", "repo", "axios", "", "", ""),
	}
	got := filterBySearch(records, "zzz-no-match")
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// TestDashboard_SearchByPackage はq=パラメータでダッシュボードが絞り込まれることを確認
func TestDashboard_SearchByPackage(t *testing.T) {
	srv, s, _ := newTestServer(t)
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Number: 1, Owner: "org", Repo: "repo", PackageName: "lodash", CVEID: "CVE-2024-0001", Severity: model.SeverityHigh, CreatedAt: time.Now()},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Number: 2, Owner: "org", Repo: "repo", PackageName: "axios", CVEID: "CVE-2024-0002", Severity: model.SeverityHigh, CreatedAt: time.Now()},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/?q=lodash", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "lodash") {
		t.Error("should contain lodash")
	}
	if strings.Contains(body, "axios") {
		t.Error("should not contain axios when searching for lodash")
	}
}

// TestDashboard_SearchEmpty はq=空で全件表示されることを確認
func TestDashboard_SearchEmpty(t *testing.T) {
	srv, s, _ := newTestServer(t)
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Number: 1, Owner: "org", Repo: "repo1", PackageName: "lodash", CVEID: "CVE-2024-0001", Severity: model.SeverityHigh, CreatedAt: time.Now()},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Number: 2, Owner: "org", Repo: "repo2", PackageName: "axios", CVEID: "CVE-2024-0002", Severity: model.SeverityHigh, CreatedAt: time.Now()},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/?q=", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "lodash") || !strings.Contains(body, "axios") {
		t.Error("empty query should show all alerts")
	}
}
