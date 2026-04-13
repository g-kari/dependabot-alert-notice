package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// saveUniqueAlert はユニークなパッケージ・CVEのアラートをストアに保存するヘルパー
func saveUniqueAlert(s *store.Store, number int, pkg, cve string, sev model.Severity) {
	s.Save(&model.AlertRecord{
		Alert: model.Alert{
			Number:      number,
			PackageName: pkg,
			CVEID:       cve,
			Owner:       "testorg",
			Repo:        "testrepo",
			Severity:    sev,
			CreatedAt:   time.Now(),
		},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})
}

// TestDashboard_Pagination_DefaultPage1 はpage未指定でページ1が表示されることを確認
func TestDashboard_Pagination_DefaultPage1(t *testing.T) {
	srv, s, _ := newTestServer(t)
	// dashboardPageSize + 5 件のアラートを登録（別CVEなので別グループ）
	total := dashboardPageSize + 5
	for i := 1; i <= total; i++ {
		saveUniqueAlert(s, i, fmt.Sprintf("pkg-%03d", i), fmt.Sprintf("CVE-2024-%04d", i), model.SeverityHigh)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	// page 1 に dashboardPageSize 件目のパッケージが含まれる
	if !strings.Contains(body, fmt.Sprintf("pkg-%03d", dashboardPageSize)) {
		t.Errorf("page 1 should contain pkg-%03d", dashboardPageSize)
	}
	// page 1 に dashboardPageSize+1 件目は含まれない
	if strings.Contains(body, fmt.Sprintf("pkg-%03d", dashboardPageSize+1)) {
		t.Errorf("page 1 should NOT contain pkg-%03d", dashboardPageSize+1)
	}
}

// TestDashboard_Pagination_Page2 は?page=2で次のページが表示されることを確認
func TestDashboard_Pagination_Page2(t *testing.T) {
	srv, s, _ := newTestServer(t)
	total := dashboardPageSize + 5
	for i := 1; i <= total; i++ {
		saveUniqueAlert(s, i, fmt.Sprintf("pkg-%03d", i), fmt.Sprintf("CVE-2024-%04d", i), model.SeverityHigh)
	}

	req := httptest.NewRequest(http.MethodGet, "/?page=2", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	// page 2 には dashboardPageSize+1 件目以降が含まれる
	if !strings.Contains(body, fmt.Sprintf("pkg-%03d", dashboardPageSize+1)) {
		t.Errorf("page 2 should contain pkg-%03d", dashboardPageSize+1)
	}
	// page 2 に page 1 のものは含まれない
	if strings.Contains(body, fmt.Sprintf("pkg-%03d", 1)) {
		t.Errorf("page 2 should NOT contain pkg-001 (page 1 item)")
	}
}

// TestDashboard_Pagination_InvalidPage はpage=0やpage=-1でpage=1にフォールバックすることを確認
func TestDashboard_Pagination_InvalidPage(t *testing.T) {
	srv, s, _ := newTestServer(t)
	for i := 1; i <= 5; i++ {
		saveUniqueAlert(s, i, fmt.Sprintf("pkg-%03d", i), fmt.Sprintf("CVE-2024-%04d", i), model.SeverityHigh)
	}

	for _, pageParam := range []string{"0", "-1", "abc"} {
		req := httptest.NewRequest(http.MethodGet, "/?page="+pageParam, nil)
		w := httptest.NewRecorder()
		srv.handleDashboard(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("page=%s: status = %d, want 200", pageParam, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "pkg-001") {
			t.Errorf("page=%s: should show page 1 content (pkg-001)", pageParam)
		}
	}
}

// TestDashboard_Pagination_ControlsShown はページングコントロールが表示されることを確認
func TestDashboard_Pagination_ControlsShown(t *testing.T) {
	srv, s, _ := newTestServer(t)
	total := dashboardPageSize + 1
	for i := 1; i <= total; i++ {
		saveUniqueAlert(s, i, fmt.Sprintf("pkg-%03d", i), fmt.Sprintf("CVE-2024-%04d", i), model.SeverityHigh)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	body := w.Body.String()
	// ページネーションリンクが含まれること
	if !strings.Contains(body, "page=2") {
		t.Error("pagination controls should contain link to page=2")
	}
}

// TestDashboard_Pagination_RepoView はリポジトリ別ビューでもページングが効くことを確認
func TestDashboard_Pagination_RepoView(t *testing.T) {
	srv, s, _ := newTestServer(t)
	// 異なるリポジトリに1アラートずつ（dashboardPageSize+3件）
	total := dashboardPageSize + 3
	for i := 1; i <= total; i++ {
		s.Save(&model.AlertRecord{
			Alert: model.Alert{
				Number:      1,
				PackageName: "lodash",
				Owner:       "testorg",
				Repo:        fmt.Sprintf("repo-%03d", i),
				Severity:    model.SeverityHigh,
				CreatedAt:   time.Now(),
			},
			State:      model.AlertStatePending,
			NotifiedAt: time.Now(),
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/?view=repo&page=2", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, fmt.Sprintf("repo-%03d", dashboardPageSize+1)) {
		t.Errorf("repo view page 2 should contain repo-%03d", dashboardPageSize+1)
	}
}
