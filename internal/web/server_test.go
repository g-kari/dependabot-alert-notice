package web

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// mockMerger は merger.Interface のモック実装
type mockMerger struct {
	approveErr error
	rejectErr  error
	mergeErr   error
	approved   []int
	rejected   []int
}

func (m *mockMerger) Approve(_ context.Context, id int) error {
	if m.approveErr != nil {
		return m.approveErr
	}
	m.approved = append(m.approved, id)
	return nil
}

func (m *mockMerger) Reject(id int) error {
	if m.rejectErr != nil {
		return m.rejectErr
	}
	m.rejected = append(m.rejected, id)
	return nil
}

func (m *mockMerger) Merge(_ context.Context, id int) error {
	return m.mergeErr
}

func newTestServer(t *testing.T) (*Server, *store.Store, *mockMerger) {
	t.Helper()
	s := store.New()
	m := &mockMerger{}
	cfg := &config.Config{Web: config.WebConfig{Port: 0}}
	srv := New(cfg, "", s, m)
	return srv, s, m
}

func saveAlert(s *store.Store, number int, pkg string, sev model.Severity) {
	s.Save(&model.AlertRecord{
		Alert: model.Alert{
			Number:      number,
			PackageName: pkg,
			Owner:       "testorg",
			Repo:        "testrepo",
			Severity:    sev,
			CreatedAt:   time.Now(),
		},
		Evaluation: &model.Evaluation{
			Risk:           "high",
			Recommendation: "approve",
			Reasoning:      "テスト用",
		},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}

// TestDashboard_Empty は空のstoreでダッシュボードが200を返すことを確認
func TestDashboard_Empty(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "Dependabot") {
		t.Error("response should contain 'Dependabot'")
	}
}

// TestDashboard_WithAlerts はアラートがあるときにパッケージ名が表示されることを確認
func TestDashboard_WithAlerts(t *testing.T) {
	srv, s, _ := newTestServer(t)
	saveAlert(s, 1, "lodash", model.SeverityHigh)
	saveAlert(s, 2, "axios", model.SeverityCritical)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "lodash") {
		t.Error("response should contain 'lodash'")
	}
	if !strings.Contains(body, "axios") {
		t.Error("response should contain 'axios'")
	}
}

// TestDetail_Found はアラートが存在するときに200を返すことを確認
func TestDetail_Found(t *testing.T) {
	srv, s, _ := newTestServer(t)
	saveAlert(s, 1, "lodash", model.SeverityHigh)

	req := httptest.NewRequest(http.MethodGet, "/alerts/1", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	srv.handleDetail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "lodash") {
		t.Error("response should contain 'lodash'")
	}
}

// TestDetail_NotFound は存在しないIDで404を返すことを確認
func TestDetail_NotFound(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/alerts/999", nil)
	req.SetPathValue("id", "999")
	w := httptest.NewRecorder()
	srv.handleDetail(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// TestDetail_InvalidID は不正なIDで400を返すことを確認
func TestDetail_InvalidID(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/alerts/abc", nil)
	req.SetPathValue("id", "abc")
	w := httptest.NewRecorder()
	srv.handleDetail(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestApprove_Success は承認が成功してリダイレクトされることを確認
func TestApprove_Success(t *testing.T) {
	srv, s, m := newTestServer(t)
	saveAlert(s, 1, "lodash", model.SeverityHigh)

	req := httptest.NewRequest(http.MethodPost, "/alerts/1/approve", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	srv.handleApprove(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if len(m.approved) != 1 || m.approved[0] != 1 {
		t.Errorf("approved = %v, want [1]", m.approved)
	}
}

// TestApprove_Failure はmerger.Approveが失敗したとき500を返すことを確認
func TestApprove_Failure(t *testing.T) {
	srv, s, m := newTestServer(t)
	m.approveErr = errors.New("merge failed")
	saveAlert(s, 1, "lodash", model.SeverityHigh)

	req := httptest.NewRequest(http.MethodPost, "/alerts/1/approve", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	srv.handleApprove(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// TestApprove_InvalidID は不正なIDで400を返すことを確認
func TestApprove_InvalidID(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/alerts/bad/approve", nil)
	req.SetPathValue("id", "bad")
	w := httptest.NewRecorder()
	srv.handleApprove(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestReject_Success は却下が成功してリダイレクトされることを確認
func TestReject_Success(t *testing.T) {
	srv, s, m := newTestServer(t)
	saveAlert(s, 2, "axios", model.SeverityCritical)

	req := httptest.NewRequest(http.MethodPost, "/alerts/2/reject", nil)
	req.SetPathValue("id", "2")
	w := httptest.NewRecorder()
	srv.handleReject(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if len(m.rejected) != 1 || m.rejected[0] != 2 {
		t.Errorf("rejected = %v, want [2]", m.rejected)
	}
}

// TestReject_Failure はmerger.Rejectが失敗したとき500を返すことを確認
func TestReject_Failure(t *testing.T) {
	srv, s, m := newTestServer(t)
	m.rejectErr = errors.New("reject failed")
	saveAlert(s, 2, "axios", model.SeverityCritical)

	req := httptest.NewRequest(http.MethodPost, "/alerts/2/reject", nil)
	req.SetPathValue("id", "2")
	w := httptest.NewRecorder()
	srv.handleReject(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

// TestReject_InvalidID は不正なIDで400を返すことを確認
func TestReject_InvalidID(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/alerts/bad/reject", nil)
	req.SetPathValue("id", "bad")
	w := httptest.NewRecorder()
	srv.handleReject(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestLogs_Empty は空のstoreでログページが200を返すことを確認
func TestLogs_Empty(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	w := httptest.NewRecorder()
	srv.handleLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestLogs_WithEntries はログエントリがあるとき表示されることを確認
func TestLogs_WithEntries(t *testing.T) {
	srv, s, _ := newTestServer(t)
	s.AddLog(model.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "テストログメッセージ",
	})

	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	w := httptest.NewRecorder()
	srv.handleLogs(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "テストログメッセージ") {
		t.Error("response should contain log message")
	}
}

// TestSettings_Get は設定ページが200を返すことを確認
func TestSettings_Get(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	w := httptest.NewRecorder()
	srv.handleSettings(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "設定") {
		t.Error("response should contain '設定'")
	}
}

// TestSettings_Save は設定保存後にリダイレクトされることを確認
func TestSettings_Save(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		PollInterval: 30 * time.Minute,
		LogLevel:     "info",
		ClaudePath:   "claude",
		GhPath:       "gh",
		Slack:        config.SlackConfig{ChannelID: "C123"},
		Evaluator: config.EvaluatorConfig{
			Sandbox: config.SandboxConfig{
				Enabled:     true,
				Image:       "test-image",
				MemoryLimit: "512m",
				CPULimit:    "0.5",
				Timeout:     60 * time.Second,
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(
		"poll_interval=5m&log_level=debug&claude_path=claude&gh_path=gh&slack_channel_id=C456&sandbox_enabled=true&sandbox_image=test-image&sandbox_memory=512m&sandbox_cpu=0.5&sandbox_timeout=60s",
	))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleSettingsSave(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if srv.cfg.PollInterval != 5*time.Minute {
		t.Errorf("PollInterval = %v, want 5m", srv.cfg.PollInterval)
	}
	if srv.cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", srv.cfg.LogLevel)
	}
	if srv.cfg.Slack.ChannelID != "C456" {
		t.Errorf("ChannelID = %q, want C456", srv.cfg.Slack.ChannelID)
	}
}

// TestTargetAdd はターゲット追加後にリダイレクトされることを確認
func TestTargetAdd(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{}

	req := httptest.NewRequest(http.MethodPost, "/settings/targets/add", strings.NewReader("owner=myorg&repo=myrepo"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleTargetAdd(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if len(srv.cfg.Targets) != 1 {
		t.Fatalf("Targets len = %d, want 1", len(srv.cfg.Targets))
	}
	if srv.cfg.Targets[0].Owner != "myorg" || srv.cfg.Targets[0].Repo != "myrepo" {
		t.Errorf("Targets[0] = %+v", srv.cfg.Targets[0])
	}
}

// TestTargetAdd_EmptyOwner はownerが空のとき追加せずリダイレクトされることを確認
func TestTargetAdd_EmptyOwner(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{}

	req := httptest.NewRequest(http.MethodPost, "/settings/targets/add", strings.NewReader("owner=&repo=myrepo"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.handleTargetAdd(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if len(srv.cfg.Targets) != 0 {
		t.Error("Targets should be empty when owner is missing")
	}
}

// TestTargetDelete はターゲット削除が正しく動くことを確認
func TestTargetDelete(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		Targets: []config.Target{
			{Owner: "org1", Repo: "repo1"},
			{Owner: "org2", Repo: "repo2"},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/settings/targets/0/delete", nil)
	req.SetPathValue("i", "0")
	w := httptest.NewRecorder()
	srv.handleTargetDelete(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if len(srv.cfg.Targets) != 1 {
		t.Fatalf("Targets len = %d, want 1", len(srv.cfg.Targets))
	}
	if srv.cfg.Targets[0].Owner != "org2" {
		t.Errorf("Targets[0].Owner = %q, want org2", srv.cfg.Targets[0].Owner)
	}
}

// TestMarkdownFunc はmarkdownテンプレート関数の動作を確認
func TestMarkdownFunc(t *testing.T) {
	markdownFn, ok := templateFuncs["markdown"].(func(string) template.HTML)
	if !ok {
		t.Fatal("markdown関数がtemplateFuncsに定義されていない")
	}

	tests := []struct {
		name        string
		input       string
		contains    string
		notContains string
	}{
		{
			name:     "見出し変換",
			input:    "## Hello\n\nworld",
			contains: "<h2>",
		},
		{
			name:     "太字変換",
			input:    "**bold** text",
			contains: "<strong>bold</strong>",
		},
		{
			name:     "空文字列",
			input:    "",
			contains: "",
		},
		{
			name:        "XSS防止（raw HTML非許可）",
			input:       "<script>alert('xss')</script>",
			notContains: "<script>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(markdownFn(tt.input))
			if tt.contains != "" && !strings.Contains(got, tt.contains) {
				t.Errorf("got %q, want to contain %q", got, tt.contains)
			}
			if tt.notContains != "" && strings.Contains(got, tt.notContains) {
				t.Errorf("got %q, want NOT to contain %q", got, tt.notContains)
			}
		})
	}
}

// TestDetail_RendersMarkdownDescription はMarkdown形式のDescriptionがHTMLとしてレンダリングされることを確認
func TestDetail_RendersMarkdownDescription(t *testing.T) {
	srv, s, _ := newTestServer(t)
	r := &model.AlertRecord{
		Alert: model.Alert{
			Number:      10,
			PackageName: "lodash",
			Owner:       "testorg",
			Repo:        "testrepo",
			Severity:    model.SeverityHigh,
			Description: "## 脆弱性の説明\n\nこれは **重要な** 脆弱性です。\n\n- 項目1\n- 項目2",
			CreatedAt:   time.Now(),
		},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	}
	s.Save(r)

	idStr := fmt.Sprintf("%d", r.Alert.ID)
	req := httptest.NewRequest(http.MethodGet, "/alerts/"+idStr, nil)
	req.SetPathValue("id", idStr)
	w := httptest.NewRecorder()
	srv.handleDetail(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<h2>") {
		t.Error("Markdown見出しがHTMLに変換されていない: <h2>が見つからない")
	}
	if !strings.Contains(body, "<strong>") {
		t.Error("Markdown太字がHTMLに変換されていない: <strong>が見つからない")
	}
	if !strings.Contains(body, "<ul>") {
		t.Error("Markdownリストがイに変換されていない: <ul>が見つからない")
	}
}

// TestTargetDelete_InvalidIndex は範囲外インデックスを無視することを確認
func TestTargetDelete_InvalidIndex(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		Targets: []config.Target{{Owner: "org1"}},
	}

	req := httptest.NewRequest(http.MethodPost, "/settings/targets/99/delete", nil)
	req.SetPathValue("i", "99")
	w := httptest.NewRecorder()
	srv.handleTargetDelete(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if len(srv.cfg.Targets) != 1 {
		t.Error("Targets should not be changed for out-of-range index")
	}
}
