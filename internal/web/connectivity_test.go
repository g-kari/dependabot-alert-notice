package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

func TestConnectivity_Page(t *testing.T) {
	srv, _, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/settings/connectivity", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivity(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "疎通テスト") {
		t.Error("response should contain '疎通テスト'")
	}
}

func TestConnectivityTest_ReturnsJSON(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
	}

	req := httptest.NewRequest(http.MethodPost, "/api/connectivity-test", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityTest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var result connectivityResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
}

func TestConnectivityTest_BadGhPath(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
	}

	req := httptest.NewRequest(http.MethodPost, "/api/connectivity-test", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityTest(w, req)

	var result connectivityResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if result.GH.OK {
		t.Error("gh should not be ok with invalid path")
	}
	if result.Claude.OK {
		t.Error("claude should not be ok with invalid path")
	}
}

func TestConnectivityTest_NoTargets(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
		Targets:    nil,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/connectivity-test", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityTest(w, req)

	var result connectivityResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(result.Targets) != 0 {
		t.Errorf("targets = %d, want 0", len(result.Targets))
	}
}

func TestConnectivityTest_NoSlackToken(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
		Slack:      config.SlackConfig{ChannelID: "C123"},
	}
	// 環境変数SLACK_BOT_TOKENが未設定の状態でテスト
	t.Setenv("SLACK_BOT_TOKEN", "")

	req := httptest.NewRequest(http.MethodPost, "/api/connectivity-test", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityTest(w, req)

	var result connectivityResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if result.Slack.OK {
		t.Error("slack should not be ok without token")
	}
	if !strings.Contains(result.Slack.Message, "SLACK_BOT_TOKEN") {
		t.Errorf("slack message should mention SLACK_BOT_TOKEN, got: %s", result.Slack.Message)
	}
}

func TestConnectivityTest_SandboxDisabled(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
		Evaluator: config.EvaluatorConfig{
			Sandbox: config.SandboxConfig{Enabled: false},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/connectivity-test", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityTest(w, req)

	var result connectivityResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !result.Sandbox.OK {
		t.Errorf("サンドボックス無効時は OK=true を返すべき: %s", result.Sandbox.Message)
	}
	if !strings.Contains(result.Sandbox.Message, "無効") {
		t.Errorf("メッセージに '無効' が含まれるべき: %s", result.Sandbox.Message)
	}
}

func TestConnectivityTest_SandboxEnabled_NoDocker(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
		Evaluator: config.EvaluatorConfig{
			Sandbox: config.SandboxConfig{
				Enabled: true,
				Image:   "dependabot-evaluator:latest",
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/connectivity-test", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityTest(w, req)

	var result connectivityResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	// docker が存在しない or イメージが存在しない場合は OK=false になるはず
	// docker が存在してイメージもある環境ではスキップ
	t.Logf("sandbox result: ok=%v, message=%q", result.Sandbox.OK, result.Sandbox.Message)
}

func TestConnectivityTest_WithTarget(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		GhPath:     "/nonexistent-gh-12345",
		ClaudePath: "/nonexistent-claude-12345",
		Targets: []config.Target{
			{Owner: "testorg", Repo: "testrepo"},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/api/connectivity-test", nil)
	w := httptest.NewRecorder()
	srv.handleConnectivityTest(w, req)

	var result connectivityResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if len(result.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(result.Targets))
	}
	if result.Targets[0].Owner != "testorg" {
		t.Errorf("owner = %q, want testorg", result.Targets[0].Owner)
	}
	// 無効なghPathなのでエラーになるはず
	if result.Targets[0].OK {
		t.Error("target should not be ok with invalid gh path")
	}
}
