package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/control"
)

func TestAWSConditionalEvaluationDetailAndLegacyFallback(t *testing.T) {
	srv, s, _ := newTestServer(t)
	saveAlert(s, 1, "pkg", "high")
	record := s.List()[0]
	record.Evaluation.AWSRisk = "EC2で実行する場合の確認事項 <script>alert(1)</script>"
	s.Save(record)
	for _, hasAWS := range []bool{true, false} {
		if !hasAWS {
			record.Evaluation.AWSRisk = ""
			s.Save(record)
		}
		req := httptest.NewRequest("GET", "/alerts/1", nil)
		req.SetPathValue("id", "1")
		w := httptest.NewRecorder()
		srv.handleDetail(w, req)
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, "AWSで危険になる利用条件") {
			t.Fatal(body)
		}
		if hasAWS && (!strings.Contains(body, "EC2で実行する場合") || strings.Contains(body, "<script>alert(1)</script>")) {
			t.Fatal("AWS not rendered safely")
		}
		if !hasAWS && !strings.Contains(body, "未評価（再評価すると確認できます）") {
			t.Fatal("legacy fallback missing")
		}
	}
}

func TestWebAndTUISaveApplyDisabledApprovalAndPodmanWithoutRestart(t *testing.T) {
	for _, surface := range []string{"web", "tui"} {
		t.Run(surface, func(t *testing.T) {
			srv := tuiServer(t)
			called := false
			srv.SetEvaluatorConfigChanged(func(c config.Config) { called = c.DisableApproval && c.Evaluator.Sandbox.Runtime == "podman" })
			if surface == "web" {
				req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader("disable_approval=true&sandbox_enabled=true&sandbox_runtime=podman"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				srv.handleSettingsSave(w, req)
				if w.Code != 303 {
					t.Fatalf("save=%d %s", w.Code, w.Body.String())
				}
			} else {
				w := tuiRequest(t, srv, "PUT", "/api/tui/config", control.Settings{YAML: "disable_approval: true\nevaluator: {sandbox: {runtime: podman}}"}, true)
				if w.Code != 200 || strings.Contains(w.Body.String(), `"restart_required":true`) {
					t.Fatalf("save=%d %s", w.Code, w.Body.String())
				}
			}
			snapshot, err := srv.ConfigurationSnapshot()
			if err != nil || !called || !snapshot.Config.DisableApproval || snapshot.Config.Evaluator.Sandbox.Runtime != "podman" {
				t.Fatalf("not reflected: %+v %v callback=%v", snapshot, err, called)
			}
		})
	}
}
