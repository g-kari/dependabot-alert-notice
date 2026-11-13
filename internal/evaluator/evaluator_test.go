package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestClaudeModelCommandArgs(t *testing.T) {
	cfg := &config.Config{ClaudePath: "claude", Evaluator: config.EvaluatorConfig{ClaudeModel: "claude-sonnet-test"}}
	e, ok := New(cfg).(*DirectEvaluator)
	if !ok || e.model != "claude-sonnet-test" {
		t.Fatalf("direct evaluator = %+v", e)
	}
	args := claudeArgs("prompt", cfg.Evaluator.ClaudeModel)
	if got := strings.Join(args, " "); !strings.Contains(got, "--model claude-sonnet-test") {
		t.Fatalf("direct args = %q", got)
	}
	docker := &DockerEvaluator{cfg: cfg.Evaluator}
	if got := strings.Join(docker.buildDockerArgs("prompt", "C:/Users/test/.claude"), " "); !strings.Contains(got, "--model claude-sonnet-test") {
		t.Fatalf("docker args = %q", got)
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantFound bool
	}{
		{
			name:      "pure JSON",
			input:     `{"risk":"high","impact":"test","recommendation":"approve","reasoning":"ok"}`,
			want:      `{"risk":"high","impact":"test","recommendation":"approve","reasoning":"ok"}`,
			wantFound: true,
		},
		{
			name:      "JSON with prefix text",
			input:     `Here is the evaluation:\n{"risk":"medium","impact":"low","recommendation":"approve","reasoning":"safe"}`,
			want:      `{"risk":"medium","impact":"low","recommendation":"approve","reasoning":"safe"}`,
			wantFound: true,
		},
		{
			name:      "JSON with suffix text",
			input:     `{"risk":"low","impact":"none","recommendation":"approve","reasoning":"ok"}\nDone.`,
			want:      `{"risk":"low","impact":"none","recommendation":"approve","reasoning":"ok"}`,
			wantFound: true,
		},
		{
			name:      "no JSON",
			input:     "Just some plain text without any braces",
			want:      "Just some plain text without any braces",
			wantFound: false,
		},
		{
			name:      "starts with J like error message",
			input:     "JSONで回答します",
			want:      "JSONで回答します",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := extractJSON([]byte(tt.input))
			if found != tt.wantFound {
				t.Errorf("extractJSON() found = %v, want %v", found, tt.wantFound)
			}
			if string(got) != tt.want {
				t.Errorf("extractJSON() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestParseEvaluation_NoJSON(t *testing.T) {
	input := "JSONで回答します。リスクは高いです。"
	_, err := parseEvaluation([]byte(input))
	if err == nil {
		t.Fatal("parseEvaluation() error = nil, want error")
	}
	// エラーメッセージが明確であることを確認
	errMsg := err.Error()
	if errMsg == "invalid character 'J' looking for beginning of value" {
		t.Errorf("error message should be descriptive, got cryptic: %q", errMsg)
	}
}

func TestParseEvaluation(t *testing.T) {
	input := `{"risk":"high","impact":"RCE vulnerability","recommendation":"approve","reasoning":"Critical fix needed"}`
	eval, err := parseEvaluation([]byte(input))
	if err != nil {
		t.Fatalf("parseEvaluation() error = %v", err)
	}
	if eval.Risk != "high" {
		t.Errorf("Risk = %q, want %q", eval.Risk, "high")
	}
	if eval.Recommendation != "approve" {
		t.Errorf("Recommendation = %q, want %q", eval.Recommendation, "approve")
	}
}

func TestParseEvaluation_FormattedOutput(t *testing.T) {
	// 箇条書き形式（改行あり）のJSONがパースできることを確認
	input := `{"impact":"• RCE実行が可能\n• 機密データの漏洩リスク\n• サービス停止の可能性","recommendation":"approve","reasoning":"• express.json()で外部入力を受け取る場合\n• プロトタイプ汚染につながるパターン"}`
	eval, err := parseEvaluation([]byte(input))
	if err != nil {
		t.Fatalf("parseEvaluation() error = %v", err)
	}
	if eval.Impact == "" {
		t.Error("Impact should not be empty")
	}
	if eval.Reasoning == "" {
		t.Error("Reasoning should not be empty")
	}
	// 箇条書きマーカーが含まれていることを確認
	if len(eval.Impact) < 2 {
		t.Errorf("Impact too short: %q", eval.Impact)
	}
}

// TestDockerEvaluator_SecurityOptFlag は --security-opt=no-new-privileges が使われていることを確認
func TestDockerEvaluator_SecurityOptFlag(t *testing.T) {
	cfg := config.EvaluatorConfig{
		Sandbox: config.SandboxConfig{
			Image:       "test-image:latest",
			MemoryLimit: "512m",
			CPULimit:    "0.5",
		},
	}
	e := &DockerEvaluator{cfg: cfg}
	args := e.buildDockerArgs("test prompt", filepath.Join("home", "test", ".claude"))

	hasSecurityOpt := false
	for _, arg := range args {
		if arg == "--security-opt=no-new-privileges" {
			hasSecurityOpt = true
		}
		if arg == "--no-new-privileges" {
			t.Error("args should not contain deprecated --no-new-privileges flag")
		}
	}
	if !hasSecurityOpt {
		t.Error("args should contain --security-opt=no-new-privileges")
	}
}

// TestDockerEvaluator_MountsClaudeJSON は ~/.claude.json もマウントされることを確認
func TestDockerEvaluator_MountsClaudeJSON(t *testing.T) {
	cfg := config.EvaluatorConfig{
		Sandbox: config.SandboxConfig{
			Image:       "test-image:latest",
			MemoryLimit: "512m",
			CPULimit:    "0.5",
		},
	}
	e := &DockerEvaluator{cfg: cfg}
	claudeHome := filepath.Join("home", "test", ".claude")
	args := e.buildDockerArgs("test prompt", claudeHome)
	claudeJSON := filepath.Join(filepath.Dir(claudeHome), ".claude.json")

	hasDirMount := false
	hasJSONMount := false
	for i, arg := range args {
		if arg == "-v" && i+1 < len(args) {
			v := args[i+1]
			if v == claudeHome+":/home/node/.claude:ro" {
				hasDirMount = true
			}
			if v == claudeJSON+":/home/node/.claude.json:ro" {
				hasJSONMount = true
			}
		}
	}
	if !hasDirMount {
		t.Error("args should mount ~/.claude directory")
	}
	if !hasJSONMount {
		t.Error("args should mount ~/.claude.json file")
	}
}

func TestParseEvaluationClaudeFormat(t *testing.T) {
	// claude --output-format json の旧出力形式: {"result":"..."}
	input := `{"result":"{\"risk\":\"medium\",\"impact\":\"test\",\"recommendation\":\"manual-review\",\"reasoning\":\"needs review\"}"}`
	eval, err := parseEvaluation([]byte(input))
	if err != nil {
		t.Fatalf("parseEvaluation() error = %v", err)
	}
	if eval.Risk != "medium" {
		t.Errorf("Risk = %q, want %q", eval.Risk, "medium")
	}
}

func TestParseEvaluation_ArrayFormat(t *testing.T) {
	// claude --output-format json の新しいストリーム形式（JSON配列）
	input := `[{"type":"system","subtype":"init"},{"type":"assistant","message":{"content":[{"type":"text","text":"thinking..."}]}},{"type":"result","subtype":"success","is_error":false,"result":"{\"risk\":\"high\",\"impact\":\"RCE\",\"recommendation\":\"approve\",\"reasoning\":\"critical patch needed\"}","stop_reason":"end_turn"}]`
	eval, err := parseEvaluation([]byte(input))
	if err != nil {
		t.Fatalf("parseEvaluation() error = %v", err)
	}
	if eval.Risk != "high" {
		t.Errorf("Risk = %q, want high", eval.Risk)
	}
	if eval.Recommendation != "approve" {
		t.Errorf("Recommendation = %q, want approve", eval.Recommendation)
	}
}

func TestParseEvaluation_ArrayFormat_ErrorResult(t *testing.T) {
	// is_error=true の場合はエラーを返す
	input := `[{"type":"result","subtype":"error","is_error":true,"result":""}]`
	_, err := parseEvaluation([]byte(input))
	if err == nil {
		t.Fatal("parseEvaluation() should return error for is_error=true result")
	}
}

func TestNew_HermesProxyDoesNotSelectCLIOrSandbox(t *testing.T) {
	cfg := config.Defaults()
	cfg.Evaluator.Provider = "hermes"
	got := reflect.TypeOf(newEvaluator(cfg, "windows", "amd64")).String()
	if got != "*evaluator.HermesEvaluator" {
		t.Fatalf("provider=hermes selected %s, want HermesEvaluator", got)
	}
}

func TestHermesEvaluator_UsesChatCompletionsWithoutTools(t *testing.T) {
	var method, path, authorization string
	var payload map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path, authorization = r.Method, r.URL.Path, r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		content := `{"impact":"impact sample","recommendation":"manual-review","reasoning":"reason sample","aws_risk":"not applicable"}`
		response, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": content}}}})
		if err != nil {
			t.Errorf("marshal response: %v", err)
			return
		}
		if _, err := w.Write(response); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer server.Close()

	cfg := config.Defaults()
	cfg.Evaluator.Provider = "hermes"
	cfg.Evaluator.HermesBaseURL = server.URL + "/v1"
	cfg.Evaluator.HermesModel = "Hermes-Test-Model"
	cfg.Evaluator.Sandbox.Enabled = false
	cfg.Evaluator.Sandbox.Runtime = "podman"
	got, err := newEvaluator(cfg, "windows", "amd64").Evaluate(context.Background(), model.Alert{PackageName: "sentinel-package"})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got.Recommendation != "manual-review" {
		t.Fatalf("recommendation = %q", got.Recommendation)
	}
	if method != http.MethodPost || path != "/v1/chat/completions" || authorization != "Bearer hermes-proxy" {
		t.Fatalf("request = %s %s authorization=%q", method, path, authorization)
	}
	var request struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if err := json.Unmarshal(rawPayload, &request); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if request.Model != "Hermes-Test-Model" || len(request.Messages) != 1 || request.Messages[0].Role != "user" || !strings.Contains(request.Messages[0].Content, "sentinel-package") {
		t.Fatalf("request model/messages = %q / %+v", request.Model, request.Messages)
	}
	if _, hasTools := payload["tools"]; hasTools {
		t.Fatal("Hermes subscription proxy requests must not enable tools")
	}
}

func TestHermesEvaluator_RejectsIncompleteOrInvalidEvaluation(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "empty object", content: `{}`},
		{name: "missing impact", content: `{"recommendation":"approve","reasoning":"reason","aws_risk":"risk"}`},
		{name: "missing recommendation", content: `{"impact":"impact","reasoning":"reason","aws_risk":"risk"}`},
		{name: "invalid recommendation", content: `{"impact":"impact","recommendation":"maybe","reasoning":"reason","aws_risk":"risk"}`},
		{name: "missing reasoning", content: `{"impact":"impact","recommendation":"approve","aws_risk":"risk"}`},
		{name: "missing AWS risk", content: `{"impact":"impact","recommendation":"approve","reasoning":"reason"}`},
		{name: "whitespace-only impact", content: `{"impact":"  ","recommendation":"approve","reasoning":"reason","aws_risk":"risk"}`},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				response, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": test.content}}}})
				if err != nil {
					t.Errorf("marshal response: %v", err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write(response); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			defer server.Close()

			cfg := config.Defaults()
			cfg.Evaluator.Provider = "hermes"
			cfg.Evaluator.HermesBaseURL = server.URL + "/v1"
			cfg.Evaluator.Sandbox.Enabled = false
			cfg.Evaluator.Sandbox.Runtime = "podman"
			if evaluation, err := newEvaluator(cfg, "windows", "amd64").Evaluate(context.Background(), model.Alert{}); err == nil {
				t.Fatalf("Evaluate() accepted incomplete result %+v", evaluation)
			}
		})
	}
}

func TestHermesEvaluator_CheckUsesModelsEndpointWithoutInference(t *testing.T) {
	var method, path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"data":[{"id":"Hermes-4-70B"}]}`)); err != nil {
			t.Errorf("write models response: %v", err)
		}
	}))
	defer server.Close()

	cfg := config.Defaults()
	cfg.Evaluator.Provider = "hermes"
	cfg.Evaluator.HermesBaseURL = server.URL + "/v1"
	checker, ok := newEvaluator(cfg, "windows", "amd64").(interface{ Check(context.Context) error })
	if !ok {
		t.Fatal("Hermes evaluator does not expose a connectivity check")
	}
	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if method != http.MethodGet || path != "/v1/models" {
		t.Fatalf("check request = %s %s, want GET /v1/models", method, path)
	}
}

func TestHermesEvaluator_CheckRejectsMissingOrUnavailableModel(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "missing data", body: `{}`},
		{name: "empty models", body: `{"data":[]}`},
		{name: "configured model absent", body: `{"data":[{"id":"Other-Model"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(test.body)); err != nil {
					t.Errorf("write model response: %v", err)
				}
			}))
			defer server.Close()

			cfg := config.Defaults()
			cfg.Evaluator.HermesModel = "Hermes-4-70B"
			cfg.Evaluator.HermesBaseURL = server.URL + "/v1"
			checker := newHermesEvaluator(cfg.Evaluator)
			if err := checker.Check(context.Background()); err == nil {
				t.Fatal("Check() accepted a model list without the configured model")
			}
		})
	}
}

func TestHermesEvaluator_CheckRejectsTrailingOrOversizedModelList(t *testing.T) {
	valid := `{"data":[{"id":"Hermes-4-70B"}]}`
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "valid with trailing whitespace", body: valid + "\n \t"},
		{name: "trailing garbage", body: valid + "junk", wantErr: true},
		{name: "second JSON value", body: valid + ` {"data":[]}`, wantErr: true},
		{name: "oversized body", body: valid + strings.Repeat(" ", 1<<20), wantErr: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(test.body)); err != nil {
					t.Errorf("write model response: %v", err)
				}
			}))
			defer server.Close()

			cfg := config.Defaults()
			cfg.Evaluator.HermesModel = "Hermes-4-70B"
			cfg.Evaluator.HermesBaseURL = server.URL + "/v1"
			err := newHermesEvaluator(cfg.Evaluator).Check(context.Background())
			if (err != nil) != test.wantErr {
				t.Fatalf("Check() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestHermesEvaluator_DoesNotFollowRedirects(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationCalls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/v1/chat/completions", http.StatusFound)
	}))
	defer redirect.Close()

	cfg := config.Defaults()
	cfg.Evaluator.Provider = "hermes"
	cfg.Evaluator.HermesBaseURL = redirect.URL + "/v1"
	cfg.Evaluator.Sandbox.Enabled = false
	cfg.Evaluator.Sandbox.Runtime = "podman"
	_, err := newEvaluator(cfg, "windows", "amd64").Evaluate(context.Background(), model.Alert{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("Evaluate() error = %v, want HTTP 302", err)
	}
	if destinationCalls.Load() != 0 {
		t.Fatalf("redirect destination calls = %d, want 0", destinationCalls.Load())
	}
}

func TestHermesEvaluator_ParseErrorsDoNotLogModelPayload(t *testing.T) {
	marker := "private-alert-sentinel"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		content := marker
		response, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"content": content}}}})
		if err != nil {
			t.Errorf("marshal response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(response); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer server.Close()

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	cfg := config.Defaults()
	cfg.Evaluator.Provider = "hermes"
	cfg.Evaluator.HermesBaseURL = server.URL + "/v1"
	cfg.Evaluator.Sandbox.Enabled = false
	cfg.Evaluator.Sandbox.Runtime = "podman"
	_, err := newEvaluator(cfg, "windows", "amd64").Evaluate(context.Background(), model.Alert{})
	if err == nil || strings.Contains(err.Error(), marker) || strings.Contains(logs.String(), marker) {
		t.Fatalf("invalid model output leaked: err=%v logs=%s", err, logs.String())
	}
}
