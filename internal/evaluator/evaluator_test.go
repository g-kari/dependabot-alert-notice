package evaluator

import (
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

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
	args := e.buildDockerArgs("test prompt", "/home/test/.claude")

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

func TestParseEvaluationClaudeFormat(t *testing.T) {
	// claude --output-format json の出力形式
	input := `{"result":"{\"risk\":\"medium\",\"impact\":\"test\",\"recommendation\":\"manual-review\",\"reasoning\":\"needs review\"}"}`
	eval, err := parseEvaluation([]byte(input))
	if err != nil {
		t.Fatalf("parseEvaluation() error = %v", err)
	}
	if eval.Risk != "medium" {
		t.Errorf("Risk = %q, want %q", eval.Risk, "medium")
	}
}
