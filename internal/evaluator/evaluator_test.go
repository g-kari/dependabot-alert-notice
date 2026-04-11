package evaluator

import (
	"testing"
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
