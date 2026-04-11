package evaluator

import (
	"testing"
)

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "pure JSON",
			input: `{"risk":"high","impact":"test","recommendation":"approve","reasoning":"ok"}`,
			want:  `{"risk":"high","impact":"test","recommendation":"approve","reasoning":"ok"}`,
		},
		{
			name:  "JSON with prefix text",
			input: `Here is the evaluation:\n{"risk":"medium","impact":"low","recommendation":"approve","reasoning":"safe"}`,
			want:  `{"risk":"medium","impact":"low","recommendation":"approve","reasoning":"safe"}`,
		},
		{
			name:  "JSON with suffix text",
			input: `{"risk":"low","impact":"none","recommendation":"approve","reasoning":"ok"}\nDone.`,
			want:  `{"risk":"low","impact":"none","recommendation":"approve","reasoning":"ok"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(extractJSON([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("extractJSON() = %q, want %q", got, tt.want)
			}
		})
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
