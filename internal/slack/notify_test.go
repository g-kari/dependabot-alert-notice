package slack

import (
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// TestBuildBlocks_WithEval はAI評価ありのブロック生成でパニックしないことを確認
func TestBuildBlocks_WithEval(t *testing.T) {
	record := &model.AlertRecord{
		Alert: model.Alert{
			ID:          1,
			PackageName: "lodash",
			Owner:       "myorg",
			Repo:        "myrepo",
			Severity:    model.SeverityHigh,
			CVEID:       "CVE-2021-1234",
			CVSSScore:   7.5,
			FixedIn:     "4.17.21",
		},
		Evaluation: &model.Evaluation{
			Risk:           "high",
			Recommendation: "approve",
			Reasoning:      "テスト理由",
		},
	}

	blocks := buildBlocks(record)
	if len(blocks) == 0 {
		t.Error("blocks should not be empty")
	}
}

// TestBuildBlocks_WithoutEval はAI評価なし（nil）でパニックしないことを確認
func TestBuildBlocks_WithoutEval(t *testing.T) {
	record := &model.AlertRecord{
		Alert: model.Alert{
			ID:          2,
			PackageName: "express",
			Owner:       "myorg",
			Repo:        "myrepo",
			Severity:    model.SeverityCritical,
			CVEID:       "CVE-2022-9999",
			CVSSScore:   9.8,
		},
		Evaluation: nil,
	}

	// nilのままでpanicしないこと
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("buildBlocks panicked with nil eval: %v", r)
		}
	}()

	blocks := buildBlocks(record)
	if len(blocks) == 0 {
		t.Error("blocks should not be empty even without eval")
	}
}
