package slack

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	slackgo "github.com/slack-go/slack"
)

// blocksToText はBlock KitのブロックスライスをJSON化してテキスト検索用文字列を返す
func blocksToText(blocks []slackgo.Block) string {
	b, _ := json.Marshal(blocks)
	return string(b)
}

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
			Impact:         "• test impact",
			Recommendation: "approve",
			Reasoning:      "テスト理由",
		},
	}

	blocks := buildBlocks(record)
	if len(blocks) == 0 {
		t.Error("blocks should not be empty")
	}
}

// TestBuildBlocks_WithEval_ContainsImpactAndReasoning はImpactとReasoningが表示されることを確認
func TestBuildBlocks_WithEval_ContainsImpactAndReasoning(t *testing.T) {
	record := &model.AlertRecord{
		Alert: model.Alert{
			ID:          1,
			PackageName: "lodash",
			Owner:       "myorg",
			Repo:        "myrepo",
			Severity:    model.SeverityHigh,
		},
		Evaluation: &model.Evaluation{
			Impact:         "• RCE possible\n• Data leak",
			Recommendation: "approve",
			Reasoning:      "• Using eval() with user input",
		},
	}

	text := blocksToText(buildBlocks(record))

	if !strings.Contains(text, "侵害される内容") {
		t.Error("blocks should contain '侵害される内容' label")
	}
	if !strings.Contains(text, "侵害される使い方") {
		t.Error("blocks should contain '侵害される使い方' label")
	}
	if !strings.Contains(text, "RCE possible") {
		t.Error("blocks should contain impact content")
	}
}

// TestBuildBlocks_WithEval_NoRisk はRiskが表示されないことを確認
func TestBuildBlocks_WithEval_NoRisk(t *testing.T) {
	record := &model.AlertRecord{
		Alert:      model.Alert{ID: 1, PackageName: "express", Owner: "org", Repo: "repo", Severity: model.SeverityHigh},
		Evaluation: &model.Evaluation{Impact: "test", Recommendation: "approve", Reasoning: "test"},
	}
	text := blocksToText(buildBlocks(record))
	if strings.Contains(text, "*Risk:*") {
		t.Error("blocks should NOT contain '*Risk:*'")
	}
}

// TestBuildResolvedBlocks_ContainsDone は対応済みブロックに「✅ 対応済み」が含まれることを確認
func TestBuildResolvedBlocks_ContainsDone(t *testing.T) {
	record := &model.AlertRecord{
		Alert: model.Alert{
			ID:          1,
			PackageName: "lodash",
			Owner:       "myorg",
			Repo:        "myrepo",
			Severity:    model.SeverityHigh,
			HTMLURL:     "https://github.com/myorg/myrepo/security/dependabot/1",
		},
	}

	text := blocksToText(buildResolvedBlocks(record))
	if !strings.Contains(text, "対応済み") {
		t.Error("resolved blocks should contain '対応済み'")
	}
}

// TestBuildResolvedBlocks_NoActionButtons はアクションボタンが除去されていることを確認
func TestBuildResolvedBlocks_NoActionButtons(t *testing.T) {
	record := &model.AlertRecord{
		Alert: model.Alert{
			ID:          1,
			PackageName: "lodash",
			Owner:       "myorg",
			Repo:        "myrepo",
			Severity:    model.SeverityHigh,
		},
	}

	text := blocksToText(buildResolvedBlocks(record))
	if strings.Contains(text, "マージ承認") {
		t.Error("resolved blocks should NOT contain action buttons")
	}
	if strings.Contains(text, "却下") {
		t.Error("resolved blocks should NOT contain reject button")
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
