package slack

import (
	"context"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestDisabledApprovalRemovesButtonsAndRejectsOldActions(t *testing.T) {
	rec := &model.AlertRecord{Alert: model.Alert{ID: 1}, Evaluation: &model.Evaluation{AWSRisk: "AWS条件"}}
	text := blocksToText(buildBlocks(rec, true))
	if strings.Contains(text, `"action_id":"approve"`) || strings.Contains(text, `"action_id":"reject"`) {
		t.Fatal(text)
	}
	if !strings.Contains(text, "AWS条件") {
		t.Fatal("AWS detail missing")
	}
	m := &mockMerger{}
	c := newTestSlackClient(m)
	disabled := true
	c.SetConfigSource(func() (config.Snapshot, error) {
		return config.Snapshot{Config: config.Config{DisableApproval: disabled}}, nil
	})
	for _, action := range []string{"approve", "reject"} {
		c.handleInteraction(context.Background(), makeCallback(action, "1", "U1"))
	}
	if len(m.approved)+len(m.rejected) != 0 {
		t.Fatal("old action accepted")
	}
	disabled = false
	c.handleInteraction(context.Background(), makeCallback("approve", "1", "U1"))
	if len(m.approved) != 1 {
		t.Fatal("new setting was not applied")
	}
}
