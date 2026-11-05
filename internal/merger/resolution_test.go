package merger

import (
	"context"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestMergeRefusesResolvedHistoryBeforeExternalWork(t *testing.T) {
	m, s := setupMerger(t, &mockGHClient{}, "")
	t.Cleanup(func() { _ = s.Close() })
	rec := saveRecordWithPR(s, 1, "pkg", "org", "repo", 10)
	s.RemoveResolvedAlerts("org", "repo", nil)
	if err := m.Merge(context.Background(), rec.Alert.ID); err == nil || !strings.Contains(err.Error(), "解決済み") {
		t.Fatalf("resolved history reached external merge path: %v", err)
	}
	if saved, err := s.Get(rec.Alert.ID); err != nil || saved.State != model.AlertStatePending {
		t.Fatalf("history state changed: %+v err=%v", saved, err)
	}
}
