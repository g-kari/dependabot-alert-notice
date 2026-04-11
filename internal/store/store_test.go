package store

import (
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestSaveAndGet(t *testing.T) {
	s := New()

	record := &model.AlertRecord{
		Alert: model.Alert{
			ID:          1,
			PackageName: "lodash",
			Owner:       "test-org",
			Repo:        "test-repo",
			Severity:    model.SeverityHigh,
		},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	}

	s.Save(record)

	got, err := s.Get(1)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Alert.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want %q", got.Alert.PackageName, "lodash")
	}
}

func TestGetNotFound(t *testing.T) {
	s := New()
	_, err := s.Get(999)
	if err == nil {
		t.Error("Get() should return error for non-existent ID")
	}
}

func TestHas(t *testing.T) {
	s := New()
	if s.Has(1) {
		t.Error("Has() should return false for empty store")
	}

	s.Save(&model.AlertRecord{
		Alert: model.Alert{ID: 1},
		State: model.AlertStatePending,
	})

	if !s.Has(1) {
		t.Error("Has() should return true after Save()")
	}
}

func TestUpdateState(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert: model.Alert{ID: 1},
		State: model.AlertStatePending,
	})

	if err := s.UpdateState(1, model.AlertStateMerged); err != nil {
		t.Fatalf("UpdateState() error = %v", err)
	}

	got, _ := s.Get(1)
	if got.State != model.AlertStateMerged {
		t.Errorf("State = %q, want %q", got.State, model.AlertStateMerged)
	}
	if got.MergedAt == nil {
		t.Error("MergedAt should be set when state is merged")
	}
}

func TestUpdateStateNotFound(t *testing.T) {
	s := New()
	err := s.UpdateState(999, model.AlertStateMerged)
	if err == nil {
		t.Error("UpdateState() should return error for non-existent ID")
	}
}

func TestList(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{Alert: model.Alert{ID: 1}, State: model.AlertStatePending})
	s.Save(&model.AlertRecord{Alert: model.Alert{ID: 2}, State: model.AlertStatePending})

	list := s.List()
	if len(list) != 2 {
		t.Errorf("List() len = %d, want 2", len(list))
	}
}

func TestEvalStatusSaveAndGet(t *testing.T) {
	s := New()

	record := &model.AlertRecord{
		Alert:      model.Alert{ID: 10, PackageName: "axios"},
		State:      model.AlertStatePending,
		EvalStatus: model.EvalStatusEvaluating,
		NotifiedAt: time.Now(),
	}
	s.Save(record)

	got, err := s.Get(10)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.EvalStatus != model.EvalStatusEvaluating {
		t.Errorf("EvalStatus = %q, want %q", got.EvalStatus, model.EvalStatusEvaluating)
	}
}

func TestUpdateEvalStatus(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{ID: 20},
		State:      model.AlertStatePending,
		EvalStatus: model.EvalStatusEvaluating,
	})

	if err := s.UpdateEvalStatus(20, model.EvalStatusFailed); err != nil {
		t.Fatalf("UpdateEvalStatus() error = %v", err)
	}

	got, _ := s.Get(20)
	if got.EvalStatus != model.EvalStatusFailed {
		t.Errorf("EvalStatus = %q, want %q", got.EvalStatus, model.EvalStatusFailed)
	}
}

func TestUpdateEvalStatusNotFound(t *testing.T) {
	s := New()
	err := s.UpdateEvalStatus(999, model.EvalStatusDone)
	if err == nil {
		t.Error("UpdateEvalStatus() should return error for non-existent ID")
	}
}

func TestNeedsEvaluation(t *testing.T) {
	s := New()

	// 存在しない → true
	if !s.NeedsEvaluation(1) {
		t.Error("NeedsEvaluation() should return true for non-existent alert")
	}

	// evaluating → false（評価中はスキップ）
	s.Save(&model.AlertRecord{Alert: model.Alert{ID: 1}, EvalStatus: model.EvalStatusEvaluating})
	if s.NeedsEvaluation(1) {
		t.Error("NeedsEvaluation() should return false for evaluating alert")
	}

	// done → false
	s.Save(&model.AlertRecord{Alert: model.Alert{ID: 2}, EvalStatus: model.EvalStatusDone})
	if s.NeedsEvaluation(2) {
		t.Error("NeedsEvaluation() should return false for done alert")
	}

	// failed → true（再試行対象）
	s.Save(&model.AlertRecord{Alert: model.Alert{ID: 3}, EvalStatus: model.EvalStatusFailed})
	if !s.NeedsEvaluation(3) {
		t.Error("NeedsEvaluation() should return true for failed alert")
	}
}

func TestListIncludesEvalStatus(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{Alert: model.Alert{ID: 1}, EvalStatus: model.EvalStatusEvaluating})
	s.Save(&model.AlertRecord{Alert: model.Alert{ID: 2}, EvalStatus: model.EvalStatusFailed})

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("List() len = %d, want 2", len(list))
	}
	statuses := map[int]model.EvalStatus{}
	for _, r := range list {
		statuses[r.Alert.ID] = r.EvalStatus
	}
	if statuses[1] != model.EvalStatusEvaluating {
		t.Errorf("id=1 EvalStatus = %q, want evaluating", statuses[1])
	}
	if statuses[2] != model.EvalStatusFailed {
		t.Errorf("id=2 EvalStatus = %q, want failed", statuses[2])
	}
}

func TestAddLogAndListLogs(t *testing.T) {
	s := New()
	s.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "info", Message: "test1"})
	s.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "error", Message: "test2"})

	logs := s.ListLogs()
	if len(logs) != 2 {
		t.Errorf("ListLogs() len = %d, want 2", len(logs))
	}
}
