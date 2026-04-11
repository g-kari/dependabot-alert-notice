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
			Number:      1,
			PackageName: "lodash",
			Owner:       "test-org",
			Repo:        "test-repo",
			Severity:    model.SeverityHigh,
		},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	}

	s.Save(record)
	if record.Alert.ID == 0 {
		t.Fatal("Save() should assign internal ID")
	}

	got, err := s.Get(record.Alert.ID)
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
	if s.HasByKey("org", "repo", 1) {
		t.Error("HasByKey() should return false for empty store")
	}

	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1},
		State: model.AlertStatePending,
	})

	if !s.HasByKey("org", "repo", 1) {
		t.Error("HasByKey() should return true after Save()")
	}
}

func TestUpdateState(t *testing.T) {
	s := New()
	r := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1},
		State: model.AlertStatePending,
	}
	s.Save(r)

	if err := s.UpdateState(r.Alert.ID, model.AlertStateMerged); err != nil {
		t.Fatalf("UpdateState() error = %v", err)
	}

	got, _ := s.Get(r.Alert.ID)
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
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, State: model.AlertStatePending})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, State: model.AlertStatePending})

	list := s.List()
	if len(list) != 2 {
		t.Errorf("List() len = %d, want 2", len(list))
	}
}

func TestEvalStatusSaveAndGet(t *testing.T) {
	s := New()

	record := &model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo", Number: 10, PackageName: "axios"},
		State:      model.AlertStatePending,
		EvalStatus: model.EvalStatusEvaluating,
		NotifiedAt: time.Now(),
	}
	s.Save(record)

	got, err := s.Get(record.Alert.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.EvalStatus != model.EvalStatusEvaluating {
		t.Errorf("EvalStatus = %q, want %q", got.EvalStatus, model.EvalStatusEvaluating)
	}
}

func TestUpdateEvalStatus(t *testing.T) {
	s := New()
	r := &model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo", Number: 20},
		State:      model.AlertStatePending,
		EvalStatus: model.EvalStatusEvaluating,
	}
	s.Save(r)

	if err := s.UpdateEvalStatus(r.Alert.ID, model.EvalStatusFailed); err != nil {
		t.Fatalf("UpdateEvalStatus() error = %v", err)
	}

	got, _ := s.Get(r.Alert.ID)
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
	if !s.NeedsEvaluation(9999) {
		t.Error("NeedsEvaluation() should return true for non-existent alert")
	}

	// evaluating → false（評価中はスキップ）
	r1 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, EvalStatus: model.EvalStatusEvaluating}
	s.Save(r1)
	if s.NeedsEvaluation(r1.Alert.ID) {
		t.Error("NeedsEvaluation() should return false for evaluating alert")
	}

	// done → false
	r2 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, EvalStatus: model.EvalStatusDone}
	s.Save(r2)
	if s.NeedsEvaluation(r2.Alert.ID) {
		t.Error("NeedsEvaluation() should return false for done alert")
	}

	// failed → true（再試行対象）
	r3 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 3}, EvalStatus: model.EvalStatusFailed}
	s.Save(r3)
	if !s.NeedsEvaluation(r3.Alert.ID) {
		t.Error("NeedsEvaluation() should return true for failed alert")
	}
}

func TestListIncludesEvalStatus(t *testing.T) {
	s := New()
	r1 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, EvalStatus: model.EvalStatusEvaluating}
	r2 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, EvalStatus: model.EvalStatusFailed}
	s.Save(r1)
	s.Save(r2)

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("List() len = %d, want 2", len(list))
	}
	statuses := map[int]model.EvalStatus{}
	for _, r := range list {
		statuses[r.Alert.ID] = r.EvalStatus
	}
	if statuses[r1.Alert.ID] != model.EvalStatusEvaluating {
		t.Errorf("r1 EvalStatus = %q, want evaluating", statuses[r1.Alert.ID])
	}
	if statuses[r2.Alert.ID] != model.EvalStatusFailed {
		t.Errorf("r2 EvalStatus = %q, want failed", statuses[r2.Alert.ID])
	}
}

func TestListPendingEvaluation(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, EvalStatus: model.EvalStatusPending})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, EvalStatus: model.EvalStatusFailed})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 3}, EvalStatus: model.EvalStatusDone})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 4}, EvalStatus: model.EvalStatusEvaluating})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 5}, EvalStatus: model.EvalStatusPending})

	got := s.ListPendingEvaluation(10)
	if len(got) != 3 { // pending x2 + failed x1
		t.Errorf("ListPendingEvaluation() len = %d, want 3", len(got))
	}

	// limit が効くか
	got2 := s.ListPendingEvaluation(2)
	if len(got2) != 2 {
		t.Errorf("ListPendingEvaluation(2) len = %d, want 2", len(got2))
	}
}

// TestSave_SameNumberDifferentRepos は同じアラート番号でも別リポジトリなら別レコードとして保存されることを確認
func TestSave_SameNumberDifferentRepos(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repoA", Number: 6},
		State: model.AlertStatePending,
	})
	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repoB", Number: 6},
		State: model.AlertStatePending,
	})
	list := s.List()
	if len(list) != 2 {
		t.Errorf("List() len = %d, want 2 (同番号でも別リポは別レコード)", len(list))
	}
}

// TestHasByKey は HasByKey が (owner, repo, number) の組み合わせで重複チェックすることを確認
func TestHasByKey(t *testing.T) {
	s := New()
	if s.HasByKey("org", "repo", 1) {
		t.Error("HasByKey() should return false for empty store")
	}
	record := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1},
		State: model.AlertStatePending,
	}
	s.Save(record)
	if !s.HasByKey("org", "repo", 1) {
		t.Error("HasByKey() should return true after Save()")
	}
	if s.HasByKey("org", "other-repo", 1) {
		t.Error("HasByKey() should return false for different repo with same number")
	}
}

// TestSave_AssignsInternalID は Save後にAuto-increment内部IDが record.Alert.ID にセットされることを確認
func TestSave_AssignsInternalID(t *testing.T) {
	s := New()
	r1 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, State: model.AlertStatePending}
	r2 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, State: model.AlertStatePending}
	s.Save(r1)
	s.Save(r2)
	if r1.Alert.ID == 0 {
		t.Error("Save() should assign internal ID to r1.Alert.ID")
	}
	if r2.Alert.ID == 0 {
		t.Error("Save() should assign internal ID to r2.Alert.ID")
	}
	if r1.Alert.ID == r2.Alert.ID {
		t.Error("Save() should assign distinct internal IDs")
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
