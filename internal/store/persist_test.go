package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestNewWithPath_CreatesEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("NewWithPath() error = %v", err)
	}
	if s.HasByKey("org", "repo", 1) {
		t.Error("新規ストアにレコードがあってはいけない")
	}
}

func TestNewWithPath_LoadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	s1, _ := NewWithPath(path)
	r := &model.AlertRecord{
		Alert:      model.Alert{Number: 42, PackageName: "lodash", Owner: "org", Repo: "repo"},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	}
	s1.Save(r)

	// 別インスタンスで同じファイルを開く
	s2, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("NewWithPath() error = %v", err)
	}
	if !s2.HasByKey("org", "repo", 42) {
		t.Error("再起動後にNumber=42が見つからない")
	}
	got, _ := s2.Get(r.Alert.ID)
	if got.Alert.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want lodash", got.Alert.PackageName)
	}
}

func TestNewWithPath_PersistsUpdateState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	s1, _ := NewWithPath(path)
	r := &model.AlertRecord{
		Alert:      model.Alert{Number: 1, Owner: "org", Repo: "repo"},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	}
	s1.Save(r)
	_ = s1.UpdateState(r.Alert.ID, model.AlertStateMerged)

	s2, _ := NewWithPath(path)
	got, err := s2.Get(r.Alert.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.State != model.AlertStateMerged {
		t.Errorf("State = %q, want merged", got.State)
	}
}

func TestNewWithPath_PersistsEvaluation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	s1, _ := NewWithPath(path)
	r := &model.AlertRecord{
		Alert: model.Alert{Number: 5, PackageName: "axios", Owner: "org", Repo: "repo"},
		Evaluation: &model.Evaluation{
			Risk:           "high",
			Recommendation: "approve",
			Reasoning:      "テスト",
		},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	}
	s1.Save(r)

	s2, _ := NewWithPath(path)
	got, _ := s2.Get(r.Alert.ID)
	if got.Evaluation == nil {
		t.Fatal("Evaluationがnilになっている")
	}
	if got.Evaluation.Risk != "high" {
		t.Errorf("Risk = %q, want high", got.Evaluation.Risk)
	}
}
