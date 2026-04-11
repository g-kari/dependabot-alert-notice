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
	if s.Has(1) {
		t.Error("新規ストアにレコードがあってはいけない")
	}
}

func TestNewWithPath_LoadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	s1, _ := NewWithPath(path)
	s1.Save(&model.AlertRecord{
		Alert:      model.Alert{ID: 42, PackageName: "lodash", Owner: "org", Repo: "repo"},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})

	// 別インスタンスで同じファイルを開く
	s2, err := NewWithPath(path)
	if err != nil {
		t.Fatalf("NewWithPath() error = %v", err)
	}
	if !s2.Has(42) {
		t.Error("再起動後にID=42が見つからない")
	}
	r, _ := s2.Get(42)
	if r.Alert.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want lodash", r.Alert.PackageName)
	}
}

func TestNewWithPath_PersistsUpdateState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	s1, _ := NewWithPath(path)
	s1.Save(&model.AlertRecord{
		Alert:      model.Alert{ID: 1, Owner: "org", Repo: "repo"},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})
	_ = s1.UpdateState(1, model.AlertStateMerged)

	s2, _ := NewWithPath(path)
	r, err := s2.Get(1)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if r.State != model.AlertStateMerged {
		t.Errorf("State = %q, want merged", r.State)
	}
}

func TestNewWithPath_PersistsEvaluation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")

	s1, _ := NewWithPath(path)
	s1.Save(&model.AlertRecord{
		Alert: model.Alert{ID: 5, PackageName: "axios", Owner: "org", Repo: "repo"},
		Evaluation: &model.Evaluation{
			Risk:           "high",
			Recommendation: "approve",
			Reasoning:      "テスト",
		},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	})

	s2, _ := NewWithPath(path)
	r, _ := s2.Get(5)
	if r.Evaluation == nil {
		t.Fatal("Evaluationがnilになっている")
	}
	if r.Evaluation.Risk != "high" {
		t.Errorf("Risk = %q, want high", r.Evaluation.Risk)
	}
}
