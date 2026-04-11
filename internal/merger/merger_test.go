package merger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// mockGHClient は github.Client のモック実装
type mockGHClient struct {
	prNum    int
	prErr    error
	fetchErr error
}

func (m *mockGHClient) FetchAlerts(ctx context.Context, target config.Target) ([]model.Alert, error) {
	return nil, m.fetchErr
}

func (m *mockGHClient) FindDependabotPR(ctx context.Context, owner, repo, pkgName string) (int, error) {
	return m.prNum, m.prErr
}

func setupMerger(t *testing.T, ghClient *mockGHClient, ghPath string) (*Merger, *store.Store) {
	t.Helper()
	s := store.New()
	cfg := &config.Config{GhPath: ghPath}
	return New(cfg, s, ghClient), s
}

func saveRecord(s *store.Store, id int, pkg, owner, repo string) {
	s.Save(&model.AlertRecord{
		Alert: model.Alert{
			ID:          id,
			PackageName: pkg,
			Owner:       owner,
			Repo:        repo,
		},
		State: model.AlertStatePending,
	})
}

// fakeGhBin はテスト用の偽ghバイナリを一時ディレクトリに作成して返す。
// successが trueなら終了コード0、falseなら1を返すスクリプトを生成する。
func fakeGhBin(t *testing.T, success bool) string {
	t.Helper()
	dir := t.TempDir()

	var script string
	exitCode := 0
	if !success {
		exitCode = 1
	}

	if runtime.GOOS == "windows" {
		script = fmt.Sprintf("@echo off\r\nexit %d\r\n", exitCode)
		path := filepath.Join(dir, "gh.bat")
		if err := os.WriteFile(path, []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
		return path
	}

	script = fmt.Sprintf("#!/bin/sh\nexit %d\n", exitCode)
	path := filepath.Join(dir, "gh")
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReject(t *testing.T) {
	m, s := setupMerger(t, &mockGHClient{}, "gh")
	saveRecord(s, 1, "lodash", "org", "repo")

	if err := m.Reject(1); err != nil {
		t.Fatalf("Reject() error = %v", err)
	}

	rec, _ := s.Get(1)
	if rec.State != model.AlertStateRejected {
		t.Errorf("State = %q, want %q", rec.State, model.AlertStateRejected)
	}
}

func TestReject_NotFound(t *testing.T) {
	m, _ := setupMerger(t, &mockGHClient{}, "gh")
	err := m.Reject(999)
	if err == nil {
		t.Error("Reject() should return error for non-existent alert")
	}
}

func TestApprove_SetsApprovedState(t *testing.T) {
	// PR検索エラーでもApproveステートはセットされる（Mergeは失敗）
	ghClient := &mockGHClient{prErr: errors.New("PR not found")}
	m, s := setupMerger(t, ghClient, "gh")
	saveRecord(s, 1, "lodash", "org", "repo")

	// Mergeが失敗するのでApproveはエラーを返す
	err := m.Approve(context.Background(), 1)
	if err == nil {
		t.Error("Approve() should return error when PR not found")
	}

	// それでもstoreのStateはApprovedに変わっている
	rec, _ := s.Get(1)
	if rec.State != model.AlertStateApproved {
		t.Errorf("State = %q, want %q", rec.State, model.AlertStateApproved)
	}
}

func TestApprove_NotFound(t *testing.T) {
	m, _ := setupMerger(t, &mockGHClient{}, "gh")
	err := m.Approve(context.Background(), 999)
	if err == nil {
		t.Error("Approve() should return error for non-existent alert")
	}
}

func TestMerge_AlertNotFound(t *testing.T) {
	m, _ := setupMerger(t, &mockGHClient{prNum: 42}, "gh")
	err := m.Merge(context.Background(), 999)
	if err == nil {
		t.Error("Merge() should return error for non-existent alert")
	}
}

func TestMerge_PRNotFound(t *testing.T) {
	ghClient := &mockGHClient{prErr: errors.New("no PR")}
	m, s := setupMerger(t, ghClient, "gh")
	saveRecord(s, 1, "lodash", "org", "repo")

	err := m.Merge(context.Background(), 1)
	if err == nil {
		t.Error("Merge() should return error when PR not found")
	}
}

func TestMerge_GhCommandFails(t *testing.T) {
	ghPath := fakeGhBin(t, false) // 終了コード1を返す偽gh
	ghClient := &mockGHClient{prNum: 42}
	m, s := setupMerger(t, ghClient, ghPath)
	saveRecord(s, 1, "lodash", "org", "repo")

	err := m.Merge(context.Background(), 1)
	if err == nil {
		t.Error("Merge() should return error when gh command fails")
	}

	rec, _ := s.Get(1)
	// gh失敗時はMergedにならない
	if rec.State == model.AlertStateMerged {
		t.Error("State should not be merged when gh command fails")
	}
}

func TestMerge_Success(t *testing.T) {
	// gh CLIが存在する環境でのみ実行（テスト環境ではghコマンド不要のケースをテスト）
	ghPath := fakeGhBin(t, true) // 終了コード0を返す偽gh
	ghClient := &mockGHClient{prNum: 42}
	m, s := setupMerger(t, ghClient, ghPath)
	saveRecord(s, 1, "lodash", "org", "repo")

	err := m.Merge(context.Background(), 1)
	if err != nil {
		// 偽ghがpr mergeコマンドを解釈しない場合もあるのでスキップ
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("Merge() unexpected error: %v", err)
		}
	}

	rec, _ := s.Get(1)
	if rec.State != model.AlertStateMerged {
		t.Errorf("State = %q, want %q", rec.State, model.AlertStateMerged)
	}
	if rec.MergedAt == nil {
		t.Error("MergedAt should be set after merge")
	}
}
