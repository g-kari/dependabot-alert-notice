package merger

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/github"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type Merger struct {
	ghPath   string
	store    *store.Store
	ghClient github.Client
}

func New(cfg *config.Config, s *store.Store, ghClient github.Client) *Merger {
	return &Merger{
		ghPath:   cfg.GhPath,
		store:    s,
		ghClient: ghClient,
	}
}

func (m *Merger) Merge(ctx context.Context, alertID int) error {
	record, err := m.store.Get(alertID)
	if err != nil {
		return fmt.Errorf("アラート取得失敗: %w", err)
	}

	alert := record.Alert

	// Dependabot PRを検索
	prNum, err := m.ghClient.FindDependabotPR(ctx, alert.Owner, alert.Repo, alert.PackageName)
	if err != nil {
		return fmt.Errorf("PR検索失敗: %w", err)
	}

	// PRをマージ
	repo := fmt.Sprintf("%s/%s", alert.Owner, alert.Repo)
	prNumStr := github.PRNumberToString(prNum)
	cmd := exec.CommandContext(ctx, m.ghPath, "pr", "merge", prNumStr,
		"--repo", repo,
		"--squash", "--delete-branch", "--auto",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("PRマージ失敗", "pr", prNum, "repo", repo, "output", string(out), "error", err)
		return fmt.Errorf("PRマージ失敗 (#%d): %w", prNum, err)
	}

	// ステート更新
	if err := m.store.UpdateState(alertID, model.AlertStateMerged); err != nil {
		return fmt.Errorf("ステート更新失敗: %w", err)
	}

	slog.Info("PRマージ完了", "alertID", alertID, "pr", prNum, "repo", repo)
	return nil
}

func (m *Merger) Approve(ctx context.Context, alertID int) error {
	if err := m.store.UpdateState(alertID, model.AlertStateApproved); err != nil {
		return fmt.Errorf("承認ステート更新失敗: %w", err)
	}
	return m.Merge(ctx, alertID)
}

func (m *Merger) Reject(alertID int) error {
	return m.store.UpdateState(alertID, model.AlertStateRejected)
}
