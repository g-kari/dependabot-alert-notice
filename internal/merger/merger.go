package merger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/github"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type Merger struct {
	ghPath   string
	store    *store.Store
	ghClient github.Client
	policy   *policy.Guard
}

// ErrApprovalDisabled rejects domain operations while approval is disabled.
var ErrApprovalDisabled = errors.New("承認機能は無効化されています")

func New(cfg *config.Config, s *store.Store, ghClient github.Client) *Merger {
	return &Merger{
		ghPath:   cfg.GhPath,
		store:    s,
		ghClient: ghClient,
		policy: policy.NewGuard(func() (config.Snapshot, error) {
			clone, err := config.Clone(*cfg)
			return config.Snapshot{Revision: clone.ConfigRevision, Config: clone}, err
		}),
	}
}

func (m *Merger) Merge(ctx context.Context, alertID int) error {
	return m.withRecord(ctx, alertID, func(record *model.AlertRecord, cfg config.Config) error { return m.merge(ctx, record, cfg) })
}

// SetRepositoryPolicy binds the shared application guard before starting workers.
func (m *Merger) SetRepositoryPolicy(guard *policy.Guard) {
	if guard != nil {
		m.policy = guard
	}
}

func (m *Merger) withRecord(ctx context.Context, id int, fn func(*model.AlertRecord, config.Config) error) error {
	record, err := m.store.Get(id)
	if err != nil {
		return fmt.Errorf("アラート取得失敗: %w", err)
	}
	return m.policy.WithAllowed(ctx, record.Alert.Owner, record.Alert.Repo, func(snapshot config.Snapshot) error {
		if snapshot.Config.DisableApproval {
			return ErrApprovalDisabled
		}
		current, err := m.store.Get(id)
		if err != nil {
			return fmt.Errorf("操作前アラート確認失敗: %w", err)
		}
		if current.ResolvedAt != nil {
			return fmt.Errorf("解決済みアラートは操作できません (id=%d)", id)
		}
		return fn(current, snapshot.Config)
	})
}

func (m *Merger) merge(ctx context.Context, record *model.AlertRecord, cfg config.Config) error {
	alertID := record.Alert.ID
	client := m.ghClient
	if configurable, ok := client.(github.ConfigClient); ok {
		bound, err := configurable.WithConfig(cfg)
		if err != nil {
			return err
		}
		client = bound
	}

	alert := record.Alert
	slog.Info("マージ処理開始", "alertID", alertID, "pkg", alert.PackageName, "repo", fmt.Sprintf("%s/%s", alert.Owner, alert.Repo), "prNumber", alert.PRNumber)

	// PRNumberが既知ならそれを使う。なければ従来のPR検索にフォールバック（grouped PR以外）
	prNum := alert.PRNumber
	if prNum == 0 {
		slog.Debug("PRNumber未設定、PR検索実行", "alertID", alertID, "pkg", alert.PackageName)
		var err error
		prNum, err = client.FindDependabotPR(ctx, alert.Owner, alert.Repo, alert.PackageName)
		if err != nil {
			return fmt.Errorf("PR検索失敗: %w", err)
		}
	} else {
		slog.Debug("PRNumber既知、FindDependabotPRスキップ", "alertID", alertID, "prNumber", prNum)
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

	// 当該アラートをmergedに更新
	if err := m.store.UpdateState(alertID, model.AlertStateMerged); err != nil {
		return fmt.Errorf("ステート更新失敗: %w", err)
	}

	// PRNumberが設定されている場合、同PRを共有する兄弟アラートも一括でmergedに更新
	siblingCount := 0
	if alert.PRNumber > 0 {
		siblings := m.store.ListByPRNumber(alert.Owner, alert.Repo, alert.PRNumber)
		for _, sib := range siblings {
			if sib.Alert.ID == alertID {
				continue // 当該アラートは既に更新済み
			}
			if err := m.store.UpdateState(sib.Alert.ID, model.AlertStateMerged); err != nil {
				slog.Error("兄弟アラートのステート更新失敗", "alertID", sib.Alert.ID, "error", err)
			} else {
				siblingCount++
			}
		}
	}

	slog.Info("PRマージ完了", "alertID", alertID, "pr", prNum, "repo", repo, "siblingsMerged", siblingCount)
	return nil
}

func (m *Merger) Approve(ctx context.Context, alertID int) error {
	slog.Info("承認処理開始", "alertID", alertID)
	return m.withRecord(ctx, alertID, func(record *model.AlertRecord, cfg config.Config) error {
		if err := m.store.UpdateState(alertID, model.AlertStateApproved); err != nil {
			return fmt.Errorf("承認ステート更新失敗: %w", err)
		}
		return m.merge(ctx, record, cfg)
	})
}

func (m *Merger) Reject(alertID int) error {
	slog.Info("却下処理", "alertID", alertID)
	return m.withRecord(context.Background(), alertID, func(*model.AlertRecord, config.Config) error {
		return m.store.UpdateState(alertID, model.AlertStateRejected)
	})
}
