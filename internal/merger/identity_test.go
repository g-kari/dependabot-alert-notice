package merger

import (
	"context"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
	"github.com/g-kari/dependabot-alert-notice/internal/github"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type mergeIdentityRunner struct {
	calls [][]string
	fail  bool
}

func (r *mergeIdentityRunner) Output(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	if r.fail {
		return nil, ghcommand.ErrIdentity
	}
	return nil, nil
}

type mergeIdentityClient struct {
	runner   *mergeIdentityRunner
	snapshot *config.Config
}

func (c *mergeIdentityClient) FetchAlerts(context.Context, config.Target) ([]model.Alert, error) {
	return nil, nil
}
func (c *mergeIdentityClient) FindDependabotPR(ctx context.Context, owner, repo, pkg string) (int, error) {
	_, err := c.runner.Output(ctx, "pr", "list", "--repo", owner+"/"+repo)
	return 7, err
}
func (c *mergeIdentityClient) WithConfig(cfg config.Config) (github.Client, error) {
	*c.snapshot = cfg
	return c, nil
}
func (c *mergeIdentityClient) GitHubRunner() (ghcommand.Runner, error) { return c.runner, nil }

func TestMergeSharesSnapshotAuthenticationWithPRLookup(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	runner := &mergeIdentityRunner{}
	var snapshot config.Config
	client := &mergeIdentityClient{runner: runner, snapshot: &snapshot}
	cfg := &config.Config{GhPath: "old-must-not-execute", Targets: []config.Target{{Owner: "org"}}}
	m := New(cfg, s, client)
	cfg.GhPath = "current-must-not-execute"
	cfg.GitHubAuth = ghcommand.Settings{Mode: "inherited"}
	record := saveRecordWithPR(s, 1, "pkg", "org", "repo", 0)
	if err := m.Merge(context.Background(), record.Alert.ID); err != nil {
		t.Fatal(err)
	}
	if snapshot.GhPath != cfg.GhPath || snapshot.GitHubAuth != cfg.GitHubAuth {
		t.Fatal("operation did not use current policy snapshot")
	}
	if len(runner.calls) != 2 || runner.calls[0][1] != "list" || runner.calls[1][1] != "merge" {
		t.Fatalf("lookup and merge did not share context: %v", runner.calls)
	}
}

func TestMergeIdentityFailureDoesNotMarkMerged(t *testing.T) {
	s := store.New()
	t.Cleanup(func() { _ = s.Close() })
	runner := &mergeIdentityRunner{fail: true}
	var snapshot config.Config
	client := &mergeIdentityClient{runner: runner, snapshot: &snapshot}
	cfg := &config.Config{GhPath: "must-not-execute", Targets: []config.Target{{Owner: "org"}}}
	m := New(cfg, s, client)
	record := saveRecordWithPR(s, 2, "pkg", "org", "repo", 7)
	if err := m.Merge(context.Background(), record.Alert.ID); err == nil {
		t.Fatal("identity failure was ignored")
	}
	current, err := s.Get(record.Alert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.State == model.AlertStateMerged {
		t.Fatal("failed operation marked merged")
	}
}
