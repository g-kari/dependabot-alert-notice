package github

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
)

type recordingIdentityRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recordingIdentityRunner) Output(_ context.Context, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string(nil), args...))
	if args[0] == "pr" {
		return []byte(`[{"number":7,"title":"Bump pkg from 1 to 2"}]`), nil
	}
	if args[0] == "repo" {
		if args[1] == "list" {
			return []byte(`[]`), nil
		}
		return []byte("main"), nil
	}
	if args[1] == "rate_limit" {
		return []byte("5000\t2000000000"), nil
	}
	if args[1] == "graphql" {
		return []byte(`{"data":{"repository":{"vulnerabilityAlerts":{"nodes":[]}}}}`), nil
	}
	return []byte(`[]`), nil
}

func TestAllGitHubReadsUseOneInjectedRunner(t *testing.T) {
	runner := &recordingIdentityRunner{}
	c := &ghClient{cfg: &config.Config{GhPath: "must-not-execute"}, runner: runner}
	ctx := context.Background()
	c.fetchContributors(ctx, "org", "repo")
	if _, err := c.checkRateLimit(ctx); err != nil {
		t.Fatal(err)
	}
	c.fetchHomepage(ctx, "org", "repo")
	c.fetchDefaultBranch(ctx, "org", "repo")
	c.isRepoArchived(ctx, "org", "repo")
	if _, err := c.fetchOrgAlerts(ctx, "org", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.fetchRepoList(ctx, "org"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.fetchRepoAlerts(ctx, "org", "repo"); err != nil {
		t.Fatal(err)
	}
	c.fetchGraphQLUpdates(ctx, "org", "repo")
	if n, err := c.FindDependabotPR(ctx, "org", "repo", "pkg"); err != nil || n != 7 {
		t.Fatalf("PR=%d err=%v", n, err)
	}
	if len(runner.calls) != 10 {
		t.Fatalf("expected ten common-runner call sites, got %d", len(runner.calls))
	}
	bound, err := c.GitHubRunner()
	if err != nil || bound != runner {
		t.Fatal("lookup runner was not shared")
	}
}

func TestGraphQLUpdatesUsesSharedFixedReadBuilder(t *testing.T) {
	runner := &recordingIdentityRunner{}
	c := &ghClient{cfg: &config.Config{GhPath: "must-not-execute"}, runner: runner}
	c.fetchGraphQLUpdates(context.Background(), "org", "repo")
	query, err := ghcommand.DependabotUpdatesQuery("org", "repo")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"api", "graphql", "-f", "query=" + query}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("commands=%q; want fixed read command %q", runner.calls, want)
	}
}

func TestGraphQLUpdatesRejectsInvalidRepositoryWithoutCallingRunner(t *testing.T) {
	for _, tc := range []struct{ owner, repo string }{
		{`org") { name } } mutation { fixture } #`, "repo"},
		{"org", `repo") { name } } mutation { fixture } #`},
		{"org", ".."}, {"other.invalid/org", "repo"},
	} {
		runner := &recordingIdentityRunner{}
		c := &ghClient{cfg: &config.Config{GhPath: "must-not-execute"}, runner: runner}
		info := c.fetchGraphQLUpdates(context.Background(), tc.owner, tc.repo)
		if len(runner.calls) != 0 || len(info.Errors) != 0 || len(info.PRNumbers) != 0 {
			t.Fatalf("owner=%q repo=%q: commands=%q info=%+v; want no command and empty optional metadata", tc.owner, tc.repo, runner.calls, info)
		}
	}
}

func TestWithConfigPreservesAuthSelectionAndRejectsMissingExplicitSource(t *testing.T) {
	c := New(&config.Config{GhPath: "unused"}).(ConfigClient)
	settings := ghcommand.Settings{Mode: "token_env", TokenEnv: "MISSING_SYNTHETIC_GITHUB_SOURCE", ExpectedLogin: "alice"}
	if _, err := c.WithConfig(config.Config{GhPath: "must-not-execute", GitHubAuth: settings}); err == nil {
		t.Fatal("missing explicit source silently fell back")
	}
	bound, err := c.WithConfig(config.Config{GhPath: "selected", GitHubAuth: ghcommand.Settings{Mode: "inherited"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bound.(*ghClient).cfg.GitHubAuth, ghcommand.Settings{Mode: "inherited"}) {
		t.Fatal("lost auth mode")
	}
}
