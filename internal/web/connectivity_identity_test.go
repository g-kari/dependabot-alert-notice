package web

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
)

type connectivityIdentityRunner struct {
	mu    sync.Mutex
	calls int
	fail  bool
}

func (r *connectivityIdentityRunner) Description() string { return "token_env (synthetic)" }
func (r *connectivityIdentityRunner) Identity(context.Context) (string, error) {
	if r.fail {
		return "", ghcommand.ErrIdentity
	}
	return "alice", nil
}
func (r *connectivityIdentityRunner) Output(_ context.Context, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail {
		return nil, ghcommand.ErrIdentity
	}
	if args[0] == "repo" {
		return []byte("repo\n"), nil
	}
	return []byte("2"), nil
}

func TestConnectivityReusesSelectedAuthenticationForEveryProbe(t *testing.T) {
	runner := &connectivityIdentityRunner{}
	gh := connectivityGitHub{runner: runner}
	ctx := context.Background()
	status := testGH(ctx, gh)
	if !status.OK || !strings.Contains(status.Message, "token_env") {
		t.Fatalf("status=%+v", status)
	}
	if !testRepoTarget(ctx, gh, "org", "repo").OK || !testOrgTarget(ctx, gh, "org").OK || !testUserRepoTarget(ctx, gh, "org").OK {
		t.Fatal("probe failed")
	}
	if runner.calls != 4 {
		t.Fatalf("shared runner calls=%d", runner.calls)
	}
	runner.fail = true
	if testGH(ctx, gh).OK || testRepoTarget(ctx, gh, "org", "repo").OK || testUserRepoTarget(ctx, gh, "org").OK {
		t.Fatal("identity failure reported as success")
	}
}

func TestTUIAuthReferenceChangeRequiresRestart(t *testing.T) {
	a := config.Config{GitHubAuth: ghcommand.Settings{Mode: "inherited"}}
	b := a
	b.GitHubAuth = ghcommand.Settings{Mode: "token_env", TokenEnv: "FIXTURE_TOKEN"}
	if !restartForSettings(a, b) {
		t.Fatal("auth selection change not recognized")
	}
}
