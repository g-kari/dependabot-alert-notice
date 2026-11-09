package updater

import (
	"context"
	"fmt"
	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
	"reflect"
	"testing"
)

func TestGitHubSourcePinsRepositoryTagAndAssets(t *testing.T) {
	var calls [][]string
	s := GitHubSource{Repository: "g-kari/dependabot-alert-notice", Run: func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		return []byte(`{"tag_name":"v1.2.3","assets":[{"name":"checksums.txt"}]}`), nil
	}}
	r, err := s.Latest(context.Background())
	if err != nil || r.Tag != "v1.2.3" || len(r.Assets) != 1 {
		t.Fatalf("release=%+v err=%v", r, err)
	}
	if err := s.Download(context.Background(), r.Tag, "archive.tar.gz", "destination with spaces"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"api", "repos/g-kari/dependabot-alert-notice/releases/latest"},
		{"release", "download", "v1.2.3", "--repo", "g-kari/dependabot-alert-notice", "--pattern", "archive.tar.gz", "--pattern", "checksums.txt", "--dir", "destination with spaces"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v", calls)
	}
}

type recordingRunner struct{ calls [][]string }

func (r *recordingRunner) Output(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	return []byte(`{"tag_name":"v1.2.3"}`), nil
}

func TestGitHubSourceSharesFrozenRunnerAcrossLookupAndDownload(t *testing.T) {
	runner := &recordingRunner{}
	s := GitHubSource{Repository: "org/repo", Path: "must-not-execute", Auth: ghcommand.Settings{Mode: "token_env", TokenEnv: "MISSING_SOURCE"}, Runner: runner}
	if _, err := s.Latest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Download(context.Background(), "v1.2.3", "archive.tar.gz", "destination"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[0][0] != "api" || runner.calls[1][0] != "release" {
		t.Fatalf("calls=%v", runner.calls)
	}
	s.Runner = nil
	if _, err := s.Latest(context.Background()); err == nil {
		t.Fatal("explicit updater source fell back to console")
	}
}

func TestGitHubSourceRejectsInvalidRepositoryAndCommandFailures(t *testing.T) {
	for _, repo := range []string{"../bad", "owner/repo/extra", "https://github.com/owner/repo", "owner/repo"} {
		called := false
		s := GitHubSource{Repository: repo, Run: func(context.Context, ...string) ([]byte, error) {
			called = true
			return nil, fmt.Errorf("not authenticated")
		}}
		if _, err := s.Latest(context.Background()); err == nil {
			t.Fatal("expected error")
		}
		if called != (repo == "owner/repo") {
			t.Fatalf("unexpected command for %q", repo)
		}
	}
}
