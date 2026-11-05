package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/updater"
)

func TestRestartRunsOnlyAfterCleanupAndPreservesArgumentsAndEnvironment(t *testing.T) {
	var order []string
	args := []string{"old-path", "--config", "path with spaces/config.yaml", "--update-interval", "1h"}
	env := []string{"FIXTURE=value"}
	err := runAndRestart(func() string {
		defer func() { order = append(order, "closed") }()
		return "/new/binary"
	}, func(path string, gotArgs, gotEnv []string) error {
		order = append(order, "restart")
		if path != "/new/binary" || !reflect.DeepEqual(gotArgs, args) || !reflect.DeepEqual(gotEnv, env) {
			t.Fatalf("restart changed invocation")
		}
		return nil
	}, args, env)
	if err != nil || !reflect.DeepEqual(order, []string{"closed", "restart"}) {
		t.Fatalf("order=%v err=%v", order, err)
	}
	if err := runAndRestart(func() string { return "" }, func(string, []string, []string) error { t.Fatal("normal shutdown restarted"); return nil }, args, env); err != nil {
		t.Fatal(err)
	}
}

type updateSourceFixture struct{ tag string }

func (f updateSourceFixture) Latest(context.Context) (updater.Release, error) {
	return updater.Release{Tag: f.tag}, nil
}
func (f updateSourceFixture) Download(context.Context, string, string, string) error {
	panic("check must not download")
}

func TestReleaseUpdateCommandReportsCheckWithoutApplying(t *testing.T) {
	for _, tt := range []struct{ tag, want string }{
		{"v1.2.0", "更新があります"},
		{"v1.0.0", "現在の版を維持"},
		{"v0.9.0", "現在の版を維持"},
	} {
		var out bytes.Buffer
		u := updater.Updater{Source: updateSourceFixture{tag: tt.tag}, Current: "v1.0.0"}
		if err := runReleaseUpdate(context.Background(), u, false, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), tt.want) {
			t.Fatalf("output=%s", out.String())
		}
	}
}
