package ghcommand

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecutableIsPinnedFromFrozenPathWithoutExecution(t *testing.T) {
	dir := t.TempDir()
	name := "gh-fixture"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("synthetic file, never executable content"), 0700); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=" + dir, "APP_TOKEN=fixture"}
	c, err := NewWithEnvironment(name, Settings{Mode: "token_env", TokenEnv: "APP_TOKEN"}, env)
	if err != nil {
		t.Fatal(err)
	}
	env[0] = "PATH=" + t.TempDir()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.execute = func(_ context.Context, got string, _ []string, _ []string) ([]byte, []byte, error) {
		if got != path {
			t.Fatalf("unpinned executable %q", got)
		}
		return nil, nil, nil
	}
	if _, err := c.Output(context.Background(), "api", "rate_limit"); err != nil {
		t.Fatal(err)
	}
}

func TestRelativeExecutableIsPinnedToOriginalDirectoryWithoutExecution(t *testing.T) {
	input := filepath.Join("fixture-bin", "gh")
	want, err := filepath.Abs(input)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewWithEnvironment(input, Settings{Mode: "token_env", TokenEnv: "APP_TOKEN"}, []string{"APP_TOKEN=fixture"})
	if err != nil {
		t.Fatal(err)
	}
	c.execute = func(_ context.Context, got string, _ []string, _ []string) ([]byte, []byte, error) {
		if got != want {
			t.Fatalf("relative path not pinned: %q", got)
		}
		return nil, nil, nil
	}
	if _, err := c.Output(context.Background(), "api", "rate_limit"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithEnvironment("missing-fixture", Settings{Mode: "token_env", TokenEnv: "APP_TOKEN"}, []string{"APP_TOKEN=fixture", "PATH=."}); err == nil {
		t.Fatal("implicit cwd PATH entry was accepted")
	}
}
