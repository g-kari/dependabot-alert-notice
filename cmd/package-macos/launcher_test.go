package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStarterUsesPersistentDataWithoutOverwritingConfiguration(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("bash launcher requires a native Mac/Linux runner; not verified on Windows")
	}
	root := filepath.Join(t.TempDir(), "Mac distribution with spaces")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	starter, err := os.ReadFile("../../packaging/macos/Start.command")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Start.command"), starter, 0755); err != nil {
		t.Fatal(err)
	}
	original := []byte("fixture config; must survive updates\n")
	if err := os.WriteFile(filepath.Join(root, "config.yaml.example"), original, 0644); err != nil {
		t.Fatal(err)
	}
	fake := []byte("#!/bin/bash\nset -eu\nif [ \"${3:-}\" = --update ]; then printf 'checked\\n' >> update-checked; exit 1; fi\nif [ \"${3:-}\" = --web-url ]; then printf '%s\\n' \"$FIXTURE_WEB_URL\"; exit 0; fi\nprintf '%s\\n' \"$PWD\" > app-ran\nprintf '%s\\n' \"$@\" > app-args\nsleep 1\n")
	if err := os.WriteFile(filepath.Join(root, "dependabot-alert-notice"), fake, 0755); err != nil {
		t.Fatal(err)
	}
	var checks atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checks.Add(1)
		_, _ = io.WriteString(w, "fixture settings")
	}))
	defer server.Close()
	home := t.TempDir()
	data := filepath.Join(home, "Library", "Application Support", "security-notice")
	for run := 0; run < 2; run++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, "Start.command"), "--update-interval", "1h")
		cmd.Dir = t.TempDir() // Finder's cwd is not the distribution directory.
		cmd.Env = append(os.Environ(), "HOME="+home, "SECURITY_NOTICE_DATA_DIR="+data, "SECURITY_NOTICE_NO_BROWSER=1", "FIXTURE_WEB_URL="+server.URL)
		if run == 1 {
			cmd.Env = append(cmd.Env, "SECURITY_NOTICE_AUTO_UPDATE=0")
		}
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("starter run %d: %v\n%s", run, err, out)
		}
		checked, err := os.ReadFile(filepath.Join(data, "update-checked"))
		if err != nil || string(checked) != "checked\n" {
			t.Fatalf("update must run once, survive failure and honor opt-out: %q err=%v", checked, err)
		}
		marker, err := os.ReadFile(filepath.Join(data, "app-ran"))
		if err != nil || strings.TrimSpace(string(marker)) != data {
			t.Fatalf("wrong data cwd: %q err=%v", marker, err)
		}
		args, err := os.ReadFile(filepath.Join(data, "app-args"))
		if err != nil || string(args) != "--config\n"+filepath.Join(data, "config.yaml")+"\n--update-interval\n1h\n" {
			t.Fatalf("launcher did not forward update interval: %q err=%v", args, err)
		}
		stored, err := os.ReadFile(filepath.Join(data, "config.yaml"))
		if err != nil || string(stored) != string(original) {
			t.Fatalf("configuration overwritten on run %d: %q err=%v", run, stored, err)
		}
		info, err := os.Stat(filepath.Join(data, "config.yaml"))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private config permissions: %v err=%v", info, err)
		}
		if err := os.WriteFile(filepath.Join(root, "config.yaml.example"), []byte("new version; do not replace user settings"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if checks.Load() < 2 {
		t.Fatal("starter did not await local fixture readiness")
	}
}
