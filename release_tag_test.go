package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestExplicitReleaseTagCreationIsBoundedAndNonOverwriting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("The release tag step runs in Bash on ubuntu-latest")
	}
	body, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct{ Name, If, Run string }
		}
	}
	if err := yaml.Unmarshal(body, &workflow); err != nil {
		t.Fatal(err)
	}
	steps := workflow.Jobs["prepare-tag"].Steps
	if len(steps) != 1 || !strings.Contains(steps[0].If, "github.event_name == 'workflow_dispatch'") || !strings.Contains(steps[0].If, "inputs.create_tag") {
		t.Fatal("tag creation must be explicitly enabled by manual dispatch")
	}
	script := steps[0].Run
	if strings.Contains(script, "${{") || strings.Contains(script, "--force") || strings.Contains(script, "--method PATCH") || strings.Contains(script, "--method DELETE") {
		t.Fatal("tag script must not interpolate inputs or overwrite/delete references")
	}
	for _, tt := range []struct {
		name, tag string
		ok        bool
		writes    int
	}{
		{"new", "v0.4.0", true, 1},
		{"existing-same", "v0.4.0", true, 0},
		{"existing-different", "v0.4.0", false, 0},
		{"main-changed", "v0.4.0", false, 0},
		{"main-error", "v0.4.0", false, 0},
		{"bad-main", "v0.4.0", false, 0},
		{"wrong-dispatch", "v0.4.0", false, 0},
		{"wrong-ref", "v0.4.0", false, 0},
		{"tag-read-error", "v0.4.0", false, 0},
		{"lost-ack", "v0.4.0", true, 1},
		{"write-failed", "v0.4.0", false, 1},
		{"invalid", "v0.4.0-rc.1", false, 0},
		{"invalid", "v01.4.0", false, 0},
		{"invalid", "v0.4.0; echo unsafe", false, 0},
	} {
		t.Run(tt.name+"/"+tt.tag, func(t *testing.T) {
			dir := t.TempDir()
			mock := `#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$MOCK_ROOT/calls"
if [ "$2" = --method ]; then
  test "$3" = POST
  printf 'write\n' >> "$MOCK_ROOT/writes"
  if [ "$MOCK_CASE" = write-failed ]; then exit 1; fi
  touch "$MOCK_ROOT/tag"
  if [ "$MOCK_CASE" = lost-ack ]; then exit 1; fi
  exit 0
fi
case "$2" in
  */git/ref/heads/main)
    n=0; if [ -f "$MOCK_ROOT/main-count" ]; then n=$(cat "$MOCK_ROOT/main-count"); fi
    n=$((n+1)); echo "$n" > "$MOCK_ROOT/main-count"
    if [ "$MOCK_CASE" = main-error ]; then exit 1; fi
    if [ "$MOCK_CASE" = bad-main ]; then echo malformed; exit 0; fi
    if [ "$MOCK_CASE" = main-changed ] && [ "$n" -gt 1 ]; then printf '%040d\n' 2; else printf '%040d\n' 1; fi
    ;;
  */git/matching-refs/tags/v0.4.0)
    if [ "$MOCK_CASE" = tag-read-error ]; then exit 1; fi
    if [ "$MOCK_CASE" = existing-different ]; then printf '%040d\n' 2
    elif [ "$MOCK_CASE" = existing-same ] || [ -f "$MOCK_ROOT/tag" ]; then printf '%040d\n' 1; fi
    ;;
  *) exit 9 ;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(mock), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-c", script)
			for _, entry := range os.Environ() {
				key, _, _ := strings.Cut(entry, "=")
				switch key {
				case "PATH", "GH_TOKEN", "GITHUB_TOKEN", "GITHUB_REPOSITORY", "RELEASE_TAG", "MOCK_ROOT", "MOCK_CASE", "DISPATCH_REF", "DISPATCH_SHA":
					continue
				}
				cmd.Env = append(cmd.Env, entry)
			}
			cmd.Env = append(cmd.Env, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "GITHUB_REPOSITORY=example/synthetic", "RELEASE_TAG="+tt.tag, "MOCK_ROOT="+dir, "MOCK_CASE="+tt.name)
			ref, sha := "refs/heads/main", strings.Repeat("0", 39)+"1"
			if tt.name == "wrong-dispatch" {
				sha = strings.Repeat("0", 39) + "2"
			}
			if tt.name == "wrong-ref" {
				ref = "refs/heads/other"
			}
			cmd.Env = append(cmd.Env, "DISPATCH_REF="+ref, "DISPATCH_SHA="+sha)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tt.ok {
				t.Fatalf("success=%t want=%t: %v\n%s", err == nil, tt.ok, err, output)
			}
			writes, readErr := os.ReadFile(filepath.Join(dir, "writes"))
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if got := strings.Count(string(writes), "write\n"); got != tt.writes {
				t.Fatalf("tag writes=%d want=%d", got, tt.writes)
			}
			if tt.name == "invalid" {
				if _, err := os.Stat(filepath.Join(dir, "calls")); !os.IsNotExist(err) {
					t.Fatal("invalid tag must be rejected before any GitHub call")
				}
			}
		})
	}
}
