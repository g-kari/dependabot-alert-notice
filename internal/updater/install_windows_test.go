//go:build windows

package updater

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallBinaryReplacesTargetAndClearsBackup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dependabot-alert-notice.exe")
	if err := os.WriteFile(target, []byte("old executable"), 0755); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(dir, "candidate")
	if err := os.WriteFile(candidate, []byte("new executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := installBinary(candidate, target); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "new executable" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if _, err := os.Stat(target + ".old"); !os.IsNotExist(err) {
		t.Fatalf("backup still present: err=%v", err)
	}
}

func TestInstallBinaryRestoresTargetWhenReplacementFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dependabot-alert-notice.exe")
	if err := os.WriteFile(target, []byte("old executable"), 0755); err != nil {
		t.Fatal(err)
	}
	// A directory cannot be renamed over the target, so the replacement fails
	// after the current binary has been moved aside.
	candidate := filepath.Join(dir, "candidate")
	if err := os.Mkdir(candidate, 0700); err != nil {
		t.Fatal(err)
	}
	if err := installBinary(candidate, target); err == nil {
		t.Fatal("directory candidate must not replace the executable")
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "old executable" {
		t.Fatalf("failure must restore binary: body=%q err=%v", body, err)
	}
}
