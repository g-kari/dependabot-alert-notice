//go:build windows

package updater

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestInstallBinaryRejectsInvalidCandidateBeforeChangingTargetOrBackup(t *testing.T) {
	for _, scenario := range []string{"directory", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "dependabot-alert-notice.exe")
			backup := target + ".old"
			for path, body := range map[string]string{target: "old executable", backup: "previous backup"} {
				if err := os.WriteFile(path, []byte(body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			candidate := filepath.Join(dir, "candidate")
			if scenario == "directory" {
				if err := os.Mkdir(candidate, 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := installBinary(candidate, target)
			if err == nil || !strings.Contains(err.Error(), "更新候補") {
				t.Fatalf("scenario=%s: invalid candidate must be rejected: err=%v", scenario, err)
			}
			if scenario == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing candidate error must be preserved: err=%v", err)
			}
			for path, want := range map[string]string{target: "old executable", backup: "previous backup"} {
				body, err := os.ReadFile(path)
				if err != nil || string(body) != want {
					t.Fatalf("scenario=%s path=%s: body=%q want=%q err=%v", scenario, path, body, want, err)
				}
			}
			if scenario == "directory" {
				info, err := os.Stat(candidate)
				if err != nil || !info.IsDir() {
					t.Fatalf("directory candidate must remain in place: info=%v err=%v", info, err)
				}
			}
		})
	}
}

func TestInstallBinaryRestoresTargetWhenReplacementFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dependabot-alert-notice.exe")
	if err := os.WriteFile(target, []byte("old executable"), 0755); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(dir, "candidate")
	if err := os.WriteFile(candidate, []byte("new executable"), 0755); err != nil {
		t.Fatal(err)
	}
	// Denying FILE_SHARE_DELETE allows validation and reads, but guarantees that
	// renaming this regular file fails after the target has been moved aside.
	path, err := syscall.UTF16PtrFromString(candidate)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(path, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.CloseHandle(handle); err != nil {
			t.Errorf("close candidate handle: %v", err)
		}
	})
	err = installBinary(candidate, target)
	const errorSharingViolation syscall.Errno = 32 // ERROR_SHARING_VIOLATION
	var renameErr *os.LinkError
	if !errors.As(err, &renameErr) || renameErr.Old != candidate || renameErr.New != target || !errors.Is(err, errorSharingViolation) {
		t.Fatalf("candidate rename must fail with a sharing violation: err=%v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "old executable" {
		t.Fatalf("failure must restore binary: body=%q err=%v", body, err)
	}
	if _, err := os.Stat(target + ".old"); !os.IsNotExist(err) {
		t.Fatalf("rollback must restore the backup to the target: err=%v", err)
	}
	body, err = os.ReadFile(candidate)
	if err != nil || string(body) != "new executable" {
		t.Fatalf("failed candidate must remain in place: body=%q err=%v", body, err)
	}
}

func TestInstallBinaryReportsReplacementAndRestoreFailuresAndPreservesBackup(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dependabot-alert-notice.exe")
	backup := target + ".old"
	candidate := filepath.Join(dir, "candidate")
	for path, body := range map[string]string{target: "old executable", candidate: "new executable"} {
		if err := os.WriteFile(path, []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	replacementErr := errors.New("replacement failed")
	restoreErr := errors.New("restore failed")
	renameCalls := 0
	// Inject only the failures that would otherwise require racing a filesystem
	// change between the two renames. The initial backup move uses the real OS.
	err := installBinaryWithRename(candidate, target, func(old, new string) error {
		renameCalls++
		switch renameCalls {
		case 1:
			if old != target || new != backup {
				t.Fatalf("backup rename: old=%s new=%s", old, new)
			}
			return os.Rename(old, new)
		case 2:
			if old != candidate || new != target {
				t.Fatalf("replacement rename: old=%s new=%s", old, new)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("target must have been moved before replacement: err=%v", err)
			}
			return &os.LinkError{Op: "rename", Old: old, New: new, Err: replacementErr}
		case 3:
			if old != backup || new != target {
				t.Fatalf("restore rename: old=%s new=%s", old, new)
			}
			return &os.LinkError{Op: "rename", Old: old, New: new, Err: restoreErr}
		default:
			t.Fatalf("unexpected rename call %d: old=%s new=%s", renameCalls, old, new)
			return nil
		}
	})
	if renameCalls != 3 || !errors.Is(err, replacementErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("both failures must be preserved: renameCalls=%d err=%v", renameCalls, err)
	}
	if !strings.Contains(err.Error(), backup) {
		t.Fatalf("restore failure must identify the retained backup: err=%v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("failed restore must not claim the target was restored: err=%v", err)
	}
	for path, want := range map[string]string{backup: "old executable", candidate: "new executable"} {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != want {
			t.Fatalf("path=%s: body=%q want=%q err=%v", path, body, want, err)
		}
	}
}
