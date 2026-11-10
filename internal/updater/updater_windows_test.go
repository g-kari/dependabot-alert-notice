//go:build windows

package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const updaterVersionHelperMarker = "DEVSECOPS_UPDATER_TEST_VERSION_MARKER"

func TestMain(m *testing.M) {
	// The staged test executable acts only as an owned --version fixture.
	// Do not run the test suite again in the child process.
	if marker := os.Getenv(updaterVersionHelperMarker); marker != "" {
		if len(os.Args) != 2 || os.Args[1] != "--version" {
			os.Exit(2)
		}
		if err := os.WriteFile(marker, []byte(os.Args[0]), 0600); err != nil {
			os.Exit(3)
		}
		if _, err := fmt.Fprintln(os.Stdout, "dependabot-alert-notice 1.10.0"); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestApplyWindowsRunsDefaultVersionVerificationBeforeReplacing(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if len(binary) == 0 || len(binary) > maxBinarySize {
		t.Fatalf("fixture binary size=%d is outside the archive limit", len(binary))
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "dependabot-alert-notice.exe", Mode: 0755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buf.Bytes()
	for _, tt := range []struct {
		name, tag string
		updated   bool
	}{
		{name: "matching version", tag: "v1.10.0", updated: true},
		{name: "wrong version", tag: "v1.11.0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "install directory with spaces")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "dependabot-alert-notice.exe")
			old := []byte("old executable")
			if err := os.WriteFile(target, old, 0755); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(dir, "version-helper-ran")
			t.Setenv(updaterVersionHelperMarker, marker)
			t.Setenv("PATHEXT", ".COM;.EXE;.BAT;.CMD")
			asset := "dependabot-alert-notice_" + strings.TrimPrefix(tt.tag, "v") + "_windows_" + runtime.GOARCH + ".tar.gz"
			checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), asset)
			source := &fakeSource{release: Release{Tag: tt.tag, Assets: []Asset{{Name: asset}, {Name: "checksums.txt"}}}, archive: archive, checksum: checksum}
			// Leave Verify nil: the production verifier must launch candidate.exe.
			u := Updater{Source: source, Current: "v1.9.0", OS: "windows", Arch: runtime.GOARCH, Executable: target}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result, err := u.Apply(ctx)
			if result.Updated != tt.updated || (err == nil) != tt.updated {
				t.Fatalf("tag=%s result=%+v err=%v", tt.tag, result, err)
			}
			if !tt.updated && !strings.Contains(err.Error(), "候補バージョンがReleaseタグと一致しません") {
				t.Fatalf("tag=%s: expected the default verifier to reject the version: err=%v", tt.tag, err)
			}
			ran, readErr := os.ReadFile(marker)
			if readErr != nil || filepath.Base(string(ran)) != "candidate.exe" || filepath.Dir(filepath.Dir(string(ran))) != dir {
				t.Fatalf("staged candidate.exe must run --version: path=%q err=%v", ran, readErr)
			}
			want := old
			if tt.updated {
				want = binary
			}
			body, readErr := os.ReadFile(target)
			if readErr != nil || !bytes.Equal(body, want) {
				t.Fatalf("tag=%s: target must match expected executable after verification: err=%v", tt.tag, readErr)
			}
			if _, err := os.Stat(target + ".old"); !os.IsNotExist(err) {
				t.Fatalf("tag=%s: unexpected backup after apply: err=%v", tt.tag, err)
			}
		})
	}
}
