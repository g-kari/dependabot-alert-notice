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
	"strings"
	"testing"
)

type fakeSource struct {
	release   Release
	archive   []byte
	checksum  string
	downloads int
	err       error
}

func (f *fakeSource) Latest(context.Context) (Release, error) { return f.release, f.err }
func (f *fakeSource) Download(_ context.Context, tag, asset, dir string) error {
	f.downloads++
	if tag != f.release.Tag {
		return fmt.Errorf("wrong tag: %s", tag)
	}
	if err := os.WriteFile(filepath.Join(dir, asset), f.archive, 0600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(f.checksum), 0600)
}

func archiveFixture(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("new executable")
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestCheckUsesSemanticVersionsAndPublishedStableReleases(t *testing.T) {
	for _, tt := range []struct {
		current, tag                     string
		draft, prerelease, want, invalid bool
	}{
		{"v1.9.0", "v1.10.0", false, false, true, false},
		{"1.10.0", "v1.10.0", false, false, false, false},
		{"v2.0.0", "v1.10.0", false, false, false, false},
		{"v1.10.0-preview.1", "v1.10.0", false, false, true, false},
		{"v1.0.0", "v2.0.0", true, false, false, true},
		{"v1.0.0", "v2.0.0", false, true, false, true},
		{"v1.0.0", "v2.0.0-rc.1", false, false, false, true},
		{"dev", "v1.0.0", false, false, false, true},
		{"v1.0.0", "../../evil", false, false, false, true},
		{"v1.0.0", "v01.2.3", false, false, false, true},
	} {
		t.Run(tt.current+"_"+tt.tag, func(t *testing.T) {
			u := Updater{Source: &fakeSource{release: Release{Tag: tt.tag, Draft: tt.draft, Prerelease: tt.prerelease}}, Current: tt.current, OS: "linux", Arch: "amd64"}
			result, err := u.Check(context.Background())
			if (err != nil) != tt.invalid || result.Available != tt.want {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestApplyVerifiesBeforeReplacingAndPreservesOldBinaryOnFailure(t *testing.T) {
	for _, scenario := range []string{"success", "checksum mismatch", "checksum missing", "unsafe archive", "wrong version", "locked", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "dependabot-alert-notice")
			if err := os.WriteFile(target, []byte("old executable"), 0755); err != nil {
				t.Fatal(err)
			}
			asset := "dependabot-alert-notice_1.10.0_linux_amd64.tar.gz"
			name := "dependabot-alert-notice"
			if scenario == "unsafe archive" {
				name = "../dependabot-alert-notice"
			}
			archive := archiveFixture(t, name)
			checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), asset)
			if scenario == "checksum mismatch" {
				checksum = strings.Repeat("0", 64) + "  " + asset
			}
			if scenario == "checksum missing" {
				checksum = ""
			}
			f := &fakeSource{release: Release{Tag: "v1.10.0", Assets: []Asset{{Name: asset}, {Name: "checksums.txt"}}}, archive: archive, checksum: checksum}
			verified := false
			u := Updater{Source: f, Current: "v1.9.0", OS: "linux", Arch: "amd64", Executable: target, Verify: func(_ context.Context, path, tag string) error {
				verified = true
				body, err := os.ReadFile(path)
				if err != nil || string(body) != "new executable" || tag != "v1.10.0" {
					t.Fatalf("candidate=%q tag=%s err=%v", body, tag, err)
				}
				if scenario == "wrong version" {
					return fmt.Errorf("unexpected version")
				}
				return nil
			}}
			if scenario == "locked" {
				if err := os.Mkdir(target+".update-lock", 0700); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			result, err := u.Apply(ctx)
			body, readErr := os.ReadFile(target)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if scenario == "success" {
				if err != nil || !result.Updated || string(body) != "new executable" || !verified {
					t.Fatalf("result=%+v body=%q err=%v", result, body, err)
				}
			} else if err == nil || string(body) != "old executable" {
				t.Fatalf("failure must preserve binary: body=%q err=%v", body, err)
			}
			if (scenario == "checksum mismatch" || scenario == "checksum missing") && verified {
				t.Fatal("unverified candidate executed")
			}
		})
	}
}

func TestApplyDoesNotDownloadWhenCurrentOrAssetsAreMissing(t *testing.T) {
	for _, tag := range []string{"v1.0.0", "v2.0.0"} {
		f := &fakeSource{release: Release{Tag: tag}}
		u := Updater{Source: f, Current: "v1.0.0", OS: "linux", Arch: "amd64", Executable: filepath.Join(t.TempDir(), "binary")}
		_, err := u.Apply(context.Background())
		if (err != nil) != (tag == "v2.0.0") || f.downloads != 0 {
			t.Fatalf("tag=%s downloads=%d err=%v", tag, f.downloads, err)
		}
	}
}

func TestReleaseBinaryNameMatchesPlatformArchiveEntry(t *testing.T) {
	for _, tt := range []struct{ goos, want string }{
		{"linux", "dependabot-alert-notice"},
		{"darwin", "dependabot-alert-notice"},
		{"windows", "dependabot-alert-notice.exe"},
	} {
		if got := releaseBinaryName(tt.goos); got != tt.want {
			t.Fatalf("goos=%s got=%q want=%q", tt.goos, got, tt.want)
		}
	}
}

func TestApplyWindowsUsesExecutableArchiveAssetAndEntry(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dependabot-alert-notice.exe")
	if err := os.WriteFile(target, []byte("old executable"), 0755); err != nil {
		t.Fatal(err)
	}
	asset := "dependabot-alert-notice_1.10.0_windows_amd64.tar.gz"
	archive := archiveFixture(t, "dependabot-alert-notice.exe")
	checksum := fmt.Sprintf("%x  %s\n", sha256.Sum256(archive), asset)
	f := &fakeSource{release: Release{Tag: "v1.10.0", Assets: []Asset{{Name: asset}, {Name: "checksums.txt"}}}, archive: archive, checksum: checksum}
	u := Updater{Source: f, Current: "v1.9.0", OS: "windows", Arch: "amd64", Executable: target, Verify: func(_ context.Context, path, tag string) error {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "new executable" || tag != "v1.10.0" {
			t.Fatalf("candidate=%q tag=%s err=%v", body, tag, err)
		}
		return nil
	}}
	result, err := u.Apply(context.Background())
	if err != nil || !result.Updated {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "new executable" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}
