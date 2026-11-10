// Package updater installs newer stable tag releases without touching user data.
package updater

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Asset identifies a release attachment.
type Asset struct {
	Name string `json:"name"`
}

// Release contains the immutable tag and release eligibility information.
type Release struct {
	Tag        string  `json:"tag_name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

// Source isolates release metadata and downloads from update logic.
type Source interface {
	Latest(context.Context) (Release, error)
	Download(context.Context, string, string, string) error
}

// Result describes the checked release and whether it was installed.
type Result struct {
	Current, Latest    string
	Available, Updated bool
	release            Release
}

// Updater validates a tag release before replacing Executable on Mac/Linux.
type Updater struct {
	Source                        Source
	Current, OS, Arch, Executable string
	Verify                        func(context.Context, string, string) error
}

var versionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)

func parseVersion(version string) ([]string, error) {
	parts := versionPattern.FindStringSubmatch(version)
	if parts == nil {
		return nil, fmt.Errorf("更新にはSemVerのリリース版が必要です: %q", version)
	}
	for _, id := range strings.Split(parts[4], ".") {
		if len(id) > 1 && id[0] == '0' && strings.Trim(id, "0123456789") == "" {
			return nil, fmt.Errorf("不正なプレリリース番号: %q", version)
		}
	}
	return parts[1:5], nil
}

// releaseBinaryName returns the release archive entry name for the target platform.
func releaseBinaryName(goos string) string {
	if goos == "windows" {
		return "dependabot-alert-notice.exe"
	}
	return "dependabot-alert-notice"
}

// Check compares semantic versions and never recommends a downgrade.
func (u Updater) Check(ctx context.Context) (Result, error) {
	result := Result{Current: u.Current}
	current, err := parseVersion(u.Current)
	if err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("更新確認中止: %w", err)
	}
	if u.Source == nil {
		return result, fmt.Errorf("更新元が未設定です")
	}
	release, err := u.Source.Latest(ctx)
	if err != nil {
		return result, fmt.Errorf("更新確認: %w", err)
	}
	latest, err := parseVersion(release.Tag)
	if err != nil {
		return result, err
	}
	if release.Draft || release.Prerelease || latest[3] != "" {
		return result, fmt.Errorf("更新元は公開済みの安定版Releaseである必要があります")
	}
	result.Latest, result.release = release.Tag, release
	for i := 0; i < 3; i++ {
		if current[i] == latest[i] {
			continue
		}
		result.Available = len(latest[i]) > len(current[i]) || (len(latest[i]) == len(current[i]) && latest[i] > current[i])
		return result, nil
	}
	result.Available = current[3] != ""
	return result, nil
}

// Apply downloads, verifies and atomically installs a newer release. Restart to use it.
func (u Updater) Apply(ctx context.Context) (Result, error) {
	result, err := u.Check(ctx)
	if err != nil || !result.Available {
		return result, err
	}
	if u.OS != "linux" && u.OS != "darwin" && u.OS != "windows" {
		return result, fmt.Errorf("自動置換はMac/Linux/Windows対応です。このOSはReleaseから手動更新してください")
	}
	if u.Arch != "amd64" && u.Arch != "arm64" {
		return result, fmt.Errorf("未対応CPU: %s", u.Arch)
	}
	asset := "dependabot-alert-notice_" + strings.TrimPrefix(result.Latest, "v") + "_" + u.OS + "_" + u.Arch + ".tar.gz"
	found := map[string]bool{}
	for _, a := range result.release.Assets {
		found[a.Name] = true
	}
	if !found[asset] || !found["checksums.txt"] {
		return result, fmt.Errorf("Releaseに%sとchecksums.txtが必要です", asset)
	}
	target, err := filepath.EvalSymlinks(u.Executable)
	if err != nil {
		return result, fmt.Errorf("更新対象取得: %w", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		return result, fmt.Errorf("更新対象確認: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("更新対象が通常ファイルではありません")
	}
	lock := target + ".update-lock"
	if err := os.Mkdir(lock, 0700); err != nil {
		return result, fmt.Errorf("更新ロック取得（別の更新処理または書込権限を確認）: %w", err)
	}
	defer removeTemporary(lock)
	// Staging beside the executable keeps the final rename on one filesystem.
	dir, err := os.MkdirTemp(filepath.Dir(target), ".security-notice-update-*")
	if err != nil {
		return result, fmt.Errorf("更新作業フォルダ作成: %w", err)
	}
	defer removeTemporary(dir)
	if err := u.Source.Download(ctx, result.Latest, asset, dir); err != nil {
		return result, fmt.Errorf("更新ダウンロード: %w", err)
	}
	if err := verifyChecksum(dir, asset); err != nil {
		return result, err
	}
	candidate := filepath.Join(dir, "candidate")
	if err := extractBinary(filepath.Join(dir, asset), candidate, releaseBinaryName(u.OS)); err != nil {
		return result, err
	}
	if err := os.Chmod(candidate, info.Mode().Perm()&0777); err != nil {
		return result, fmt.Errorf("更新実行権限設定: %w", err)
	}
	verify := u.Verify
	if verify == nil {
		verify = verifyVersion
	}
	if err := verify(ctx, candidate, result.Latest); err != nil {
		return result, fmt.Errorf("更新バイナリ動作確認: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return result, fmt.Errorf("更新適用中止: %w", err)
	}
	if err := installBinary(candidate, target); err != nil {
		return result, fmt.Errorf("更新適用: %w", err)
	}
	result.Updated = true
	return result, nil
}

func removeTemporary(path string) {
	if err := os.RemoveAll(path); err != nil {
		slog.Warn("更新一時ファイル削除失敗", "path", path, "error", err)
	}
}

func verifyChecksum(dir, asset string) error {
	file, err := os.Open(filepath.Join(dir, "checksums.txt"))
	if err != nil {
		return fmt.Errorf("チェックサム取得: %w", err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	expected := ""
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == asset {
			if expected != "" {
				return fmt.Errorf("チェックサムが重複しています")
			}
			expected = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("チェックサム読込: %w", err)
	}
	want, err := hex.DecodeString(expected)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("対象のSHA-256チェックサムがありません")
	}
	archive, err := os.Open(filepath.Join(dir, asset))
	if err != nil {
		return fmt.Errorf("更新アーカイブ取得: %w", err)
	}
	defer func() { _ = archive.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, archive); err != nil {
		return fmt.Errorf("更新チェックサム算出: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(expected) {
		return fmt.Errorf("更新アーカイブのSHA-256が一致しません")
	}
	return nil
}

const maxBinarySize = 256 << 20

func extractBinary(archive, candidate, name string) error {
	file, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("更新アーカイブ読込: %w", err)
	}
	defer func() { _ = file.Close() }()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("更新gzip読込: %w", err)
	}
	defer func() { _ = gz.Close() }()
	reader := tar.NewReader(gz)
	found := false
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("更新tar読込: %w", err)
		}
		// Never unpack ancillary files, symlinks or paths from the archive.
		if header.Name != name {
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > maxBinarySize {
			return fmt.Errorf("更新バイナリエントリが不正です")
		}
		found = true
		output, err := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if err != nil {
			return fmt.Errorf("更新候補作成: %w", err)
		}
		_, copyErr := io.CopyN(output, reader, header.Size)
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			return fmt.Errorf("更新候補保存: copy=%v sync=%v close=%v", copyErr, syncErr, closeErr)
		}
	}
	if !found {
		return fmt.Errorf("アーカイブに更新バイナリがありません")
	}
	return nil
}

func verifyVersion(ctx context.Context, path, tag string) error {
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		return fmt.Errorf("候補バイナリ実行: %w", err)
	}
	// GoReleaser strips the leading v; the Mac packager preserves it.
	text := strings.TrimSpace(string(out))
	if text != "dependabot-alert-notice "+tag && text != "dependabot-alert-notice "+strings.TrimPrefix(tag, "v") {
		return fmt.Errorf("候補バージョンがReleaseタグと一致しません")
	}
	return nil
}
