package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
)

// GitHubSource retrieves published releases through the user's gh authentication.
type GitHubSource struct {
	Repository string
	Path       string
	Run        func(context.Context, ...string) ([]byte, error)
}

var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)

func (s GitHubSource) command(ctx context.Context, args ...string) ([]byte, error) {
	if !repositoryPattern.MatchString(s.Repository) {
		return nil, fmt.Errorf("更新リポジトリはowner/repo形式で指定してください")
	}
	if s.Run != nil {
		return s.Run(ctx, args...)
	}
	path := s.Path
	if path == "" {
		path = "gh"
	}
	// Output keeps release JSON separate from stderr and avoids logging credentials.
	out, err := exec.CommandContext(ctx, path, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("GitHub Release取得（ghの認証・リポジトリアクセスを確認）: %w", err)
	}
	return out, nil
}

// Latest returns GitHub's latest published non-prerelease release.
func (s GitHubSource) Latest(ctx context.Context) (Release, error) {
	out, err := s.command(ctx, "api", "repos/"+s.Repository+"/releases/latest")
	if err != nil {
		return Release{}, fmt.Errorf("最新Release確認: %w", err)
	}
	var release Release
	if err := json.Unmarshal(out, &release); err != nil {
		return Release{}, fmt.Errorf("Release解析: %w", err)
	}
	return release, nil
}

// Download fetches the exact tag's archive and checksum into an empty directory.
func (s GitHubSource) Download(ctx context.Context, tag, asset, dir string) error {
	_, err := s.command(ctx, "release", "download", tag, "--repo", s.Repository, "--pattern", asset, "--pattern", "checksums.txt", "--dir", dir)
	if err != nil {
		return fmt.Errorf("更新ファイル取得: %w", err)
	}
	return nil
}
