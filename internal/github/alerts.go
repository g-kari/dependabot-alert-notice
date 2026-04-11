package github

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

type Client interface {
	FetchAlerts(ctx context.Context, target config.Target) ([]model.Alert, error)
	FindDependabotPR(ctx context.Context, owner, repo, pkgName string) (int, error)
}

type ghClient struct {
	ghPath string
}

func New(cfg *config.Config) Client {
	return &ghClient{ghPath: cfg.GhPath}
}

type ghAlert struct {
	Number           int    `json:"number"`
	State            string `json:"state"`
	HTMLURL          string `json:"html_url"`
	CreatedAt        string `json:"created_at"`
	SecurityAdvisory struct {
		Summary string `json:"summary"`
		CVEs    []struct {
			ID string `json:"cve_id"`
		} `json:"identifiers"`
	} `json:"security_advisory"`
	SecurityVulnerability struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Severity            string `json:"severity"`
		FirstPatchedVersion struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
}

func (c *ghClient) FetchAlerts(ctx context.Context, target config.Target) ([]model.Alert, error) {
	// リポジトリ指定あり → 直接取得
	if target.Repo != "" {
		return c.fetchRepoAlerts(ctx, target.Owner, target.Repo)
	}

	// リポジトリ指定なし → org API を試してダメなら全repoにフォールバック
	alerts, err := c.fetchOrgAlerts(ctx, target.Owner)
	if err != nil {
		slog.Debug("org APIが失敗、ユーザーリポジトリにフォールバック", "owner", target.Owner, "error", err)
		return c.fetchUserRepoAlerts(ctx, target.Owner)
	}
	return alerts, nil
}

func (c *ghClient) fetchOrgAlerts(ctx context.Context, owner string) ([]model.Alert, error) {
	endpoint := fmt.Sprintf("/orgs/%s/dependabot/alerts?state=open&per_page=100", owner)
	cmd := exec.CommandContext(ctx, c.ghPath, "api", endpoint, "--paginate")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("org API 失敗: %w", err)
	}
	return c.parseAlerts(out, owner, "")
}

// fetchUserRepoAlerts はユーザーの全リポジトリを列挙して各リポジトリのアラートを取得する
func (c *ghClient) fetchUserRepoAlerts(ctx context.Context, owner string) ([]model.Alert, error) {
	// リポジトリ一覧取得
	cmd := exec.CommandContext(ctx, c.ghPath, "repo", "list", owner,
		"--json", "name",
		"--jq", ".[].name",
		"--limit", "1000",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("リポジトリ一覧取得失敗: %w", err)
	}

	var repos []string
	for _, line := range splitLines(string(out)) {
		if line != "" {
			repos = append(repos, line)
		}
	}

	slog.Debug("ユーザーリポジトリ一覧取得", "owner", owner, "count", len(repos))

	var all []model.Alert
	for _, repo := range repos {
		alerts, err := c.fetchRepoAlerts(ctx, owner, repo)
		if err != nil {
			slog.Debug("リポジトリのアラート取得スキップ", "repo", repo, "error", err)
			continue
		}
		all = append(all, alerts...)
	}

	slog.Info("アラート取得完了（全リポジトリ）", "owner", owner, "repos", len(repos), "alerts", len(all))
	return all, nil
}

func (c *ghClient) fetchRepoAlerts(ctx context.Context, owner, repo string) ([]model.Alert, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open&per_page=100", owner, repo)
	cmd := exec.CommandContext(ctx, c.ghPath, "api", endpoint, "--paginate")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gh api 実行失敗: %w", err)
	}
	alerts, err := c.parseAlerts(out, owner, repo)
	if err != nil {
		return nil, err
	}
	slog.Info("アラート取得完了", "target", fmt.Sprintf("%s/%s", owner, repo), "count", len(alerts))
	return alerts, nil
}

func (c *ghClient) parseAlerts(out []byte, owner, repo string) ([]model.Alert, error) {
	var raw []ghAlert
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("JSONパース失敗: %w", err)
	}

	alerts := make([]model.Alert, 0, len(raw))
	for _, r := range raw {
		createdAt, _ := time.Parse(time.RFC3339, r.CreatedAt)

		var cveID string
		if len(r.SecurityAdvisory.CVEs) > 0 {
			cveID = r.SecurityAdvisory.CVEs[0].ID
		}

		alerts = append(alerts, model.Alert{
			ID:               r.Number,
			Number:           r.Number,
			State:            r.State,
			Owner:            owner,
			Repo:             repo,
			PackageName:      r.SecurityVulnerability.Package.Name,
			PackageEcosystem: r.SecurityVulnerability.Package.Ecosystem,
			Severity:         model.Severity(r.SecurityVulnerability.Severity),
			CVEID:            cveID,
			Summary:          r.SecurityAdvisory.Summary,
			FixedIn:          r.SecurityVulnerability.FirstPatchedVersion.Identifier,
			HTMLURL:          r.HTMLURL,
			CreatedAt:        createdAt,
		})
	}
	return alerts, nil
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func (c *ghClient) FindDependabotPR(ctx context.Context, owner, repo, pkgName string) (int, error) {
	// dependabot PRを検索
	cmd := exec.CommandContext(ctx, c.ghPath, "pr", "list",
		"--repo", fmt.Sprintf("%s/%s", owner, repo),
		"--author", "app/dependabot",
		"--state", "open",
		"--json", "number,title",
		"--limit", "100",
	)
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("gh pr list 実行失敗: %w", err)
	}

	var prs []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
	}
	if err := json.Unmarshal(out, &prs); err != nil {
		return 0, fmt.Errorf("PRリストパース失敗: %w", err)
	}

	for _, pr := range prs {
		// dependabot PRのタイトルにはパッケージ名が含まれる
		if containsPackageName(pr.Title, pkgName) {
			return pr.Number, nil
		}
	}

	return 0, fmt.Errorf("パッケージ %s のDependabot PRが見つかりません", pkgName)
}

func containsPackageName(title, pkgName string) bool {
	return len(pkgName) > 0 && contains(title, pkgName)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	if substr == "" {
		return true
	}
	n := len(substr)
	for i := 0; i <= len(s)-n; i++ {
		if equalFold(s[i:i+n], substr) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// PRNumberToString はPR番号を文字列に変換する
func PRNumberToString(n int) string {
	return strconv.Itoa(n)
}
