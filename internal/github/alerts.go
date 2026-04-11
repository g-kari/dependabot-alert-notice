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
	var endpoint string
	if target.Repo != "" {
		endpoint = fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open&per_page=100", target.Owner, target.Repo)
	} else {
		endpoint = fmt.Sprintf("/orgs/%s/dependabot/alerts?state=open&per_page=100", target.Owner)
	}

	cmd := exec.CommandContext(ctx, c.ghPath, "api", endpoint, "--paginate")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("gh api 実行失敗: %w", err)
	}

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

		alert := model.Alert{
			ID:               r.Number,
			Number:           r.Number,
			State:            r.State,
			Owner:            target.Owner,
			Repo:             target.Repo,
			PackageName:      r.SecurityVulnerability.Package.Name,
			PackageEcosystem: r.SecurityVulnerability.Package.Ecosystem,
			Severity:         model.Severity(r.SecurityVulnerability.Severity),
			CVEID:            cveID,
			Summary:          r.SecurityAdvisory.Summary,
			FixedIn:          r.SecurityVulnerability.FirstPatchedVersion.Identifier,
			HTMLURL:          r.HTMLURL,
			CreatedAt:        createdAt,
		}
		alerts = append(alerts, alert)
	}

	slog.Info("アラート取得完了", "target", fmt.Sprintf("%s/%s", target.Owner, target.Repo), "count", len(alerts))
	return alerts, nil
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
