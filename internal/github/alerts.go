package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// SkipError はDependabot未有効・権限なし等でアラート取得をスキップする場合のエラー型
type SkipError struct {
	Owner  string
	Repo   string
	Reason string
}

func (e *SkipError) Error() string {
	return fmt.Sprintf("Dependabotアラートスキップ (%s/%s): %s", e.Owner, e.Repo, e.Reason)
}

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
	Number    int    `json:"number"`
	State     string `json:"state"`
	HTMLURL   string `json:"html_url"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	Repository struct {
		Name string `json:"name"`
	} `json:"repository"`

	Dependency struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
		Scope        string `json:"scope"`
		Relationship string `json:"relationship"`
	} `json:"dependency"`

	SecurityAdvisory struct {
		GHSAID      string `json:"ghsa_id"`
		CVEID       string `json:"cve_id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`

		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`

		References []struct {
			URL string `json:"url"`
		} `json:"references"`

		CWEs []struct {
			CWEID string `json:"cwe_id"`
			Name  string `json:"name"`
		} `json:"cwes"`

		PublishedAt string `json:"published_at"`
		UpdatedAt   string `json:"updated_at"`

		CVSS struct {
			Score        float64 `json:"score"`
			VectorString string  `json:"vector_string"`
		} `json:"cvss"`

		CVSSSeverities struct {
			V3 struct {
				Score        float64 `json:"score"`
				VectorString string  `json:"vector_string"`
			} `json:"cvss_v3"`
			V4 struct {
				Score        float64 `json:"score"`
				VectorString string  `json:"vector_string"`
			} `json:"cvss_v4"`
		} `json:"cvss_severities"`

		EPSS *struct {
			Percentage float64 `json:"percentage"`
			Percentile float64 `json:"percentile"`
		} `json:"epss"`
	} `json:"security_advisory"`

	SecurityVulnerability struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Severity               string `json:"severity"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
}

// RateLimitError はGitHub APIのレート制限に達した場合のエラー型
type RateLimitError struct {
	Remaining int
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("GitHub APIレート制限残り %d — ポーリングをスキップします", e.Remaining)
}

// checkRateLimit はREST APIの残りリクエスト数を返す
func (c *ghClient) checkRateLimit(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, c.ghPath, "api", "rate_limit", "--jq", ".rate.remaining").Output()
	if err != nil {
		return 5000, nil // 取得失敗時は続行
	}
	var remaining int
	_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &remaining)
	return remaining, nil
}

func (c *ghClient) FetchAlerts(ctx context.Context, target config.Target) ([]model.Alert, error) {
	// レート制限チェック（残り200未満はスキップ）
	if remaining, _ := c.checkRateLimit(ctx); remaining < 200 {
		return nil, &RateLimitError{Remaining: remaining}
	}

	// リポジトリ指定あり → 直接取得（exclude対象の場合は空を返す）
	if target.Repo != "" {
		if target.IsExcluded(target.Repo) {
			slog.Debug("リポジトリ除外スキップ", "owner", target.Owner, "repo", target.Repo)
			return nil, nil
		}
		return c.fetchRepoAlerts(ctx, target.Owner, target.Repo)
	}

	// リポジトリ指定なし → org API を試してダメなら全repoにフォールバック
	alerts, err := c.fetchOrgAlerts(ctx, target.Owner, target.Excludes)
	if err != nil {
		slog.Debug("org APIが失敗、ユーザーリポジトリにフォールバック", "owner", target.Owner, "error", err)
		return c.fetchUserRepoAlerts(ctx, target.Owner, target.Excludes)
	}
	return alerts, nil
}

func (c *ghClient) fetchOrgAlerts(ctx context.Context, owner string, excludes []string) ([]model.Alert, error) {
	endpoint := fmt.Sprintf("/orgs/%s/dependabot/alerts?state=open&per_page=100", owner)
	cmd := exec.CommandContext(ctx, c.ghPath, "api", endpoint, "--paginate")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("org API 失敗: %w", err)
	}
	alerts, err := c.parseAlerts(out, owner, "", excludes)
	if err != nil {
		return nil, err
	}

	// リポジトリ別にGraphQL APIでdependabotUpdateエラー情報を補完
	c.enrichUpdateErrors(ctx, owner, alerts)

	return alerts, nil
}

// enrichUpdateErrors はアラートをリポジトリ別にグループ化し、各リポジトリのdependabotUpdateエラーを補完する
func (c *ghClient) enrichUpdateErrors(ctx context.Context, owner string, alerts []model.Alert) {
	repoSet := make(map[string]struct{})
	for _, a := range alerts {
		repoSet[a.Repo] = struct{}{}
	}

	for repo := range repoSet {
		updateErrors := c.fetchUpdateErrors(ctx, owner, repo)
		for i := range alerts {
			if alerts[i].Repo == repo {
				if e, ok := updateErrors[alerts[i].Number]; ok {
					alerts[i].UpdateError = e
				}
			}
		}
	}
}

// fetchUserRepoAlerts はユーザーの全リポジトリを列挙して各リポジトリのアラートを取得する
func (c *ghClient) fetchUserRepoAlerts(ctx context.Context, owner string, excludes []string) ([]model.Alert, error) {
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

	excludeSet := make(map[string]struct{}, len(excludes))
	for _, ex := range excludes {
		excludeSet[ex] = struct{}{}
	}

	var repos []string
	for _, line := range splitLines(string(out)) {
		if line == "" {
			continue
		}
		if _, skip := excludeSet[line]; skip {
			slog.Debug("リポジトリ除外", "owner", owner, "repo", line)
			continue
		}
		repos = append(repos, line)
	}

	slog.Debug("ユーザーリポジトリ一覧取得", "owner", owner, "count", len(repos), "excluded", len(excludes))

	// GitHub secondary rate limit: 最大100並列。余裕を持って10に制限
	const concurrency = 10
	sem := make(chan struct{}, concurrency)

	var (
		mu  sync.Mutex
		all []model.Alert
		wg  sync.WaitGroup
	)
	for _, repo := range repos {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			alerts, err := c.fetchRepoAlerts(ctx, owner, repo)
			if err != nil {
				// SkipErrorは静かに無視（Dependabot未有効など）
				var skipErr *SkipError
				if !errors.As(err, &skipErr) {
					slog.Debug("リポジトリのアラート取得スキップ", "repo", repo, "error", err)
				}
				return
			}
			mu.Lock()
			all = append(all, alerts...)
			mu.Unlock()
		}(repo)
	}
	wg.Wait()

	slog.Info("アラート取得完了（全リポジトリ）", "owner", owner, "repos", len(repos), "alerts", len(all))
	return all, nil
}

func (c *ghClient) fetchRepoAlerts(ctx context.Context, owner, repo string) ([]model.Alert, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open&per_page=100", owner, repo)
	cmd := exec.CommandContext(ctx, c.ghPath, "api", endpoint, "--paginate")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		// Dependabot未有効・権限なし・リポジトリ不存在は警告スキップ
		if strings.Contains(msg, "not found") ||
			strings.Contains(msg, "not enabled") ||
			strings.Contains(msg, "403") ||
			strings.Contains(msg, "404") ||
			strings.Contains(msg, "dependabot alerts are disabled") {
			return nil, &SkipError{Owner: owner, Repo: repo, Reason: strings.TrimSpace(string(out))}
		}
		return nil, fmt.Errorf("gh api 実行失敗: %w", err)
	}
	alerts, err := c.parseAlerts(out, owner, repo, nil)
	if err != nil {
		return nil, err
	}

	// GraphQL APIでdependabotUpdateエラー情報を補完
	if len(alerts) > 0 {
		updateErrors := c.fetchUpdateErrors(ctx, owner, repo)
		for i := range alerts {
			if e, ok := updateErrors[alerts[i].Number]; ok {
				alerts[i].UpdateError = e
			}
		}
	}

	slog.Info("アラート取得完了", "target", fmt.Sprintf("%s/%s", owner, repo), "count", len(alerts))
	return alerts, nil
}

func (c *ghClient) parseAlerts(out []byte, owner, repo string, excludes []string) ([]model.Alert, error) {
	var raw []ghAlert
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("JSONパース失敗: %w", err)
	}

	excludeSet := make(map[string]struct{}, len(excludes))
	for _, ex := range excludes {
		excludeSet[ex] = struct{}{}
	}

	alerts := make([]model.Alert, 0, len(raw))
	for _, r := range raw {
		// org API ではレスポンスにリポジトリ名が含まれる。除外リストをチェック
		repoName := repo
		if repoName == "" {
			repoName = r.Repository.Name
		}
		if _, skip := excludeSet[repoName]; skip {
			continue
		}

		createdAt, _ := time.Parse(time.RFC3339, r.CreatedAt)
		updatedAt, _ := time.Parse(time.RFC3339, r.UpdatedAt)
		publishedAt, _ := time.Parse(time.RFC3339, r.SecurityAdvisory.PublishedAt)

		// CVSS: v4 > v3 > legacy の優先順位で取得
		cvss := r.SecurityAdvisory.CVSS.Score
		cvssVector := r.SecurityAdvisory.CVSS.VectorString
		if r.SecurityAdvisory.CVSSSeverities.V4.Score > 0 {
			cvss = r.SecurityAdvisory.CVSSSeverities.V4.Score
			cvssVector = r.SecurityAdvisory.CVSSSeverities.V4.VectorString
		} else if r.SecurityAdvisory.CVSSSeverities.V3.Score > 0 {
			cvss = r.SecurityAdvisory.CVSSSeverities.V3.Score
			cvssVector = r.SecurityAdvisory.CVSSSeverities.V3.VectorString
		}

		// CVE ID: top-level cve_id を優先し、なければ identifiers 配列から取得
		cveID := r.SecurityAdvisory.CVEID
		if cveID == "" {
			for _, id := range r.SecurityAdvisory.Identifiers {
				if id.Type == "CVE" {
					cveID = id.Value
					break
				}
			}
		}

		// References
		refs := make([]string, 0, len(r.SecurityAdvisory.References))
		for _, ref := range r.SecurityAdvisory.References {
			refs = append(refs, ref.URL)
		}

		// CWEs
		cwes := make([]model.CWE, 0, len(r.SecurityAdvisory.CWEs))
		for _, cwe := range r.SecurityAdvisory.CWEs {
			cwes = append(cwes, model.CWE{ID: cwe.CWEID, Name: cwe.Name})
		}

		// EPSS
		var epss *model.EPSS
		if r.SecurityAdvisory.EPSS != nil {
			epss = &model.EPSS{
				Percentage: r.SecurityAdvisory.EPSS.Percentage,
				Percentile: r.SecurityAdvisory.EPSS.Percentile,
			}
		}

		alerts = append(alerts, model.Alert{
			Number:           r.Number,
			State:            r.State,
			Owner:            owner,
			Repo:             repoName,
			PackageName:      r.SecurityVulnerability.Package.Name,
			PackageEcosystem: r.SecurityVulnerability.Package.Ecosystem,
			Severity:         model.Severity(r.SecurityVulnerability.Severity),
			CVEID:            cveID,
			GHSAID:           r.SecurityAdvisory.GHSAID,
			CVSSScore:        cvss,
			CVSSVector:       cvssVector,
			Summary:          r.SecurityAdvisory.Summary,
			Description:      r.SecurityAdvisory.Description,
			FixedIn:          r.SecurityVulnerability.FirstPatchedVersion.Identifier,
			HTMLURL:          r.HTMLURL,
			CreatedAt:        createdAt,
			UpdatedAt:        updatedAt,
			PublishedAt:      publishedAt,

			VulnerableVersionRange: r.SecurityVulnerability.VulnerableVersionRange,
			ManifestPath:           r.Dependency.ManifestPath,
			DependencyScope:        r.Dependency.Scope,
			DependencyRelationship: r.Dependency.Relationship,
			EPSS:                   epss,
			CWEs:                   cwes,
			References:             refs,
		})
	}
	return alerts, nil
}

// graphqlUpdateResponse はGraphQL APIのdependabotUpdate応答を表す
type graphqlUpdateResponse struct {
	Data struct {
		Repository struct {
			VulnerabilityAlerts struct {
				Nodes []struct {
					Number           int `json:"number"`
					DependabotUpdate *struct {
						Error *struct {
							ErrorType string `json:"errorType"`
							Title     string `json:"title"`
							Body      string `json:"body"`
						} `json:"error"`
						PullRequest *struct {
							Number int `json:"number"`
						} `json:"pullRequest"`
					} `json:"dependabotUpdate"`
				} `json:"nodes"`
			} `json:"vulnerabilityAlerts"`
		} `json:"repository"`
	} `json:"data"`
}

// parseUpdateErrors はGraphQL応答からdependabotUpdateエラーをパースする
func parseUpdateErrors(data []byte) map[int]*model.DependabotUpdateError {
	var resp graphqlUpdateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		slog.Debug("GraphQLレスポンスパース失敗", "error", err)
		return nil
	}

	errors := make(map[int]*model.DependabotUpdateError)
	for _, node := range resp.Data.Repository.VulnerabilityAlerts.Nodes {
		if node.DependabotUpdate != nil && node.DependabotUpdate.Error != nil {
			e := node.DependabotUpdate.Error
			errors[node.Number] = &model.DependabotUpdateError{
				ErrorType: e.ErrorType,
				Title:     e.Title,
				Body:      e.Body,
			}
		}
	}
	return errors
}

// fetchUpdateErrors はGraphQL APIでdependabotUpdateエラー情報を取得する
func (c *ghClient) fetchUpdateErrors(ctx context.Context, owner, repo string) map[int]*model.DependabotUpdateError {
	query := fmt.Sprintf(`query {
		repository(owner: %q, name: %q) {
			vulnerabilityAlerts(first: 100, states: OPEN) {
				nodes {
					number
					dependabotUpdate {
						error { errorType title body }
						pullRequest { number }
					}
				}
			}
		}
	}`, owner, repo)

	cmd := exec.CommandContext(ctx, c.ghPath, "api", "graphql", "-f", "query="+query)
	out, err := cmd.Output()
	if err != nil {
		slog.Debug("GraphQL API失敗（dependabotUpdate取得）", "owner", owner, "repo", repo, "error", err)
		return nil
	}
	return parseUpdateErrors(out)
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
