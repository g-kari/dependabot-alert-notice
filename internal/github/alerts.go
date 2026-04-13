package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	cfg *config.Config // 設定への参照（動的変更をリアルタイムに反映するためポインタ保持）
}

func New(cfg *config.Config) Client {
	return &ghClient{cfg: cfg}
}

// buildSeverityParam は最低重要度から GitHub API の severity クエリパラメータ文字列を生成する。
// 空文字列を返した場合はパラメータなし（全件取得）を意味する。
func buildSeverityParam(minSeverity string) string {
	switch strings.ToLower(minSeverity) {
	case "critical":
		return "critical"
	case "high":
		return "critical,high"
	case "medium":
		return "critical,high,medium"
	default: // low・空・不明 → フィルタなし
		return ""
	}
}

// isRateLimitMessage は gh コマンドのエラー出力（小文字化済み）がレート制限かを判定する
func isRateLimitMessage(msg string) bool {
	return strings.Contains(msg, "rate limit") || strings.Contains(msg, "secondary rate")
}

// isRepoActive はリポジトリが指定された月数以内にpushがあったかを返す
func isRepoActive(pushedAt time.Time, activeMonths int) bool {
	if activeMonths <= 0 {
		return true // フィルタ無効
	}
	if pushedAt.IsZero() {
		return false // pushedAt不明はスキップ
	}
	cutoff := time.Now().AddDate(0, -activeMonths, 0)
	return pushedAt.After(cutoff)
}

type ghAlert struct {
	Number    int    `json:"number"`
	State     string `json:"state"`
	HTMLURL   string `json:"html_url"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	Repository struct {
		Name     string `json:"name"`
		Archived bool   `json:"archived"`
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
	ResetAt   time.Time
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("GitHub APIレート制限残り %d（リセット: %s）— ポーリングをスキップします",
		e.Remaining, e.ResetAt.Format("15:04:05"))
}

type rateLimitInfo struct {
	Remaining int
	ResetAt   time.Time
}

// checkRateLimit はREST APIの残りリクエスト数とリセット時刻を返す
func (c *ghClient) checkRateLimit(ctx context.Context) (rateLimitInfo, error) {
	out, err := exec.CommandContext(ctx, c.cfg.GhPath, "api", "rate_limit", "--jq", "[.rate.remaining, .rate.reset] | @tsv").Output()
	if err != nil {
		return rateLimitInfo{Remaining: 5000}, nil // 取得失敗時は続行
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "\t")
	var remaining, resetUnix int
	_, _ = fmt.Sscanf(parts[0], "%d", &remaining)
	if len(parts) > 1 {
		_, _ = fmt.Sscanf(parts[1], "%d", &resetUnix)
	}
	return rateLimitInfo{
		Remaining: remaining,
		ResetAt:   time.Unix(int64(resetUnix), 0),
	}, nil
}

// isRepoArchived はリポジトリがアーカイブ済みかを返す。取得失敗時は false（続行）。
func (c *ghClient) isRepoArchived(ctx context.Context, owner, repo string) bool {
	out, err := exec.CommandContext(ctx, c.cfg.GhPath, "repo", "view",
		fmt.Sprintf("%s/%s", owner, repo),
		"--json", "isArchived",
		"--jq", ".isArchived",
	).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

func (c *ghClient) FetchAlerts(ctx context.Context, target config.Target) ([]model.Alert, error) {
	// レート制限チェック（残り200未満はスキップ）
	info, _ := c.checkRateLimit(ctx)
	slog.Debug("レート制限確認", "remaining", info.Remaining, "resetAt", info.ResetAt.Format("15:04:05"))
	if info.Remaining < 200 {
		return nil, &RateLimitError{Remaining: info.Remaining, ResetAt: info.ResetAt}
	}

	// リポジトリ指定あり → 直接取得（exclude対象・アーカイブ済みの場合は空を返す）
	if target.Repo != "" {
		slog.Info("アラート取得開始（リポジトリ指定）", "owner", target.Owner, "repo", target.Repo)
		if target.IsExcluded(target.Repo) {
			slog.Debug("リポジトリ除外スキップ", "owner", target.Owner, "repo", target.Repo)
			return nil, nil
		}
		if c.isRepoArchived(ctx, target.Owner, target.Repo) {
			slog.Debug("アーカイブリポジトリをスキップ", "owner", target.Owner, "repo", target.Repo)
			return nil, nil
		}
		return c.fetchRepoAlerts(ctx, target.Owner, target.Repo)
	}

	// リポジトリ指定なし → org API を試してダメなら全repoにフォールバック
	slog.Info("アラート取得開始（org全体）", "owner", target.Owner)
	alerts, err := c.fetchOrgAlerts(ctx, target.Owner, target.Excludes)
	if err != nil {
		slog.Debug("org APIが失敗、ユーザーリポジトリにフォールバック", "owner", target.Owner, "error", err)
		return c.fetchUserRepoAlerts(ctx, target.Owner, target.Excludes)
	}
	return alerts, nil
}

// alertNumberMarker は gh api --paginate の出力から取得件数を数えるためのマーカー
var alertNumberMarker = []byte(`"number":`)

func (c *ghClient) fetchOrgAlerts(ctx context.Context, owner string, excludes []string) ([]model.Alert, error) {
	endpoint := fmt.Sprintf("/orgs/%s/dependabot/alerts?state=open&per_page=100", owner)
	if sev := buildSeverityParam(c.cfg.FetchMinSeverity); sev != "" {
		endpoint += "&severity=" + sev
	}
	slog.Info("org APIアラート取得開始", "owner", owner, "fetchMinSeverity", c.cfg.FetchMinSeverity)

	cmd := exec.CommandContext(ctx, c.cfg.GhPath, "api", endpoint, "--paginate")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe 失敗: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("org API 起動失敗: %w", err)
	}

	// ストリームを読みながら取得件数をカウント（100件≒1ページごとにログ）
	var buf bytes.Buffer
	fetched := 0
	chunk := make([]byte, 32*1024)
	for {
		n, readErr := stdout.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
			prev := fetched / 100
			fetched += bytes.Count(chunk[:n], alertNumberMarker)
			if fetched/100 > prev {
				slog.Info("org APIアラート取得中", "owner", owner, "fetched", fetched)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = cmd.Wait()
			return nil, fmt.Errorf("stdout 読み込み失敗: %w", readErr)
		}
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("org API 失敗: %w", err)
	}

	alerts, err := c.parseAlerts(buf.Bytes(), owner, "", excludes)
	if err != nil {
		return nil, err
	}
	slog.Info("org APIアラートパース完了", "owner", owner, "count", len(alerts))

	// activeMonths > 0 のとき: リポ一覧を取得して非活動リポのアラートをフィルタ
	if c.cfg.ActiveMonths > 0 && len(alerts) > 0 {
		repoList, err := c.fetchRepoList(ctx, owner)
		if err != nil {
			slog.Warn("リポ一覧取得失敗（activeMonthsフィルタをスキップ）", "owner", owner, "error", err)
		} else {
			before := len(alerts)
			alerts = filterAlertsByActiveRepos(alerts, repoList, c.cfg.ActiveMonths)
			slog.Info("直近活動フィルタ適用（org）", "owner", owner, "before", before, "after", len(alerts), "activeMonths", c.cfg.ActiveMonths)
		}
	}

	// リポジトリ別にGraphQL APIでdependabotUpdateエラー情報を補完
	c.enrichUpdateErrors(ctx, owner, alerts)

	repoCount := 0
	repoSet := make(map[string]struct{})
	for _, a := range alerts {
		repoSet[a.Repo] = struct{}{}
	}
	repoCount = len(repoSet)
	slog.Info("org APIアラート取得完了", "owner", owner, "count", len(alerts), "repos", repoCount)

	return alerts, nil
}

// fetchRepoList は gh repo list でリポジトリ一覧（名前・アーカイブ状態・pushedAt）を取得する
func (c *ghClient) fetchRepoList(ctx context.Context, owner string) ([]repoListItem, error) {
	cmd := exec.CommandContext(ctx, c.cfg.GhPath, "repo", "list", owner,
		"--json", "name,isArchived,pushedAt",
		"--limit", "1000",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("リポジトリ一覧取得失敗: %w", err)
	}
	var items []repoListItem
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("リポジトリ一覧JSONパース失敗: %w", err)
	}
	slog.Debug("リポジトリ一覧取得", "owner", owner, "count", len(items))
	return items, nil
}

// filterAlertsByActiveRepos は非活動リポジトリ（アーカイブ・pushedAt古い・リポ一覧にない）のアラートを除外する。
// activeMonths=0 のときはフィルタなしで全件返す。
func filterAlertsByActiveRepos(alerts []model.Alert, repoList []repoListItem, activeMonths int) []model.Alert {
	if activeMonths <= 0 {
		return alerts
	}
	activeSet := make(map[string]struct{}, len(repoList))
	for _, r := range repoList {
		if !r.IsArchived && isRepoActive(r.PushedAt, activeMonths) {
			activeSet[r.Name] = struct{}{}
		}
	}
	result := alerts[:0]
	for _, a := range alerts {
		if _, ok := activeSet[a.Repo]; ok {
			result = append(result, a)
		}
	}
	return result
}

// enrichUpdateErrors はアラートをリポジトリ別にグループ化し、各リポジトリのdependabotUpdate情報（エラー + PR番号）を補完する
func (c *ghClient) enrichUpdateErrors(ctx context.Context, owner string, alerts []model.Alert) {
	repoSet := make(map[string]struct{})
	for _, a := range alerts {
		repoSet[a.Repo] = struct{}{}
	}
	if len(repoSet) == 0 {
		return
	}
	slog.Info("GraphQL補完開始（PR番号・エラー情報）", "owner", owner, "repos", len(repoSet))

	done := 0
	for repo := range repoSet {
		info := c.fetchGraphQLUpdates(ctx, owner, repo)
		for i := range alerts {
			if alerts[i].Repo == repo {
				if e, ok := info.Errors[alerts[i].Number]; ok {
					alerts[i].UpdateError = e
				}
				if pr, ok := info.PRNumbers[alerts[i].Number]; ok {
					alerts[i].PRNumber = pr
				}
			}
		}
		done++
		if done%10 == 0 || done == len(repoSet) {
			slog.Info("GraphQL補完進捗", "owner", owner, "done", done, "total", len(repoSet))
		}
	}
	slog.Info("GraphQL補完完了", "owner", owner, "repos", len(repoSet))
}

// repoListItem は `gh repo list --json name,isArchived,pushedAt` の各要素
type repoListItem struct {
	Name       string    `json:"name"`
	IsArchived bool      `json:"isArchived"`
	PushedAt   time.Time `json:"pushedAt"`
}

// fetchUserRepoAlerts はユーザーの全リポジトリを列挙して各リポジトリのアラートを取得する
func (c *ghClient) fetchUserRepoAlerts(ctx context.Context, owner string, excludes []string) ([]model.Alert, error) {
	repoItems, err := c.fetchRepoList(ctx, owner)
	if err != nil {
		return nil, err
	}

	excludeSet := make(map[string]struct{}, len(excludes))
	for _, ex := range excludes {
		excludeSet[ex] = struct{}{}
	}

	var repos []string
	skippedInactive := 0
	for _, item := range repoItems {
		if item.IsArchived {
			continue
		}
		if _, skip := excludeSet[item.Name]; skip {
			slog.Debug("リポジトリ除外", "owner", owner, "repo", item.Name)
			continue
		}
		if !isRepoActive(item.PushedAt, c.cfg.ActiveMonths) {
			slog.Debug("直近活動なしリポジトリをスキップ",
				"owner", owner, "repo", item.Name, "pushedAt", item.PushedAt, "activeMonths", c.cfg.ActiveMonths)
			skippedInactive++
			continue
		}
		repos = append(repos, item.Name)
	}

	if skippedInactive > 0 {
		slog.Info("直近活動なしリポジトリをスキップ", "owner", owner, "skipped", skippedInactive, "activeMonths", c.cfg.ActiveMonths)
	}
	slog.Info("リポジトリ別アラート取得開始", "owner", owner, "repos", len(repos))

	// GitHub secondary rate limit: 最大100並列。余裕を持って10に制限
	const concurrency = 10
	sem := make(chan struct{}, concurrency)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu           sync.Mutex
		all          []model.Alert
		wg           sync.WaitGroup
		completed    int
		rateLimitErr *RateLimitError
	)
	total := len(repos)
	for _, repo := range repos {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			alerts, err := c.fetchRepoAlerts(ctx, owner, repo)

			mu.Lock()
			completed++
			done := completed
			if err == nil {
				all = append(all, alerts...)
			} else {
				var skipErr *SkipError
				var rlErr *RateLimitError
				if errors.As(err, &rlErr) {
					if rateLimitErr == nil {
						rateLimitErr = rlErr
					}
					cancel() // 残りのgoroutineをキャンセル
				} else if !errors.As(err, &skipErr) {
					slog.Debug("リポジトリのアラート取得スキップ", "repo", repo, "error", err)
				}
			}
			mu.Unlock()

			// 10件ごと、または最後の1件で進捗をログ
			if done%10 == 0 || done == total {
				slog.Info("リポジトリ別アラート取得進捗", "owner", owner, "done", done, "total", total)
			}
		}(repo)
	}
	wg.Wait()

	if rateLimitErr != nil {
		slog.Warn("レート制限によりリポジトリ別取得を中断", "owner", owner, "completed", rateLimitErr.Remaining)
		return nil, rateLimitErr
	}

	slog.Info("アラート取得完了（全リポジトリ）", "owner", owner, "repos", total, "alerts", len(all))
	return all, nil
}

func (c *ghClient) fetchRepoAlerts(ctx context.Context, owner, repo string) ([]model.Alert, error) {
	endpoint := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open&per_page=100", owner, repo)
	if sev := buildSeverityParam(c.cfg.FetchMinSeverity); sev != "" {
		endpoint += "&severity=" + sev
	}
	slog.Debug("gh api実行（リポジトリ）", "endpoint", endpoint)
	cmd := exec.CommandContext(ctx, c.cfg.GhPath, "api", endpoint, "--paginate")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.ToLower(strings.TrimSpace(string(out)))
		// レート制限は403で返るが権限エラーと区別する（先にチェック）
		if isRateLimitMessage(msg) {
			info, _ := c.checkRateLimit(ctx)
			slog.Warn("レート制限検出（リポジトリ取得中）", "owner", owner, "repo", repo, "remaining", info.Remaining)
			return nil, &RateLimitError{Remaining: info.Remaining, ResetAt: info.ResetAt}
		}
		// Dependabot未有効・権限なし・リポジトリ不存在はスキップ
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

	// GraphQL APIでdependabotUpdate情報（エラー + PR番号）を補完
	if len(alerts) > 0 {
		info := c.fetchGraphQLUpdates(ctx, owner, repo)
		for i := range alerts {
			if e, ok := info.Errors[alerts[i].Number]; ok {
				alerts[i].UpdateError = e
			}
			if pr, ok := info.PRNumbers[alerts[i].Number]; ok {
				alerts[i].PRNumber = pr
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
	excluded, archived := 0, 0
	for _, r := range raw {
		// org API ではレスポンスにリポジトリ名が含まれる。除外リストをチェック
		repoName := repo
		if repoName == "" {
			repoName = r.Repository.Name
		}
		if _, skip := excludeSet[repoName]; skip {
			excluded++
			continue
		}
		// アーカイブ済みリポジトリはスキップ
		if r.Repository.Archived {
			slog.Debug("アーカイブリポジトリをスキップ", "repo", repoName)
			archived++
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
	slog.Debug("アラートパース完了", "total", len(raw), "valid", len(alerts), "excluded", excluded, "archived", archived)
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

// graphqlUpdateInfo はGraphQL APIのdependabotUpdate応答から抽出した情報
type graphqlUpdateInfo struct {
	Errors    map[int]*model.DependabotUpdateError // アラート番号 → エラー情報
	PRNumbers map[int]int                          // アラート番号 → PR番号
}

// parseGraphQLUpdates はGraphQL応答からdependabotUpdateの全情報（エラー + PR番号）をパースする
func parseGraphQLUpdates(data []byte) graphqlUpdateInfo {
	info := graphqlUpdateInfo{
		Errors:    make(map[int]*model.DependabotUpdateError),
		PRNumbers: make(map[int]int),
	}
	var resp graphqlUpdateResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		slog.Debug("GraphQLレスポンスパース失敗", "error", err)
		return info
	}
	for _, node := range resp.Data.Repository.VulnerabilityAlerts.Nodes {
		if node.DependabotUpdate == nil {
			continue
		}
		if node.DependabotUpdate.Error != nil {
			e := node.DependabotUpdate.Error
			info.Errors[node.Number] = &model.DependabotUpdateError{
				ErrorType: e.ErrorType,
				Title:     e.Title,
				Body:      e.Body,
			}
		}
		if node.DependabotUpdate.PullRequest != nil && node.DependabotUpdate.PullRequest.Number > 0 {
			info.PRNumbers[node.Number] = node.DependabotUpdate.PullRequest.Number
		}
	}
	return info
}

// parseUpdateErrors はGraphQL応答からdependabotUpdateエラーをパースする（後方互換ラッパー）
func parseUpdateErrors(data []byte) map[int]*model.DependabotUpdateError {
	return parseGraphQLUpdates(data).Errors
}

// fetchGraphQLUpdates はGraphQL APIでdependabotUpdateの全情報（エラー + PR番号）を取得する
func (c *ghClient) fetchGraphQLUpdates(ctx context.Context, owner, repo string) graphqlUpdateInfo {
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

	cmd := exec.CommandContext(ctx, c.cfg.GhPath, "api", "graphql", "-f", "query="+query)
	out, err := cmd.Output()
	if err != nil {
		slog.Debug("GraphQL API失敗（dependabotUpdate取得）", "owner", owner, "repo", repo, "error", err)
		return graphqlUpdateInfo{
			Errors:    make(map[int]*model.DependabotUpdateError),
			PRNumbers: make(map[int]int),
		}
	}
	info := parseGraphQLUpdates(out)
	slog.Debug("GraphQL取得完了", "owner", owner, "repo", repo, "errors", len(info.Errors), "prs", len(info.PRNumbers))
	return info
}

func (c *ghClient) FindDependabotPR(ctx context.Context, owner, repo, pkgName string) (int, error) {
	// dependabot PRを検索
	cmd := exec.CommandContext(ctx, c.cfg.GhPath, "pr", "list",
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
