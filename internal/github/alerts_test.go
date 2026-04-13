package github

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestParseAlerts_SkipsArchivedRepository(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "gh"}}
	jsonData := `[
		{
			"number": 1,
			"state": "open",
			"html_url": "https://github.com/owner/archived-repo/security/dependabot/1",
			"created_at": "2024-01-01T00:00:00Z",
			"repository": {"name": "archived-repo", "archived": true},
			"security_advisory": {
				"cve_id": "CVE-2024-0001",
				"summary": "Archived repo vuln",
				"identifiers": [],
				"cvss": {"score": 7.0},
				"cvss_severities": {}
			},
			"security_vulnerability": {
				"package": {"name": "pkg-a", "ecosystem": "npm"},
				"severity": "high",
				"first_patched_version": {"identifier": "1.0.1"}
			}
		},
		{
			"number": 2,
			"state": "open",
			"html_url": "https://github.com/owner/active-repo/security/dependabot/2",
			"created_at": "2024-01-01T00:00:00Z",
			"repository": {"name": "active-repo", "archived": false},
			"security_advisory": {
				"cve_id": "CVE-2024-0002",
				"summary": "Active repo vuln",
				"identifiers": [],
				"cvss": {"score": 5.0},
				"cvss_severities": {}
			},
			"security_vulnerability": {
				"package": {"name": "pkg-b", "ecosystem": "npm"},
				"severity": "medium",
				"first_patched_version": {"identifier": "2.0.0"}
			}
		}
	]`
	// org alert (repo="" → repository.name から取得) でアーカイブリポジトリをスキップ
	alerts, err := c.parseAlerts([]byte(jsonData), "owner", "", nil)
	if err != nil {
		t.Fatalf("parseAlerts() error = %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 (archived repo should be skipped)", len(alerts))
	}
	if alerts[0].Repo != "active-repo" {
		t.Errorf("Repo = %q, want %q", alerts[0].Repo, "active-repo")
	}
}

func TestParseAlerts_CVEFromTopLevel(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "gh"}}
	jsonData := `[{
		"number": 1,
		"state": "open",
		"html_url": "https://github.com/owner/repo/security/dependabot/1",
		"created_at": "2024-01-01T00:00:00Z",
		"security_advisory": {
			"cve_id": "CVE-2024-1234",
			"summary": "Test vulnerability",
			"identifiers": [],
			"cvss": {"score": 7.5},
			"cvss_severities": {}
		},
		"security_vulnerability": {
			"package": {"name": "lodash", "ecosystem": "npm"},
			"severity": "high",
			"first_patched_version": {"identifier": "1.0.1"}
		}
	}]`
	alerts, err := c.parseAlerts([]byte(jsonData), "owner", "repo", nil)
	if err != nil {
		t.Fatalf("parseAlerts() error = %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %q, want %q", alerts[0].CVEID, "CVE-2024-1234")
	}
}

func TestParseAlerts_CVEFromIdentifiers(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "gh"}}
	jsonData := `[{
		"number": 2,
		"state": "open",
		"html_url": "https://github.com/owner/repo/security/dependabot/2",
		"created_at": "2024-01-01T00:00:00Z",
		"security_advisory": {
			"cve_id": "",
			"summary": "Test vulnerability",
			"identifiers": [
				{"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"},
				{"type": "CVE", "value": "CVE-2024-5678"}
			],
			"cvss": {"score": 6.0},
			"cvss_severities": {}
		},
		"security_vulnerability": {
			"package": {"name": "axios", "ecosystem": "npm"},
			"severity": "medium",
			"first_patched_version": {"identifier": "0.21.2"}
		}
	}]`
	alerts, err := c.parseAlerts([]byte(jsonData), "owner", "repo", nil)
	if err != nil {
		t.Fatalf("parseAlerts() error = %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].CVEID != "CVE-2024-5678" {
		t.Errorf("CVEID = %q, want %q", alerts[0].CVEID, "CVE-2024-5678")
	}
}

func TestParseAlerts_NoCVE(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "gh"}}
	jsonData := `[{
		"number": 3,
		"state": "open",
		"html_url": "https://github.com/owner/repo/security/dependabot/3",
		"created_at": "2024-01-01T00:00:00Z",
		"security_advisory": {
			"cve_id": "",
			"summary": "No CVE advisory",
			"identifiers": [
				{"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"}
			],
			"cvss": {"score": 5.0},
			"cvss_severities": {}
		},
		"security_vulnerability": {
			"package": {"name": "some-pkg", "ecosystem": "npm"},
			"severity": "low",
			"first_patched_version": {"identifier": ""}
		}
	}]`
	alerts, err := c.parseAlerts([]byte(jsonData), "owner", "repo", nil)
	if err != nil {
		t.Fatalf("parseAlerts() error = %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].CVEID != "" {
		t.Errorf("CVEID = %q, want empty string", alerts[0].CVEID)
	}
}

func TestParseAlerts_AllFields(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "gh"}}
	jsonData := `[{
		"number": 10,
		"state": "open",
		"html_url": "https://github.com/owner/repo/security/dependabot/10",
		"created_at": "2024-01-15T10:30:00Z",
		"updated_at": "2024-02-01T08:00:00Z",
		"dependency": {
			"package": {"ecosystem": "npm", "name": "lodash"},
			"manifest_path": "package-lock.json",
			"scope": "runtime",
			"relationship": "transitive"
		},
		"security_advisory": {
			"ghsa_id": "GHSA-abcd-efgh-ijkl",
			"cve_id": "CVE-2024-9999",
			"summary": "Prototype Pollution in lodash",
			"description": "Detailed description of the vulnerability with **markdown**.",
			"severity": "high",
			"identifiers": [
				{"type": "GHSA", "value": "GHSA-abcd-efgh-ijkl"},
				{"type": "CVE", "value": "CVE-2024-9999"}
			],
			"references": [
				{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999"},
				{"url": "https://github.com/advisories/GHSA-abcd-efgh-ijkl"}
			],
			"published_at": "2024-01-10T00:00:00Z",
			"updated_at": "2024-01-20T00:00:00Z",
			"cwes": [
				{"cwe_id": "CWE-1321", "name": "Improperly Controlled Modification of Object Prototype Attributes"},
				{"cwe_id": "CWE-94", "name": "Code Injection"}
			],
			"cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
			"cvss_severities": {
				"cvss_v3": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
				"cvss_v4": {"score": 8.2, "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}
			},
			"epss": {
				"percentage": 0.035,
				"percentile": 0.72
			}
		},
		"security_vulnerability": {
			"package": {"name": "lodash", "ecosystem": "npm"},
			"severity": "high",
			"vulnerable_version_range": ">= 4.0.0, < 4.17.21",
			"first_patched_version": {"identifier": "4.17.21"}
		}
	}]`
	alerts, err := c.parseAlerts([]byte(jsonData), "owner", "repo", nil)
	if err != nil {
		t.Fatalf("parseAlerts() error = %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	a := alerts[0]

	// 基本フィールド
	if a.GHSAID != "GHSA-abcd-efgh-ijkl" {
		t.Errorf("GHSAID = %q, want GHSA-abcd-efgh-ijkl", a.GHSAID)
	}
	if a.Description != "Detailed description of the vulnerability with **markdown**." {
		t.Errorf("Description = %q", a.Description)
	}
	if a.VulnerableVersionRange != ">= 4.0.0, < 4.17.21" {
		t.Errorf("VulnerableVersionRange = %q", a.VulnerableVersionRange)
	}

	// 依存関係情報
	if a.ManifestPath != "package-lock.json" {
		t.Errorf("ManifestPath = %q", a.ManifestPath)
	}
	if a.DependencyScope != "runtime" {
		t.Errorf("DependencyScope = %q", a.DependencyScope)
	}
	if a.DependencyRelationship != "transitive" {
		t.Errorf("DependencyRelationship = %q", a.DependencyRelationship)
	}

	// CVSS
	if a.CVSSVector == "" {
		t.Error("CVSSVector should not be empty")
	}
	// v4 優先なので 8.2
	if a.CVSSScore != 8.2 {
		t.Errorf("CVSSScore = %v, want 8.2", a.CVSSScore)
	}

	// 日時
	if a.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should not be zero")
	}
	if a.PublishedAt.IsZero() {
		t.Error("PublishedAt should not be zero")
	}

	// EPSS
	if a.EPSS == nil {
		t.Fatal("EPSS should not be nil")
	}
	if a.EPSS.Percentage != 0.035 {
		t.Errorf("EPSS.Percentage = %v, want 0.035", a.EPSS.Percentage)
	}
	if a.EPSS.Percentile != 0.72 {
		t.Errorf("EPSS.Percentile = %v, want 0.72", a.EPSS.Percentile)
	}

	// CWE
	if len(a.CWEs) != 2 {
		t.Fatalf("CWEs len = %d, want 2", len(a.CWEs))
	}
	if a.CWEs[0].ID != "CWE-1321" {
		t.Errorf("CWEs[0].ID = %q", a.CWEs[0].ID)
	}

	// References
	if len(a.References) != 2 {
		t.Fatalf("References len = %d, want 2", len(a.References))
	}
	if a.References[0] != "https://nvd.nist.gov/vuln/detail/CVE-2024-9999" {
		t.Errorf("References[0] = %q", a.References[0])
	}
}

func TestParseUpdateErrors(t *testing.T) {
	jsonData := `{
		"data": {
			"repository": {
				"vulnerabilityAlerts": {
					"nodes": [
						{
							"number": 10,
							"dependabotUpdate": {
								"error": {
									"errorType": "security_update_not_possible",
									"title": "Dependabot cannot update to the required version",
									"body": "One or more dependencies require a version incompatible"
								}
							}
						},
						{
							"number": 11,
							"dependabotUpdate": {
								"pullRequest": {"number": 42}
							}
						},
						{
							"number": 12,
							"dependabotUpdate": null
						}
					]
				}
			}
		}
	}`

	errors := parseUpdateErrors([]byte(jsonData))
	if len(errors) != 1 {
		t.Fatalf("got %d errors, want 1", len(errors))
	}
	e, ok := errors[10]
	if !ok {
		t.Fatal("expected error for alert #10")
	}
	if e.ErrorType != "security_update_not_possible" {
		t.Errorf("ErrorType = %q", e.ErrorType)
	}
	if e.Title != "Dependabot cannot update to the required version" {
		t.Errorf("Title = %q", e.Title)
	}
}

// TestParseGraphQLUpdates_ExtractsPRNumber はPR番号がGraphQL応答から正しく抽出されることを確認
func TestParseGraphQLUpdates_ExtractsPRNumber(t *testing.T) {
	jsonData := `{
		"data": {
			"repository": {
				"vulnerabilityAlerts": {
					"nodes": [
						{
							"number": 11,
							"dependabotUpdate": {
								"pullRequest": {"number": 42}
							}
						},
						{
							"number": 13,
							"dependabotUpdate": {
								"pullRequest": {"number": 42}
							}
						}
					]
				}
			}
		}
	}`

	info := parseGraphQLUpdates([]byte(jsonData))
	if len(info.PRNumbers) != 2 {
		t.Fatalf("PRNumbers len = %d, want 2", len(info.PRNumbers))
	}
	if info.PRNumbers[11] != 42 {
		t.Errorf("PRNumbers[11] = %d, want 42", info.PRNumbers[11])
	}
	if info.PRNumbers[13] != 42 {
		t.Errorf("PRNumbers[13] = %d, want 42", info.PRNumbers[13])
	}
	if len(info.Errors) != 0 {
		t.Errorf("Errors len = %d, want 0", len(info.Errors))
	}
}

// TestParseGraphQLUpdates_NullUpdate はdependabotUpdateがnullの場合をスキップすることを確認
func TestParseGraphQLUpdates_NullUpdate(t *testing.T) {
	jsonData := `{
		"data": {
			"repository": {
				"vulnerabilityAlerts": {
					"nodes": [
						{"number": 20, "dependabotUpdate": null},
						{"number": 21, "dependabotUpdate": {"pullRequest": {"number": 55}}}
					]
				}
			}
		}
	}`

	info := parseGraphQLUpdates([]byte(jsonData))
	if _, ok := info.PRNumbers[20]; ok {
		t.Error("null dependabotUpdate should produce no PR number for #20")
	}
	if info.PRNumbers[21] != 55 {
		t.Errorf("PRNumbers[21] = %d, want 55", info.PRNumbers[21])
	}
}

// TestParseGraphQLUpdates_ErrorAndPR はエラーとPR番号が共存する場合を確認
func TestParseGraphQLUpdates_ErrorAndPR(t *testing.T) {
	jsonData := `{
		"data": {
			"repository": {
				"vulnerabilityAlerts": {
					"nodes": [
						{
							"number": 10,
							"dependabotUpdate": {
								"error": {
									"errorType": "security_update_not_possible",
									"title": "Cannot update",
									"body": "Details"
								}
							}
						},
						{
							"number": 11,
							"dependabotUpdate": {
								"pullRequest": {"number": 42}
							}
						}
					]
				}
			}
		}
	}`

	info := parseGraphQLUpdates([]byte(jsonData))
	if len(info.Errors) != 1 {
		t.Errorf("Errors len = %d, want 1", len(info.Errors))
	}
	if info.Errors[10] == nil {
		t.Error("expected error for #10")
	}
	if info.PRNumbers[11] != 42 {
		t.Errorf("PRNumbers[11] = %d, want 42", info.PRNumbers[11])
	}
}

func TestContainsPackageName(t *testing.T) {
	tests := []struct {
		title   string
		pkgName string
		want    bool
	}{
		{"Bump lodash from 4.17.20 to 4.17.21", "lodash", true},
		{"Bump axios from 0.21.0 to 0.21.1", "lodash", false},
		{"Bump @types/node from 14.0.0 to 14.0.1", "@types/node", true},
		{"Update golang.org/x/crypto to v0.17.0", "golang.org/x/crypto", true},
		{"Some random PR", "lodash", false},
		{"Bump LODASH from 4.17.20 to 4.17.21", "lodash", true}, // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			got := containsPackageName(tt.title, tt.pkgName)
			if got != tt.want {
				t.Errorf("containsPackageName(%q, %q) = %v, want %v", tt.title, tt.pkgName, got, tt.want)
			}
		})
	}
}

// TestIsRepoActive は直近Nか月フィルタのロジックを確認
func TestIsRepoActive(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		pushedAt     time.Time
		activeMonths int
		want         bool
	}{
		{"activeMonths=0はフィルタなし（常にtrue）", now.AddDate(-2, 0, 0), 0, true},
		{"直近6か月: 1か月前はtrue", now.AddDate(0, -1, 0), 6, true},
		{"直近6か月: 5か月前はtrue", now.AddDate(0, -5, 0), 6, true},
		{"直近6か月: 7か月前はfalse", now.AddDate(0, -7, 0), 6, false},
		{"直近12か月: 11か月前はtrue", now.AddDate(0, -11, 0), 12, true},
		{"直近12か月: 13か月前はfalse", now.AddDate(0, -13, 0), 12, false},
		{"ゼロ値はfalse（pushedAtなし）", time.Time{}, 6, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRepoActive(tt.pushedAt, tt.activeMonths)
			if got != tt.want {
				t.Errorf("isRepoActive(%v, %d) = %v, want %v", tt.pushedAt, tt.activeMonths, got, tt.want)
			}
		})
	}
}

// TestFilterAlertsByActiveRepos は非活動リポジトリのアラートが除外されることを確認
func TestFilterAlertsByActiveRepos(t *testing.T) {
	now := time.Now()

	repoList := []repoListItem{
		{Name: "active-repo", IsArchived: false, PushedAt: now.AddDate(0, -1, 0)},  // 1か月前 → active
		{Name: "old-repo", IsArchived: false, PushedAt: now.AddDate(0, -13, 0)},    // 13か月前 → inactive
		{Name: "archived-repo", IsArchived: true, PushedAt: now.AddDate(0, -1, 0)}, // アーカイブ → inactive
	}

	alerts := []model.Alert{
		{Repo: "active-repo"},
		{Repo: "old-repo"},
		{Repo: "archived-repo"},
		{Repo: "unknown-repo"}, // リポ一覧にないもの → 除外
	}

	got := filterAlertsByActiveRepos(alerts, repoList, 12)
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1 (only active-repo)", len(got))
	}
	if got[0].Repo != "active-repo" {
		t.Errorf("Repo = %q, want %q", got[0].Repo, "active-repo")
	}
}

// TestFilterAlertsByActiveRepos_DisabledFilter はactiveMonths=0でフィルタ無効を確認
func TestFilterAlertsByActiveRepos_DisabledFilter(t *testing.T) {
	now := time.Now()
	repoList := []repoListItem{
		{Name: "old-repo", IsArchived: false, PushedAt: now.AddDate(-2, 0, 0)},
	}
	alerts := []model.Alert{
		{Repo: "old-repo"},
		{Repo: "other-repo"},
	}
	// activeMonths=0 → フィルタなし、全件返却
	got := filterAlertsByActiveRepos(alerts, repoList, 0)
	if len(got) != 2 {
		t.Fatalf("got %d alerts, want 2 (filter disabled)", len(got))
	}
}

// TestParseAlerts_DefaultBranch はorgAPIレスポンスのrepository.default_branchが正しく取得されることを確認
func TestParseAlerts_DefaultBranch(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "gh"}}
	jsonData := `[{
		"number": 1,
		"state": "open",
		"html_url": "https://github.com/owner/my-repo/security/dependabot/1",
		"created_at": "2024-01-01T00:00:00Z",
		"repository": {"name": "my-repo", "archived": false, "default_branch": "main"},
		"security_advisory": {
			"cve_id": "CVE-2024-1234",
			"summary": "Test",
			"identifiers": [],
			"cvss": {"score": 7.0},
			"cvss_severities": {}
		},
		"security_vulnerability": {
			"package": {"name": "lodash", "ecosystem": "npm"},
			"severity": "high",
			"first_patched_version": {"identifier": "1.0.1"}
		}
	}]`
	alerts, err := c.parseAlerts([]byte(jsonData), "owner", "", nil)
	if err != nil {
		t.Fatalf("parseAlerts() error = %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].DefaultBranch != "main" {
		t.Errorf("DefaultBranch = %q, want %q", alerts[0].DefaultBranch, "main")
	}
}

// TestBuildSeverityParam は最低重要度から GitHub API severity パラメータ文字列が正しく生成されることを確認
func TestBuildSeverityParam(t *testing.T) {
	tests := []struct {
		min  string
		want string
	}{
		{"critical", "critical"},
		{"high", "critical,high"},
		{"medium", "critical,high,medium"},
		{"low", ""},
		{"", ""},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.min, func(t *testing.T) {
			got := buildSeverityParam(tt.min)
			if got != tt.want {
				t.Errorf("buildSeverityParam(%q) = %q, want %q", tt.min, got, tt.want)
			}
		})
	}
}

// TestIsRateLimitMessage はレート制限メッセージの検出が正しく動作することを確認
func TestIsRateLimitMessage(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"you have exceeded a secondary rate limit", true},
		{"api rate limit exceeded for user", true},
		{"rate limit exceeded", true},
		{"resource not accessible by integration", false},
		{"403 forbidden", false},
		{"not found - 404", false},
		{"dependabot alerts are disabled for this repository", false},
	}
	for _, tc := range cases {
		got := isRateLimitMessage(tc.msg)
		if got != tc.want {
			t.Errorf("isRateLimitMessage(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// TestFetchRepoMetadata_Parallel は存在しないghパスでも panic せずゼロ値を返すことを確認
func TestFetchRepoMetadata_Parallel(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "/nonexistent/gh"}}
	ctx := context.Background()
	meta := c.fetchRepoMetadata(ctx, "owner", "repo")
	if meta.branch != "" {
		t.Errorf("branch = %q, want empty", meta.branch)
	}
	if meta.homepage != "" {
		t.Errorf("homepage = %q, want empty", meta.homepage)
	}
	if meta.contributors != nil {
		t.Errorf("contributors = %v, want nil", meta.contributors)
	}
}

// TestFetchRepoMetadata_ContextCancel はキャンセル済みコンテキストで速やかに完了しゼロ値を返すことを確認
func TestFetchRepoMetadata_ContextCancel(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "gh"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	meta := c.fetchRepoMetadata(ctx, "owner", "repo")
	if meta.branch != "" || meta.homepage != "" || meta.contributors != nil {
		t.Errorf("cancelled context should yield zero values, got branch=%q homepage=%q contributors=%v",
			meta.branch, meta.homepage, meta.contributors)
	}
}

// TestEnrichAndContributors_FieldIsolation は enrichUpdateErrors と fetchContributorsMap の並列実行で
// data race が起きないことを -race フラグ下で確認する
func TestEnrichAndContributors_FieldIsolation(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "/nonexistent/gh"}}
	ctx := context.Background()
	alerts := []model.Alert{
		{Repo: "repo-a", Number: 1},
		{Repo: "repo-b", Number: 2},
	}
	repoSet := map[string]struct{}{"repo-a": {}, "repo-b": {}}

	var (
		wg         sync.WaitGroup
		contribMap map[string][]string
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.enrichUpdateErrors(ctx, "owner", alerts)
	}()
	go func() {
		defer wg.Done()
		contribMap = c.fetchContributorsMap(ctx, "owner", repoSet)
	}()
	wg.Wait()

	if contribMap == nil {
		t.Error("contribMap should not be nil after fetchContributorsMap")
	}
}

// TestParseAlerts_Homepage はorgAPIレスポンスのrepository.homepageが正しく取得されることを確認
func TestParseAlerts_Homepage(t *testing.T) {
	c := &ghClient{cfg: &config.Config{GhPath: "gh"}}
	jsonData := `[{
		"number": 1,
		"state": "open",
		"html_url": "https://github.com/owner/my-repo/security/dependabot/1",
		"created_at": "2024-01-01T00:00:00Z",
		"repository": {"name": "my-repo", "archived": false, "default_branch": "main", "homepage": "https://example.com"},
		"security_advisory": {
			"cve_id": "CVE-2024-1234",
			"summary": "Test",
			"identifiers": [],
			"cvss": {"score": 7.0},
			"cvss_severities": {}
		},
		"security_vulnerability": {
			"package": {"name": "lodash", "ecosystem": "npm"},
			"severity": "high",
			"first_patched_version": {"identifier": "1.0.1"}
		}
	}]`
	alerts, err := c.parseAlerts([]byte(jsonData), "owner", "", nil)
	if err != nil {
		t.Fatalf("parseAlerts() error = %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(alerts))
	}
	if alerts[0].Homepage != "https://example.com" {
		t.Errorf("Homepage = %q, want %q", alerts[0].Homepage, "https://example.com")
	}
}

// TestParseContributorLogins はGitHub contributors APIレスポンスのJSONパースを確認
func TestParseContributorLogins(t *testing.T) {
	tests := []struct {
		name string
		data string
		want []string
	}{
		{
			name: "通常のコントリビューター一覧",
			data: `[{"login":"alice","contributions":100},{"login":"bob","contributions":50},{"login":"charlie","contributions":10}]`,
			want: []string{"alice", "bob", "charlie"},
		},
		{
			name: "空の配列は空スライス",
			data: `[]`,
			want: []string{},
		},
		{
			name: "loginが空のエントリはスキップ",
			data: `[{"login":"alice","contributions":100},{"login":"","contributions":5}]`,
			want: []string{"alice"},
		},
		{
			name: "不正なJSONはnil",
			data: `not json`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseContributorLogins([]byte(tt.data))
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got=%v", len(got), len(tt.want), got)
			}
			for i, v := range tt.want {
				if got[i] != v {
					t.Errorf("[%d] = %q, want %q", i, got[i], v)
				}
			}
		})
	}
}

// TestSupplementMetadata は repoList から DefaultBranch/Homepage が補完されることを確認
func TestSupplementMetadata(t *testing.T) {
	alerts := []model.Alert{
		{Repo: "repo-a", DefaultBranch: "", Homepage: ""},
		{Repo: "repo-b", DefaultBranch: "", Homepage: ""},
	}
	repoList := []repoListItem{
		{Name: "repo-a", DefaultBranchRef: struct {
			Name string `json:"name"`
		}{Name: "main"}, HomepageUrl: "https://example.com/a"},
		{Name: "repo-b", DefaultBranchRef: struct {
			Name string `json:"name"`
		}{Name: "develop"}, HomepageUrl: ""},
	}
	supplementMetadata(alerts, repoList)
	if alerts[0].DefaultBranch != "main" {
		t.Errorf("repo-a DefaultBranch = %q, want %q", alerts[0].DefaultBranch, "main")
	}
	if alerts[0].Homepage != "https://example.com/a" {
		t.Errorf("repo-a Homepage = %q, want %q", alerts[0].Homepage, "https://example.com/a")
	}
	if alerts[1].DefaultBranch != "develop" {
		t.Errorf("repo-b DefaultBranch = %q, want %q", alerts[1].DefaultBranch, "develop")
	}
	if alerts[1].Homepage != "" {
		t.Errorf("repo-b Homepage = %q, want empty", alerts[1].Homepage)
	}
}

// TestSupplementMetadata_NoOverwrite は既に値がある場合は上書きしないことを確認
func TestSupplementMetadata_NoOverwrite(t *testing.T) {
	alerts := []model.Alert{
		{Repo: "repo-a", DefaultBranch: "already-set", Homepage: "https://existing.com"},
	}
	repoList := []repoListItem{
		{Name: "repo-a", DefaultBranchRef: struct {
			Name string `json:"name"`
		}{Name: "main"}, HomepageUrl: "https://new.com"},
	}
	supplementMetadata(alerts, repoList)
	if alerts[0].DefaultBranch != "already-set" {
		t.Errorf("DefaultBranch should not be overwritten, got %q", alerts[0].DefaultBranch)
	}
	if alerts[0].Homepage != "https://existing.com" {
		t.Errorf("Homepage should not be overwritten, got %q", alerts[0].Homepage)
	}
}

func TestEqualFold(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"abc", "abc", true},
		{"ABC", "abc", true},
		{"abc", "ABC", true},
		{"abc", "abd", false},
		{"ab", "abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := equalFold(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("equalFold(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
