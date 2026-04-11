package github

import (
	"testing"
)

func TestParseAlerts_CVEFromTopLevel(t *testing.T) {
	c := &ghClient{ghPath: "gh"}
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
	c := &ghClient{ghPath: "gh"}
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
	c := &ghClient{ghPath: "gh"}
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
	c := &ghClient{ghPath: "gh"}
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
