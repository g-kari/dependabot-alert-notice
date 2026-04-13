package web

import (
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestGroupByCVE_Empty(t *testing.T) {
	groups := groupByCVE(nil)
	if len(groups) != 0 {
		t.Errorf("groups = %d, want 0", len(groups))
	}
}

func TestGroupByCVE_SingleRecord(t *testing.T) {
	records := []*model.AlertRecord{
		{
			Alert: model.Alert{
				ID:          1,
				PackageName: "lodash",
				Owner:       "testorg",
				Repo:        "repo1",
				Severity:    model.SeverityHigh,
				CVEID:       "CVE-2024-0001",
				CVSSScore:   7.5,
				Summary:     "Prototype pollution",
				CreatedAt:   time.Now(),
			},
			State: model.AlertStatePending,
		},
	}
	groups := groupByCVE(records)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if groups[0].CVEID != "CVE-2024-0001" {
		t.Errorf("CVEID = %q, want CVE-2024-0001", groups[0].CVEID)
	}
	if groups[0].PackageName != "lodash" {
		t.Errorf("PackageName = %q, want lodash", groups[0].PackageName)
	}
	if len(groups[0].Records) != 1 {
		t.Errorf("Records len = %d, want 1", len(groups[0].Records))
	}
}

func TestGroupByCVE_SameCVEMultipleRepos(t *testing.T) {
	now := time.Now()
	records := []*model.AlertRecord{
		{
			Alert: model.Alert{
				ID:          1,
				PackageName: "lodash",
				Owner:       "testorg",
				Repo:        "repo1",
				Severity:    model.SeverityHigh,
				CVEID:       "CVE-2024-0001",
				CVSSScore:   7.5,
				CreatedAt:   now.Add(-2 * time.Hour),
			},
			State: model.AlertStatePending,
		},
		{
			Alert: model.Alert{
				ID:          2,
				PackageName: "lodash",
				Owner:       "testorg",
				Repo:        "repo2",
				Severity:    model.SeverityHigh,
				CVEID:       "CVE-2024-0001",
				CVSSScore:   7.5,
				CreatedAt:   now,
			},
			State: model.AlertStatePending,
		},
	}
	groups := groupByCVE(records)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1 (same CVE should be merged)", len(groups))
	}
	if len(groups[0].Records) != 2 {
		t.Errorf("Records len = %d, want 2", len(groups[0].Records))
	}
	// CreatedAt降順: repo2（新しい）が先
	if groups[0].Records[0].Alert.Repo != "repo2" {
		t.Errorf("Records[0].Repo = %q, want repo2 (newer first)", groups[0].Records[0].Alert.Repo)
	}
}

func TestGroupByCVE_EmptyCVEID(t *testing.T) {
	records := []*model.AlertRecord{
		{
			Alert: model.Alert{
				ID:          1,
				PackageName: "pkg1",
				Owner:       "testorg",
				Repo:        "repo1",
				Severity:    model.SeverityLow,
				CVEID:       "",
				GHSAID:      "",
				CreatedAt:   time.Now(),
			},
			State: model.AlertStatePending,
		},
		{
			Alert: model.Alert{
				ID:          2,
				PackageName: "pkg2",
				Owner:       "testorg",
				Repo:        "repo2",
				Severity:    model.SeverityLow,
				CVEID:       "",
				GHSAID:      "",
				CreatedAt:   time.Now(),
			},
			State: model.AlertStatePending,
		},
	}
	groups := groupByCVE(records)
	// CVE ID・GHSA IDが両方空のアラートは個別グループになる
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2 (empty CVE/GHSA IDs should not be merged)", len(groups))
	}
}

// TestGroupByCVE_SameGHSANoCV はCVEなし・同一GHSAのアラートが1グループにまとまることを確認
func TestGroupByCVE_SameGHSANoCV(t *testing.T) {
	now := time.Now()
	records := []*model.AlertRecord{
		{
			Alert: model.Alert{
				ID:          1,
				PackageName: "pkg-a",
				Owner:       "testorg",
				Repo:        "repo1",
				Severity:    model.SeverityHigh,
				CVEID:       "",
				GHSAID:      "GHSA-xxxx-yyyy-zzzz",
				CVSSScore:   7.5,
				CreatedAt:   now.Add(-time.Hour),
			},
			State: model.AlertStatePending,
		},
		{
			Alert: model.Alert{
				ID:          2,
				PackageName: "pkg-a",
				Owner:       "testorg",
				Repo:        "repo2",
				Severity:    model.SeverityHigh,
				CVEID:       "",
				GHSAID:      "GHSA-xxxx-yyyy-zzzz",
				CVSSScore:   7.5,
				CreatedAt:   now,
			},
			State: model.AlertStatePending,
		},
	}
	groups := groupByCVE(records)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1 (same GHSA should be grouped)", len(groups))
	}
	if len(groups[0].Records) != 2 {
		t.Errorf("Records len = %d, want 2", len(groups[0].Records))
	}
	if groups[0].GHSAID != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("GHSAID = %q, want GHSA-xxxx-yyyy-zzzz", groups[0].GHSAID)
	}
	if groups[0].CVEID != "" {
		t.Errorf("CVEID = %q, want empty", groups[0].CVEID)
	}
}

// TestGroupByCVE_DifferentGHSANoCV は異なるGHSAが別グループになることを確認
func TestGroupByCVE_DifferentGHSANoCV(t *testing.T) {
	records := []*model.AlertRecord{
		{
			Alert: model.Alert{
				ID: 1, PackageName: "pkg-a", Repo: "repo1",
				Severity: model.SeverityHigh, CVEID: "", GHSAID: "GHSA-aaaa-bbbb-cccc",
				CreatedAt: time.Now(),
			},
		},
		{
			Alert: model.Alert{
				ID: 2, PackageName: "pkg-b", Repo: "repo2",
				Severity: model.SeverityMedium, CVEID: "", GHSAID: "GHSA-dddd-eeee-ffff",
				CreatedAt: time.Now(),
			},
		},
	}
	groups := groupByCVE(records)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2 (different GHSAs are separate groups)", len(groups))
	}
}

func TestGroupByCVE_Sorting(t *testing.T) {
	records := []*model.AlertRecord{
		{
			Alert: model.Alert{
				ID:          1,
				PackageName: "pkg-low",
				Owner:       "testorg",
				Repo:        "repo1",
				Severity:    model.SeverityLow,
				CVEID:       "CVE-2024-0003",
				CVSSScore:   2.0,
				CreatedAt:   time.Now(),
			},
		},
		{
			Alert: model.Alert{
				ID:          2,
				PackageName: "pkg-critical",
				Owner:       "testorg",
				Repo:        "repo2",
				Severity:    model.SeverityCritical,
				CVEID:       "CVE-2024-0001",
				CVSSScore:   9.8,
				CreatedAt:   time.Now(),
			},
		},
		{
			Alert: model.Alert{
				ID:          3,
				PackageName: "pkg-high",
				Owner:       "testorg",
				Repo:        "repo3",
				Severity:    model.SeverityHigh,
				CVEID:       "CVE-2024-0002",
				CVSSScore:   7.5,
				CreatedAt:   time.Now(),
			},
		},
	}
	groups := groupByCVE(records)
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3", len(groups))
	}
	// critical > high > low の順
	if groups[0].CVEID != "CVE-2024-0001" {
		t.Errorf("groups[0].CVEID = %q, want CVE-2024-0001 (critical)", groups[0].CVEID)
	}
	if groups[1].CVEID != "CVE-2024-0002" {
		t.Errorf("groups[1].CVEID = %q, want CVE-2024-0002 (high)", groups[1].CVEID)
	}
	if groups[2].CVEID != "CVE-2024-0003" {
		t.Errorf("groups[2].CVEID = %q, want CVE-2024-0003 (low)", groups[2].CVEID)
	}
}

func TestGroupByCVE_SortByCVSSWhenSameSeverity(t *testing.T) {
	records := []*model.AlertRecord{
		{
			Alert: model.Alert{
				ID:        1,
				CVEID:     "CVE-2024-AAA",
				Severity:  model.SeverityHigh,
				CVSSScore: 7.0,
				CreatedAt: time.Now(),
			},
		},
		{
			Alert: model.Alert{
				ID:        2,
				CVEID:     "CVE-2024-BBB",
				Severity:  model.SeverityHigh,
				CVSSScore: 8.5,
				CreatedAt: time.Now(),
			},
		},
	}
	groups := groupByCVE(records)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	// 同じSeverityならCVSS降順
	if groups[0].CVEID != "CVE-2024-BBB" {
		t.Errorf("groups[0].CVEID = %q, want CVE-2024-BBB (higher CVSS)", groups[0].CVEID)
	}
}
