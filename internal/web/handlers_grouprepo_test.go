package web

import (
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func makeRepoRecord(id int, owner, repo string, sev model.Severity, cvss float64, cveID string, createdAt time.Time) *model.AlertRecord {
	return &model.AlertRecord{
		Alert: model.Alert{
			ID:        id,
			Owner:     owner,
			Repo:      repo,
			Severity:  sev,
			CVSSScore: cvss,
			CVEID:     cveID,
			CreatedAt: createdAt,
		},
		State:      model.AlertStatePending,
		EvalStatus: model.EvalStatusPending,
	}
}

func TestGroupByRepo_Empty(t *testing.T) {
	groups := groupByRepo(nil)
	if len(groups) != 0 {
		t.Errorf("groupByRepo(nil) returned %d groups, want 0", len(groups))
	}
	groups = groupByRepo([]*model.AlertRecord{})
	if len(groups) != 0 {
		t.Errorf("groupByRepo([]) returned %d groups, want 0", len(groups))
	}
}

func TestGroupByRepo_SingleRecord(t *testing.T) {
	now := time.Now()
	records := []*model.AlertRecord{
		makeRepoRecord(1, "owner", "repo-a", model.SeverityHigh, 7.5, "CVE-2024-1", now),
	}
	groups := groupByRepo(records)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Owner != "owner" || groups[0].Repo != "repo-a" {
		t.Errorf("group = %v/%v, want owner/repo-a", groups[0].Owner, groups[0].Repo)
	}
	if len(groups[0].Records) != 1 {
		t.Errorf("group has %d records, want 1", len(groups[0].Records))
	}
}

func TestGroupByRepo_SameRepoMultipleAlerts(t *testing.T) {
	now := time.Now()
	records := []*model.AlertRecord{
		makeRepoRecord(1, "owner", "repo-a", model.SeverityHigh, 7.5, "CVE-2024-1", now),
		makeRepoRecord(2, "owner", "repo-a", model.SeverityMedium, 5.0, "CVE-2024-2", now.Add(-time.Hour)),
		makeRepoRecord(3, "owner", "repo-b", model.SeverityLow, 3.0, "", now),
	}
	groups := groupByRepo(records)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	// repo-a は2件、repo-b は1件
	found := false
	for _, g := range groups {
		if g.Repo == "repo-a" {
			found = true
			if len(g.Records) != 2 {
				t.Errorf("repo-a has %d records, want 2", len(g.Records))
			}
		}
	}
	if !found {
		t.Error("repo-a group not found")
	}
}

func TestGroupByRepo_SortBySeverity(t *testing.T) {
	now := time.Now()
	records := []*model.AlertRecord{
		makeRepoRecord(1, "owner", "low-repo", model.SeverityLow, 2.0, "", now),
		makeRepoRecord(2, "owner", "critical-repo", model.SeverityCritical, 9.8, "CVE-2024-1", now),
		makeRepoRecord(3, "owner", "medium-repo", model.SeverityMedium, 5.0, "", now),
	}
	groups := groupByRepo(records)
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3", len(groups))
	}
	if groups[0].Repo != "critical-repo" {
		t.Errorf("first group = %q, want critical-repo", groups[0].Repo)
	}
	if groups[2].Repo != "low-repo" {
		t.Errorf("last group = %q, want low-repo", groups[2].Repo)
	}
}

func TestGroupByRepo_SortByCVSSWhenSameSeverity(t *testing.T) {
	now := time.Now()
	records := []*model.AlertRecord{
		makeRepoRecord(1, "owner", "low-cvss-repo", model.SeverityHigh, 7.0, "", now),
		makeRepoRecord(2, "owner", "high-cvss-repo", model.SeverityHigh, 9.0, "", now),
	}
	groups := groupByRepo(records)
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}
	if groups[0].Repo != "high-cvss-repo" {
		t.Errorf("first group = %q, want high-cvss-repo", groups[0].Repo)
	}
}

func TestGroupByRepo_MaxSeverityFromRecords(t *testing.T) {
	now := time.Now()
	records := []*model.AlertRecord{
		makeRepoRecord(1, "owner", "repo-a", model.SeverityLow, 2.0, "", now),
		makeRepoRecord(2, "owner", "repo-a", model.SeverityCritical, 9.8, "CVE-2024-1", now.Add(-time.Hour)),
	}
	groups := groupByRepo(records)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].MaxSeverity != model.SeverityCritical {
		t.Errorf("MaxSeverity = %q, want critical", groups[0].MaxSeverity)
	}
}

func TestGroupByRepo_RecordsOrderedByCreatedAt(t *testing.T) {
	older := time.Now().Add(-2 * time.Hour)
	newer := time.Now()
	records := []*model.AlertRecord{
		makeRepoRecord(1, "owner", "repo-a", model.SeverityHigh, 7.0, "", older),
		makeRepoRecord(2, "owner", "repo-a", model.SeverityHigh, 7.0, "", newer),
	}
	groups := groupByRepo(records)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	// 新しい順
	if !groups[0].Records[0].Alert.CreatedAt.Equal(newer) {
		t.Errorf("first record should be newer, got %v", groups[0].Records[0].Alert.CreatedAt)
	}
}
