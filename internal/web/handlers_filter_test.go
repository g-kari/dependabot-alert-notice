package web

import (
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func makeRecord(owner, repo string) *model.AlertRecord {
	return &model.AlertRecord{
		Alert: model.Alert{
			ID:        1,
			Owner:     owner,
			Repo:      repo,
			Severity:  model.SeverityHigh,
			CreatedAt: time.Now(),
		},
		State: model.AlertStatePending,
	}
}

// TestFilterByConfig_NoExcludes は除外なしで全レコードが残ることを確認
func TestFilterByConfig_NoExcludes(t *testing.T) {
	records := []*model.AlertRecord{
		makeRecord("myorg", "repo1"),
		makeRecord("myorg", "repo2"),
	}
	cfg := &config.Config{
		Targets: []config.Target{
			{Owner: "myorg"},
		},
	}
	got := filterByConfig(records, cfg)
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

// TestFilterByConfig_ExcludesRepo はExcludesに含まれるrepoが除外されることを確認
func TestFilterByConfig_ExcludesRepo(t *testing.T) {
	records := []*model.AlertRecord{
		makeRecord("myorg", "repo1"),
		makeRecord("myorg", "repo2"),
		makeRecord("myorg", "repo3"),
	}
	cfg := &config.Config{
		Targets: []config.Target{
			{Owner: "myorg", Excludes: []string{"repo2"}},
		},
	}
	got := filterByConfig(records, cfg)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for _, r := range got {
		if r.Alert.Repo == "repo2" {
			t.Error("repo2 should be excluded")
		}
	}
}

// TestFilterByConfig_MultipleExcludes は複数excludeが全て除外されることを確認
func TestFilterByConfig_MultipleExcludes(t *testing.T) {
	records := []*model.AlertRecord{
		makeRecord("myorg", "repo1"),
		makeRecord("myorg", "repo2"),
		makeRecord("myorg", "repo3"),
	}
	cfg := &config.Config{
		Targets: []config.Target{
			{Owner: "myorg", Excludes: []string{"repo1", "repo3"}},
		},
	}
	got := filterByConfig(records, cfg)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Alert.Repo != "repo2" {
		t.Errorf("Repo = %q, want repo2", got[0].Alert.Repo)
	}
}

// TestFilterByConfig_DifferentOwner は別ownerのアラートに影響しないことを確認
func TestFilterByConfig_DifferentOwner(t *testing.T) {
	records := []*model.AlertRecord{
		makeRecord("org1", "repo1"),
		makeRecord("org2", "repo1"),
	}
	cfg := &config.Config{
		Targets: []config.Target{
			{Owner: "org1", Excludes: []string{"repo1"}},
			{Owner: "org2"},
		},
	}
	got := filterByConfig(records, cfg)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Alert.Owner != "org2" {
		t.Errorf("Owner = %q, want org2", got[0].Alert.Owner)
	}
}

// TestFilterByConfig_OwnerNotInTargets はターゲットに含まれないownerのアラートはそのまま表示されることを確認
func TestFilterByConfig_OwnerNotInTargets(t *testing.T) {
	records := []*model.AlertRecord{
		makeRecord("myorg", "repo1"),
		makeRecord("unknown-org", "repo1"),
	}
	cfg := &config.Config{
		Targets: []config.Target{
			{Owner: "myorg"},
		},
	}
	got := filterByConfig(records, cfg)
	// ターゲット設定外のownerもそのまま表示される
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
}

// TestFilterByConfig_EmptyTargets はターゲットが空のとき全レコードが表示されることを確認
func TestFilterByConfig_EmptyTargets(t *testing.T) {
	records := []*model.AlertRecord{
		makeRecord("myorg", "repo1"),
	}
	cfg := &config.Config{}
	got := filterByConfig(records, cfg)
	if len(got) != 1 {
		t.Errorf("len = %d, want 1 (no excludes configured)", len(got))
	}
}
