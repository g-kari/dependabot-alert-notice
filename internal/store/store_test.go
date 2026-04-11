package store

import (
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestSaveAndGet(t *testing.T) {
	s := New()

	record := &model.AlertRecord{
		Alert: model.Alert{
			Number:      1,
			PackageName: "lodash",
			Owner:       "test-org",
			Repo:        "test-repo",
			Severity:    model.SeverityHigh,
		},
		State:      model.AlertStatePending,
		NotifiedAt: time.Now(),
	}

	s.Save(record)
	if record.Alert.ID == 0 {
		t.Fatal("Save() should assign internal ID")
	}

	got, err := s.Get(record.Alert.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Alert.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want %q", got.Alert.PackageName, "lodash")
	}
}

func TestGetNotFound(t *testing.T) {
	s := New()
	_, err := s.Get(999)
	if err == nil {
		t.Error("Get() should return error for non-existent ID")
	}
}

func TestHas(t *testing.T) {
	s := New()
	if s.HasByKey("org", "repo", 1) {
		t.Error("HasByKey() should return false for empty store")
	}

	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1},
		State: model.AlertStatePending,
	})

	if !s.HasByKey("org", "repo", 1) {
		t.Error("HasByKey() should return true after Save()")
	}
}

func TestUpdateState(t *testing.T) {
	s := New()
	r := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1},
		State: model.AlertStatePending,
	}
	s.Save(r)

	if err := s.UpdateState(r.Alert.ID, model.AlertStateMerged); err != nil {
		t.Fatalf("UpdateState() error = %v", err)
	}

	got, _ := s.Get(r.Alert.ID)
	if got.State != model.AlertStateMerged {
		t.Errorf("State = %q, want %q", got.State, model.AlertStateMerged)
	}
	if got.MergedAt == nil {
		t.Error("MergedAt should be set when state is merged")
	}
}

func TestUpdateStateNotFound(t *testing.T) {
	s := New()
	err := s.UpdateState(999, model.AlertStateMerged)
	if err == nil {
		t.Error("UpdateState() should return error for non-existent ID")
	}
}

func TestList(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, State: model.AlertStatePending})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, State: model.AlertStatePending})

	list := s.List()
	if len(list) != 2 {
		t.Errorf("List() len = %d, want 2", len(list))
	}
}

func TestEvalStatusSaveAndGet(t *testing.T) {
	s := New()

	record := &model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo", Number: 10, PackageName: "axios"},
		State:      model.AlertStatePending,
		EvalStatus: model.EvalStatusEvaluating,
		NotifiedAt: time.Now(),
	}
	s.Save(record)

	got, err := s.Get(record.Alert.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.EvalStatus != model.EvalStatusEvaluating {
		t.Errorf("EvalStatus = %q, want %q", got.EvalStatus, model.EvalStatusEvaluating)
	}
}

func TestUpdateEvalStatus(t *testing.T) {
	s := New()
	r := &model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo", Number: 20},
		State:      model.AlertStatePending,
		EvalStatus: model.EvalStatusEvaluating,
	}
	s.Save(r)

	if err := s.UpdateEvalStatus(r.Alert.ID, model.EvalStatusFailed); err != nil {
		t.Fatalf("UpdateEvalStatus() error = %v", err)
	}

	got, _ := s.Get(r.Alert.ID)
	if got.EvalStatus != model.EvalStatusFailed {
		t.Errorf("EvalStatus = %q, want %q", got.EvalStatus, model.EvalStatusFailed)
	}
}

func TestUpdateEvalStatusNotFound(t *testing.T) {
	s := New()
	err := s.UpdateEvalStatus(999, model.EvalStatusDone)
	if err == nil {
		t.Error("UpdateEvalStatus() should return error for non-existent ID")
	}
}

func TestNeedsEvaluation(t *testing.T) {
	s := New()

	// 存在しない → true
	if !s.NeedsEvaluation(9999) {
		t.Error("NeedsEvaluation() should return true for non-existent alert")
	}

	// evaluating → false（評価中はスキップ）
	r1 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, EvalStatus: model.EvalStatusEvaluating}
	s.Save(r1)
	if s.NeedsEvaluation(r1.Alert.ID) {
		t.Error("NeedsEvaluation() should return false for evaluating alert")
	}

	// done → false
	r2 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, EvalStatus: model.EvalStatusDone}
	s.Save(r2)
	if s.NeedsEvaluation(r2.Alert.ID) {
		t.Error("NeedsEvaluation() should return false for done alert")
	}

	// failed → true（再試行対象）
	r3 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 3}, EvalStatus: model.EvalStatusFailed}
	s.Save(r3)
	if !s.NeedsEvaluation(r3.Alert.ID) {
		t.Error("NeedsEvaluation() should return true for failed alert")
	}
}

func TestListIncludesEvalStatus(t *testing.T) {
	s := New()
	r1 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, EvalStatus: model.EvalStatusEvaluating}
	r2 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, EvalStatus: model.EvalStatusFailed}
	s.Save(r1)
	s.Save(r2)

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("List() len = %d, want 2", len(list))
	}
	statuses := map[int]model.EvalStatus{}
	for _, r := range list {
		statuses[r.Alert.ID] = r.EvalStatus
	}
	if statuses[r1.Alert.ID] != model.EvalStatusEvaluating {
		t.Errorf("r1 EvalStatus = %q, want evaluating", statuses[r1.Alert.ID])
	}
	if statuses[r2.Alert.ID] != model.EvalStatusFailed {
		t.Errorf("r2 EvalStatus = %q, want failed", statuses[r2.Alert.ID])
	}
}

func TestListPendingEvaluation(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, EvalStatus: model.EvalStatusPending})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, EvalStatus: model.EvalStatusFailed})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 3}, EvalStatus: model.EvalStatusDone})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 4}, EvalStatus: model.EvalStatusEvaluating})
	s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 5}, EvalStatus: model.EvalStatusPending})

	got := s.ListPendingEvaluation(10)
	if len(got) != 3 { // pending x2 + failed x1
		t.Errorf("ListPendingEvaluation() len = %d, want 3", len(got))
	}

	// limit が効くか
	got2 := s.ListPendingEvaluation(2)
	if len(got2) != 2 {
		t.Errorf("ListPendingEvaluation(2) len = %d, want 2", len(got2))
	}
}

// TestSave_SameNumberDifferentRepos は同じアラート番号でも別リポジトリなら別レコードとして保存されることを確認
func TestSave_SameNumberDifferentRepos(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repoA", Number: 6},
		State: model.AlertStatePending,
	})
	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repoB", Number: 6},
		State: model.AlertStatePending,
	})
	list := s.List()
	if len(list) != 2 {
		t.Errorf("List() len = %d, want 2 (同番号でも別リポは別レコード)", len(list))
	}
}

// TestHasByKey は HasByKey が (owner, repo, number) の組み合わせで重複チェックすることを確認
func TestHasByKey(t *testing.T) {
	s := New()
	if s.HasByKey("org", "repo", 1) {
		t.Error("HasByKey() should return false for empty store")
	}
	record := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1},
		State: model.AlertStatePending,
	}
	s.Save(record)
	if !s.HasByKey("org", "repo", 1) {
		t.Error("HasByKey() should return true after Save()")
	}
	if s.HasByKey("org", "other-repo", 1) {
		t.Error("HasByKey() should return false for different repo with same number")
	}
}

// TestSave_AssignsInternalID は Save後にAuto-increment内部IDが record.Alert.ID にセットされることを確認
func TestSave_AssignsInternalID(t *testing.T) {
	s := New()
	r1 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, State: model.AlertStatePending}
	r2 := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, State: model.AlertStatePending}
	s.Save(r1)
	s.Save(r2)
	if r1.Alert.ID == 0 {
		t.Error("Save() should assign internal ID to r1.Alert.ID")
	}
	if r2.Alert.ID == 0 {
		t.Error("Save() should assign internal ID to r2.Alert.ID")
	}
	if r1.Alert.ID == r2.Alert.ID {
		t.Error("Save() should assign distinct internal IDs")
	}
}

// TestFindEvalByCVE は同一CVEの評価済み結果を返す
func TestFindEvalByCVE_NoMatch(t *testing.T) {
	s := New()
	if s.FindEvalByCVE("CVE-2024-0001") != nil {
		t.Error("FindEvalByCVE() should return nil for empty store")
	}
}

func TestFindEvalByCVE_EmptyCVEID(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo", Number: 1, CVEID: ""},
		Evaluation: &model.Evaluation{Impact: "test", Recommendation: "approve", Reasoning: "ok"},
		EvalStatus: model.EvalStatusDone,
	})
	if s.FindEvalByCVE("") != nil {
		t.Error("FindEvalByCVE(\"\") should return nil to prevent empty-CVE matching")
	}
}

func TestFindEvalByCVE_MatchExists(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, CVEID: "CVE-2024-0001"},
		Evaluation: &model.Evaluation{
			Impact:         "• data leak\n• RCE",
			Recommendation: "approve",
			Reasoning:      "• used with eval()",
		},
		EvalStatus: model.EvalStatusDone,
	})

	eval := s.FindEvalByCVE("CVE-2024-0001")
	if eval == nil {
		t.Fatal("FindEvalByCVE() should return evaluation for existing CVE")
	}
	if eval.Recommendation != "approve" {
		t.Errorf("Recommendation = %q, want approve", eval.Recommendation)
	}
	if eval.Impact != "• data leak\n• RCE" {
		t.Errorf("Impact = %q, want bullet list", eval.Impact)
	}
}

func TestFindEvalByCVE_NoEvalJSON(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo", Number: 1, CVEID: "CVE-2024-0001"},
		EvalStatus: model.EvalStatusPending,
	})
	if s.FindEvalByCVE("CVE-2024-0001") != nil {
		t.Error("FindEvalByCVE() should return nil when eval_json is NULL")
	}
}

func TestFindEvalByCVE_DifferentCVE(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo", Number: 1, CVEID: "CVE-2024-AAAA"},
		Evaluation: &model.Evaluation{Recommendation: "approve"},
		EvalStatus: model.EvalStatusDone,
	})
	if s.FindEvalByCVE("CVE-2024-BBBB") != nil {
		t.Error("FindEvalByCVE() should return nil for different CVE")
	}
}

func TestFindEvalByCVE_SameCVEMultipleRepos(t *testing.T) {
	s := New()
	// repo1: 評価なし
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo1", Number: 1, CVEID: "CVE-2024-0001"},
		EvalStatus: model.EvalStatusPending,
	})
	// repo2: 評価済み
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo2", Number: 1, CVEID: "CVE-2024-0001"},
		Evaluation: &model.Evaluation{Recommendation: "manual-review", Impact: "test"},
		EvalStatus: model.EvalStatusDone,
	})

	eval := s.FindEvalByCVE("CVE-2024-0001")
	if eval == nil {
		t.Fatal("FindEvalByCVE() should find the eval from repo2")
	}
	if eval.Recommendation != "manual-review" {
		t.Errorf("Recommendation = %q, want manual-review", eval.Recommendation)
	}
}

func TestFindEvalByCVE_SkipsFailedStatus(t *testing.T) {
	s := New()
	// eval_json はあるが eval_status = 'failed' のレコード
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo1", Number: 1, CVEID: "CVE-2024-9999"},
		Evaluation: &model.Evaluation{Recommendation: "approve"},
		EvalStatus: model.EvalStatusFailed,
	})

	eval := s.FindEvalByCVE("CVE-2024-9999")
	if eval != nil {
		t.Error("FindEvalByCVE() should return nil for failed eval_status")
	}
}

func TestFindEvalByCVE_ReturnsNewestWhenMultiple(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo1", Number: 1, CVEID: "CVE-2024-1111"},
		Evaluation: &model.Evaluation{Recommendation: "reject"},
		EvalStatus: model.EvalStatusDone,
	})
	s.Save(&model.AlertRecord{
		Alert:      model.Alert{Owner: "org", Repo: "repo2", Number: 1, CVEID: "CVE-2024-1111"},
		Evaluation: &model.Evaluation{Recommendation: "approve"},
		EvalStatus: model.EvalStatusDone,
	})

	eval := s.FindEvalByCVE("CVE-2024-1111")
	if eval == nil {
		t.Fatal("FindEvalByCVE() should return an eval")
	}
	// ORDER BY id DESC で最新（repo2のapprove）が返るはず
	if eval.Recommendation != "approve" {
		t.Errorf("Recommendation = %q, want approve (newest)", eval.Recommendation)
	}
}

func saveTestAlert(s *Store, owner, repo string, number int) *model.AlertRecord {
	rec := &model.AlertRecord{
		Alert: model.Alert{
			Number:      number,
			Owner:       owner,
			Repo:        repo,
			PackageName: "pkg-" + repo,
			Severity:    model.SeverityHigh,
		},
		State:      model.AlertStatePending,
		EvalStatus: model.EvalStatusPending,
		NotifiedAt: time.Now(),
	}
	s.Save(rec)
	return rec
}

func TestRemoveResolvedAlerts_RemovesClosedAlerts(t *testing.T) {
	s := New()
	saveTestAlert(s, "org", "repo1", 1)
	saveTestAlert(s, "org", "repo1", 2)
	saveTestAlert(s, "org", "repo1", 3)

	// #1,#2 はまだ open、#3 は GitHub で close された
	removed := s.RemoveResolvedAlerts("org", "repo1", []int{1, 2})
	if len(removed) != 1 {
		t.Fatalf("removed = %d, want 1", len(removed))
	}
	if removed[0].Alert.Number != 3 {
		t.Errorf("removed[0].Number = %d, want 3", removed[0].Alert.Number)
	}
	// DB に #3 が残っていないこと
	if s.HasByKey("org", "repo1", 3) {
		t.Error("#3 はまだ DB に残っている")
	}
	// #1, #2 は残っていること
	if !s.HasByKey("org", "repo1", 1) || !s.HasByKey("org", "repo1", 2) {
		t.Error("#1 or #2 が消えた")
	}
}

func TestRemoveResolvedAlerts_NoOpenAlerts(t *testing.T) {
	s := New()
	saveTestAlert(s, "org", "repo1", 1)
	saveTestAlert(s, "org", "repo1", 2)

	// 全アラートが close された
	removed := s.RemoveResolvedAlerts("org", "repo1", nil)
	if len(removed) != 2 {
		t.Fatalf("removed = %d, want 2", len(removed))
	}
}

func TestRemoveResolvedAlerts_AllStillOpen(t *testing.T) {
	s := New()
	saveTestAlert(s, "org", "repo1", 1)
	saveTestAlert(s, "org", "repo1", 2)

	removed := s.RemoveResolvedAlerts("org", "repo1", []int{1, 2})
	if len(removed) != 0 {
		t.Fatalf("removed = %d, want 0", len(removed))
	}
}

func TestRemoveResolvedAlerts_DifferentRepo(t *testing.T) {
	s := New()
	saveTestAlert(s, "org", "repo1", 1)
	saveTestAlert(s, "org", "repo2", 1)

	// repo1 のみ cleanup → repo2 は影響なし
	removed := s.RemoveResolvedAlerts("org", "repo1", nil)
	if len(removed) != 1 {
		t.Fatalf("removed = %d, want 1", len(removed))
	}
	if !s.HasByKey("org", "repo2", 1) {
		t.Error("repo2 の #1 が消えた")
	}
}

func TestRemoveResolvedAlerts_ReturnsSlackTS(t *testing.T) {
	s := New()
	rec := saveTestAlert(s, "org", "repo1", 1)
	_ = s.UpdateSlackMessageTS(rec.Alert.ID, "1234567890.123456")

	removed := s.RemoveResolvedAlerts("org", "repo1", nil)
	if len(removed) != 1 {
		t.Fatalf("removed = %d, want 1", len(removed))
	}
	if removed[0].SlackMessageTS != "1234567890.123456" {
		t.Errorf("SlackMessageTS = %q, want 1234567890.123456", removed[0].SlackMessageTS)
	}
}

func TestUpdateDiscordMessageID(t *testing.T) {
	s := New()
	rec := saveTestAlert(s, "org", "repo1", 1)

	if err := s.UpdateDiscordMessageID(rec.Alert.ID, "discord-msg-123"); err != nil {
		t.Fatalf("UpdateDiscordMessageID: %v", err)
	}

	got, err := s.Get(rec.Alert.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DiscordMessageID != "discord-msg-123" {
		t.Errorf("DiscordMessageID = %q, want discord-msg-123", got.DiscordMessageID)
	}
}

func TestAddLogAndListLogs(t *testing.T) {
	s := New()
	s.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "info", Message: "test1"})
	s.AddLog(model.LogEntry{Timestamp: time.Now(), Level: "error", Message: "test2"})

	logs := s.ListLogs()
	if len(logs) != 2 {
		t.Errorf("ListLogs() len = %d, want 2", len(logs))
	}
}

// TestListReposByOwner はオーナー配下のリポジトリ一覧を返すことを確認
func TestListReposByOwner(t *testing.T) {
	s := New()
	saveTestAlert(s, "org1", "repo-a", 1)
	saveTestAlert(s, "org1", "repo-b", 1)
	saveTestAlert(s, "org1", "repo-b", 2) // 重複リポ（DISTINCT確認用）
	saveTestAlert(s, "org2", "repo-c", 1) // 別オーナー（含まれないこと確認）

	repos := s.ListReposByOwner("org1")
	if len(repos) != 2 {
		t.Errorf("ListReposByOwner(org1) len = %d, want 2", len(repos))
	}
	repoSet := make(map[string]bool)
	for _, r := range repos {
		repoSet[r] = true
	}
	if !repoSet["repo-a"] {
		t.Error("expected repo-a in result")
	}
	if !repoSet["repo-b"] {
		t.Error("expected repo-b in result")
	}
}

// TestListReposByOwner_EmptyOwner はオーナーが空のとき空スライスを返すことを確認
func TestListReposByOwner_EmptyOwner(t *testing.T) {
	s := New()
	saveTestAlert(s, "org1", "repo-a", 1)

	repos := s.ListReposByOwner("")
	if len(repos) != 0 {
		t.Errorf("ListReposByOwner(\"\") should return empty, got %d items", len(repos))
	}
}

// TestListReposByOwner_NoRecords はレコードがないとき空スライスを返すことを確認
func TestListReposByOwner_NoRecords(t *testing.T) {
	s := New()
	repos := s.ListReposByOwner("org1")
	if repos == nil {
		t.Error("expected non-nil slice")
	}
	if len(repos) != 0 {
		t.Errorf("expected 0 repos, got %d", len(repos))
	}
}

// TestListByPRNumber_MatchesSameRepoPR は同repo同PR番号のアラートを正しく返すことを確認
func TestListByPRNumber_MatchesSameRepoPR(t *testing.T) {
	s := New()
	r1 := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, PRNumber: 42},
		State: model.AlertStatePending,
	}
	r2 := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2, PRNumber: 42},
		State: model.AlertStatePending,
	}
	r3 := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 3, PRNumber: 99},
		State: model.AlertStatePending,
	}
	s.Save(r1)
	s.Save(r2)
	s.Save(r3)

	result := s.ListByPRNumber("org", "repo", 42)
	if len(result) != 2 {
		t.Fatalf("ListByPRNumber(42) len = %d, want 2", len(result))
	}
	nums := map[int]bool{}
	for _, r := range result {
		nums[r.Alert.Number] = true
	}
	if !nums[1] || !nums[2] {
		t.Errorf("expected alerts #1 and #2, got %v", nums)
	}
	if nums[3] {
		t.Error("alert #3 (PRNumber=99) should not be in result")
	}
}

// TestListByPRNumber_ZeroPRNumber は prNumber=0 のとき空スライスを返すことを確認
func TestListByPRNumber_ZeroPRNumber(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, PRNumber: 0},
		State: model.AlertStatePending,
	})

	result := s.ListByPRNumber("org", "repo", 0)
	if len(result) != 0 {
		t.Errorf("ListByPRNumber(0) should return empty, got %d", len(result))
	}
}

// TestListByPRNumber_DoesNotCrossRepos は異なるrepo間でマッチしないことを確認
func TestListByPRNumber_DoesNotCrossRepos(t *testing.T) {
	s := New()
	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repoA", Number: 1, PRNumber: 42},
		State: model.AlertStatePending,
	})
	s.Save(&model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repoB", Number: 1, PRNumber: 42},
		State: model.AlertStatePending,
	})

	result := s.ListByPRNumber("org", "repoA", 42)
	if len(result) != 1 {
		t.Fatalf("ListByPRNumber should return only repoA's alert, got %d", len(result))
	}
	if result[0].Alert.Repo != "repoA" {
		t.Errorf("Repo = %q, want repoA", result[0].Alert.Repo)
	}
}

// TestSave_PersistsPRNumber はPRNumberがJSON経由で永続化されることを確認
func TestSave_PersistsPRNumber(t *testing.T) {
	s := New()
	r := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, PRNumber: 77},
		State: model.AlertStatePending,
	}
	s.Save(r)

	got, err := s.Get(r.Alert.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Alert.PRNumber != 77 {
		t.Errorf("PRNumber = %d, want 77", got.Alert.PRNumber)
	}
}

// TestSave_PRNumberZeroDefault は PRNumber未設定のレコードが 0 として読み出されることを確認
func TestSave_PRNumberZeroDefault(t *testing.T) {
	s := New()
	r := &model.AlertRecord{
		Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1},
		State: model.AlertStatePending,
	}
	s.Save(r)

	got, err := s.Get(r.Alert.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Alert.PRNumber != 0 {
		t.Errorf("PRNumber = %d, want 0 (zero value)", got.Alert.PRNumber)
	}
}
