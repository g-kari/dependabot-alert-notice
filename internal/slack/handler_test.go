package slack

import (
	"context"
	"errors"
	"testing"

	slackgo "github.com/slack-go/slack"
)

// mockMerger は merger.Interface のモック実装
type mockMerger struct {
	approveErr error
	rejectErr  error
	mergeErr   error
	approved   []int
	rejected   []int
}

func (m *mockMerger) Approve(_ context.Context, id int) error {
	if m.approveErr != nil {
		return m.approveErr
	}
	m.approved = append(m.approved, id)
	return nil
}

func (m *mockMerger) Reject(id int) error {
	if m.rejectErr != nil {
		return m.rejectErr
	}
	m.rejected = append(m.rejected, id)
	return nil
}

func (m *mockMerger) Merge(_ context.Context, id int) error {
	return m.mergeErr
}

// newTestSlackClient はSlack APIなしでテスト可能なクライアントを返す。
// テスト内でpostReplyを直接呼ばないため、api fieldはnilでOK（ただし呼ばれると panic）。
func newTestSlackClient(m *mockMerger) *SlackClient {
	return &SlackClient{
		api:       nil, // postReplyを呼ぶテストでは注意
		merger:    m,
		channelID: "C_TEST",
	}
}

// newTestSlackClientWithAllowedUsers は承認許可ユーザーリスト付きのテスト用クライアントを返す。
func newTestSlackClientWithAllowedUsers(m *mockMerger, allowedUserIDs []string) *SlackClient {
	return &SlackClient{
		api:            nil,
		merger:         m,
		channelID:      "C_TEST",
		allowedUserIDs: allowedUserIDs,
	}
}

func makeCallback(actionID, value, userID string) *slackgo.InteractionCallback {
	return &slackgo.InteractionCallback{
		User: slackgo.User{ID: userID, Name: "testuser"},
		ActionCallback: slackgo.ActionCallbacks{
			BlockActions: []*slackgo.BlockAction{
				{
					ActionID: actionID,
					Value:    value,
				},
			},
		},
	}
}

// TestHandleInteraction_Approve_ValidID は正常なapproveアクションでApproveが呼ばれることを確認
func TestHandleInteraction_Approve_ValidID(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClient(m)

	// postReplyが呼ばれる前にpanicするのでrecoverで保護
	defer func() { _ = recover() }()

	callback := makeCallback("approve", "42", "U123")
	c.handleInteraction(context.Background(), callback)

	if len(m.approved) != 1 || m.approved[0] != 42 {
		t.Errorf("approved = %v, want [42]", m.approved)
	}
}

// TestHandleInteraction_Approve_InvalidID は不正なIDがApproveを呼ばないことを確認
func TestHandleInteraction_Approve_InvalidID(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClient(m)

	callback := makeCallback("approve", "not-a-number", "U123")
	c.handleInteraction(context.Background(), callback)

	if len(m.approved) != 0 {
		t.Errorf("approved should be empty, got %v", m.approved)
	}
}

// TestHandleInteraction_Reject_ValidID は正常なrejectアクションでRejectが呼ばれることを確認
func TestHandleInteraction_Reject_ValidID(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClient(m)

	callback := makeCallback("reject", "7", "U456")
	c.handleInteraction(context.Background(), callback)

	if len(m.rejected) != 1 || m.rejected[0] != 7 {
		t.Errorf("rejected = %v, want [7]", m.rejected)
	}
}

// TestHandleInteraction_Reject_InvalidID は不正なIDがRejectを呼ばないことを確認
func TestHandleInteraction_Reject_InvalidID(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClient(m)

	callback := makeCallback("reject", "xyz", "U456")
	c.handleInteraction(context.Background(), callback)

	if len(m.rejected) != 0 {
		t.Errorf("rejected should be empty, got %v", m.rejected)
	}
}

// TestHandleInteraction_Approve_Error はApproveエラー時にApproved一覧が空のままであることを確認
func TestHandleInteraction_Approve_Error(t *testing.T) {
	m := &mockMerger{approveErr: errors.New("merge failed")}
	c := newTestSlackClient(m)

	defer func() { _ = recover() }()

	callback := makeCallback("approve", "1", "U123")
	c.handleInteraction(context.Background(), callback)

	// approveErrがセットされているのでapprovedリストは増えない
	if len(m.approved) != 0 {
		t.Errorf("approved = %v, should be empty on error", m.approved)
	}
}

// TestHandleInteraction_UnknownAction は未知のActionIDを無視することを確認
func TestHandleInteraction_UnknownAction(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClient(m)

	callback := makeCallback("unknown_action", "1", "U999")
	c.handleInteraction(context.Background(), callback)

	if len(m.approved) != 0 || len(m.rejected) != 0 {
		t.Error("unknown action should not trigger approve or reject")
	}
}

// TestHandleInteraction_OpenGithub はopen_githubアクションが副作用なしで動くことを確認
func TestHandleInteraction_OpenGithub(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClient(m)

	callback := makeCallback("open_github", "https://github.com/example", "U123")
	c.handleInteraction(context.Background(), callback)

	if len(m.approved) != 0 || len(m.rejected) != 0 {
		t.Error("open_github should not trigger approve or reject")
	}
}

// TestIsAllowedUser_EmptyList は許可リストが空のとき全員を許可することを確認
func TestIsAllowedUser_EmptyList(t *testing.T) {
	c := newTestSlackClientWithAllowedUsers(&mockMerger{}, []string{})
	if !c.isAllowedUser("U_ANY") {
		t.Error("empty allowed list should permit any user")
	}
}

// TestIsAllowedUser_NilList はnilリストのとき全員を許可することを確認
func TestIsAllowedUser_NilList(t *testing.T) {
	c := newTestSlackClientWithAllowedUsers(&mockMerger{}, nil)
	if !c.isAllowedUser("U_ANY") {
		t.Error("nil allowed list should permit any user")
	}
}

// TestIsAllowedUser_AllowedUser は許可リストに含まれるユーザーを許可することを確認
func TestIsAllowedUser_AllowedUser(t *testing.T) {
	c := newTestSlackClientWithAllowedUsers(&mockMerger{}, []string{"U111", "U222"})
	if !c.isAllowedUser("U111") {
		t.Error("U111 should be allowed")
	}
	if !c.isAllowedUser("U222") {
		t.Error("U222 should be allowed")
	}
}

// TestIsAllowedUser_DeniedUser は許可リストに含まれないユーザーを拒否することを確認
func TestIsAllowedUser_DeniedUser(t *testing.T) {
	c := newTestSlackClientWithAllowedUsers(&mockMerger{}, []string{"U111"})
	if c.isAllowedUser("U999") {
		t.Error("U999 should not be allowed")
	}
}

// TestHandleInteraction_Approve_DeniedUser は非許可ユーザーのapproveをブロックすることを確認
func TestHandleInteraction_Approve_DeniedUser(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClientWithAllowedUsers(m, []string{"U_ALLOWED"})

	defer func() { _ = recover() }()

	callback := makeCallback("approve", "42", "U_DENIED")
	c.handleInteraction(context.Background(), callback)

	if len(m.approved) != 0 {
		t.Errorf("denied user should not trigger approve, got %v", m.approved)
	}
}

// TestHandleInteraction_Reject_DeniedUser は非許可ユーザーのrejectをブロックすることを確認
func TestHandleInteraction_Reject_DeniedUser(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClientWithAllowedUsers(m, []string{"U_ALLOWED"})

	defer func() { _ = recover() }()

	callback := makeCallback("reject", "7", "U_DENIED")
	c.handleInteraction(context.Background(), callback)

	if len(m.rejected) != 0 {
		t.Errorf("denied user should not trigger reject, got %v", m.rejected)
	}
}

// TestHandleInteraction_Approve_AllowedUser は許可ユーザーのapproveが通ることを確認
func TestHandleInteraction_Approve_AllowedUser(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClientWithAllowedUsers(m, []string{"U_ALLOWED"})

	defer func() { _ = recover() }()

	callback := makeCallback("approve", "42", "U_ALLOWED")
	c.handleInteraction(context.Background(), callback)

	if len(m.approved) != 1 || m.approved[0] != 42 {
		t.Errorf("approved = %v, want [42]", m.approved)
	}
}

// TestHandleInteraction_MultipleActions は複数のBlockActionを順番に処理することを確認
func TestHandleInteraction_MultipleActions(t *testing.T) {
	m := &mockMerger{}
	c := newTestSlackClient(m)

	callback := &slackgo.InteractionCallback{
		User: slackgo.User{ID: "U123", Name: "testuser"},
		ActionCallback: slackgo.ActionCallbacks{
			BlockActions: []*slackgo.BlockAction{
				{ActionID: "reject", Value: "10"},
				{ActionID: "reject", Value: "20"},
			},
		},
	}
	c.handleInteraction(context.Background(), callback)

	if len(m.rejected) != 2 {
		t.Errorf("rejected = %v, want [10 20]", m.rejected)
	}
}
