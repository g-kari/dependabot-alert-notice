package web

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
)

// TestPoll_Redirects はポーリングが起動してダッシュボードへリダイレクトされることを確認
func TestPoll_Redirects(t *testing.T) {
	srv, _, _ := newTestServer(t)
	var called atomic.Bool
	done := make(chan struct{})
	srv.SetPollFn(func() {
		called.Store(true)
		close(done)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/poll", nil)
	w := httptest.NewRecorder()
	srv.handlePoll(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if w.Header().Get("Location") != "/" {
		t.Errorf("Location = %q, want /", w.Header().Get("Location"))
	}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("pollFn should have been called")
	}
	if !called.Load() {
		t.Error("pollFn should have been called")
	}
}

// TestPoll_NoPollFn はpollFnが未設定でも500にならないことを確認
func TestPoll_NoPollFn(t *testing.T) {
	srv, _, _ := newTestServer(t)
	// pollFnを設定しない

	req := httptest.NewRequest(http.MethodPost, "/api/poll", nil)
	w := httptest.NewRecorder()
	srv.handlePoll(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d (should redirect even without pollFn)", w.Code, http.StatusSeeOther)
	}
}

// TestPoll_DoubleExecution はポーリング中に再度リクエストしても二重実行されないことを確認
func TestPoll_DoubleExecution(t *testing.T) {
	srv, _, _ := newTestServer(t)

	callCount := 0
	var mu sync.Mutex
	start := make(chan struct{})
	done := make(chan struct{})

	srv.SetPollFn(func() {
		mu.Lock()
		callCount++
		mu.Unlock()
		<-start // ブロックして実行中状態を保持
		close(done)
	})

	// 1回目: ポーリング開始
	req1 := httptest.NewRequest(http.MethodPost, "/api/poll", nil)
	w1 := httptest.NewRecorder()
	srv.handlePoll(w1, req1)

	// goroutineが起動するまで少し待つ
	time.Sleep(20 * time.Millisecond)

	// 2回目: ポーリング中に再度リクエスト → 409
	req2 := httptest.NewRequest(http.MethodPost, "/api/poll", nil)
	w2 := httptest.NewRecorder()
	srv.handlePoll(w2, req2)

	if w2.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d (conflict while polling)", w2.Code, http.StatusConflict)
	}

	// ポーリング完了
	close(start)
	<-done

	mu.Lock()
	if callCount != 1 {
		t.Errorf("pollFn called %d times, want 1", callCount)
	}
	mu.Unlock()
}

// TestPollTarget_Success は指定インデックスのターゲット1件のFetchJobがエンキューされることを確認
func TestPollTarget_Success(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{
		Targets: []config.Target{
			{Owner: "org1", Repo: "repo1"},
			{Owner: "org2", Repo: "repo2"},
		},
	}
	srv.jobQueue = queue.New(10, 1)

	req := httptest.NewRequest(http.MethodPost, "/api/poll/target/1", nil)
	req.SetPathValue("i", "1")
	w := httptest.NewRecorder()
	srv.handlePollTarget(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if srv.jobQueue.Len() != 1 {
		t.Errorf("queue len = %d, want 1", srv.jobQueue.Len())
	}
}

// TestPollTarget_InvalidIndex は不正なインデックスで400を返すことを確認
func TestPollTarget_InvalidIndex(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{Targets: []config.Target{{Owner: "org1"}}}

	req := httptest.NewRequest(http.MethodPost, "/api/poll/target/abc", nil)
	req.SetPathValue("i", "abc")
	w := httptest.NewRecorder()
	srv.handlePollTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestPollTarget_OutOfRange は範囲外インデックスで400を返すことを確認
func TestPollTarget_OutOfRange(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg = &config.Config{Targets: []config.Target{{Owner: "org1"}}}

	req := httptest.NewRequest(http.MethodPost, "/api/poll/target/99", nil)
	req.SetPathValue("i", "99")
	w := httptest.NewRecorder()
	srv.handlePollTarget(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestPollRepo_Success はowner/repoを指定してFetchJobがエンキューされることを確認
func TestPollRepo_Success(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.jobQueue = queue.New(10, 1)

	req := httptest.NewRequest(http.MethodPost, "/api/poll/repo", nil)
	req.Form = map[string][]string{
		"owner": {"myorg"},
		"repo":  {"myrepo"},
	}
	w := httptest.NewRecorder()
	srv.handlePollRepo(w, req)

	if w.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if srv.jobQueue.Len() != 1 {
		t.Errorf("queue len = %d, want 1", srv.jobQueue.Len())
	}
}

// TestPollRepo_MissingParams はowner/repoが欠けている場合400を返すことを確認
func TestPollRepo_MissingParams(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.jobQueue = queue.New(10, 1)

	req := httptest.NewRequest(http.MethodPost, "/api/poll/repo", nil)
	req.Form = map[string][]string{"owner": {"myorg"}} // repo なし
	w := httptest.NewRecorder()
	srv.handlePollRepo(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestEnqueueEvaluate_RedirectsToReferer はRefererがある場合そこへリダイレクトすることを確認
func TestEnqueueEvaluate_RedirectsToReferer(t *testing.T) {
	srv, s, _ := newTestServer(t)
	srv.jobQueue = queue.New(10, 1)
	saveAlert(s, 1, "lodash", model.SeverityHigh)

	req := httptest.NewRequest(http.MethodPost, "/api/evaluate/1", nil)
	req.SetPathValue("id", "1")
	req.Header.Set("Referer", "http://localhost:8999/alerts/1?view=cve&page=2")
	w := httptest.NewRecorder()
	srv.handleEnqueueEvaluate(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	loc := w.Header().Get("Location")
	if loc != "http://localhost:8999/alerts/1?view=cve&page=2" {
		t.Errorf("Location = %q, want referer URL", loc)
	}
}

// TestEnqueueEvaluate_FallsBackToRootWhenNoReferer はRefererがない場合 / にリダイレクトすることを確認
func TestEnqueueEvaluate_FallsBackToRootWhenNoReferer(t *testing.T) {
	srv, s, _ := newTestServer(t)
	srv.jobQueue = queue.New(10, 1)
	saveAlert(s, 1, "lodash", model.SeverityHigh)

	req := httptest.NewRequest(http.MethodPost, "/api/evaluate/1", nil)
	req.SetPathValue("id", "1")
	w := httptest.NewRecorder()
	srv.handleEnqueueEvaluate(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
}

// TestDashboard_ShowsPollingState はポーリング中にダッシュボードが200を返すことを確認
func TestDashboard_ShowsPollingState(t *testing.T) {
	srv, _, _ := newTestServer(t)

	// ポーリング中状態を設定
	srv.pollingMu.Lock()
	srv.isPolling = true
	srv.pollingMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
