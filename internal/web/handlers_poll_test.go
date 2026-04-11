package web

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
