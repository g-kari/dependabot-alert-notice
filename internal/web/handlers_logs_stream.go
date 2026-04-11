package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

type logEvent struct {
	Timestamp string `json:"ts"`
	Level     string `json:"level"`
	AlertID   int    `json:"alert_id,omitempty"`
	Message   string `json:"message"`
}

func toLogEvent(e model.LogEntry) logEvent {
	return logEvent{
		Timestamp: e.Timestamp.Format("01-02 15:04:05"),
		Level:     e.Level,
		AlertID:   e.AlertID,
		Message:   e.Message,
	}
}

func (s *Server) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)

	sendEvent := func(e model.LogEntry) {
		b, _ := json.Marshal(toLogEvent(e))
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		if ok {
			flusher.Flush()
		}
	}

	// 既存ログを新しい順で送信
	existing := s.store.ListLogs()
	sort.Slice(existing, func(i, j int) bool {
		return existing[i].Timestamp.Before(existing[j].Timestamp)
	})
	for _, e := range existing {
		sendEvent(e)
	}

	// 初期ログ送信完了マーカー（クライアントが既存/新着を区別するため）
	_, _ = fmt.Fprintf(w, "event: ready\ndata: {}\n\n")
	if ok {
		flusher.Flush()
	}

	// 新着ログを購読
	ch := s.store.SubscribeLogs()
	defer s.store.UnsubscribeLogs(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			sendEvent(e)
		}
	}
}
