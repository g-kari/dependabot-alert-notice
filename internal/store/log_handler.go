package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// StoreLogHandler はslogのHandlerで、info以上のログをストアにも書き込む
type StoreLogHandler struct {
	inner slog.Handler
	s     *Store
}

// NewStoreLogHandler はslogのHandlerをラップしてストアにもログを書き込むHandlerを返す
func NewStoreLogHandler(inner slog.Handler, s *Store) *StoreLogHandler {
	return &StoreLogHandler{inner: inner, s: s}
}

func (h *StoreLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *StoreLogHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = h.inner.Handle(ctx, r)

	// debug は WebUI ログに出さない
	if r.Level < slog.LevelInfo {
		return nil
	}

	level := "info"
	switch {
	case r.Level >= slog.LevelError:
		level = "error"
	case r.Level >= slog.LevelWarn:
		level = "warn"
	}

	// メッセージに属性を付加（alertID は別フィールドとして抽出）
	msg := r.Message
	var alertID int
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "alertID" {
			alertID = int(a.Value.Int64())
			return true
		}
		msg += fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
		return true
	})

	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	h.s.AddLog(model.LogEntry{
		Timestamp: ts,
		Level:     level,
		Message:   msg,
		AlertID:   alertID,
	})
	return nil
}

func (h *StoreLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &StoreLogHandler{inner: h.inner.WithAttrs(attrs), s: h.s}
}

func (h *StoreLogHandler) WithGroup(name string) slog.Handler {
	return &StoreLogHandler{inner: h.inner.WithGroup(name), s: h.s}
}
