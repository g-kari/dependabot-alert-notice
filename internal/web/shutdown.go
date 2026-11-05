package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

func serveHTTP(ctx context.Context, server *http.Server, serve func() error) error {
	// Cancel SSE and other active requests when the application stops.
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	servingDone, shutdownDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
		case <-servingDone:
			if ctx.Err() == nil {
				return
			}
		}
		if err := server.Shutdown(context.Background()); err != nil {
			slog.Warn("WebUI終了待機失敗", "error", err)
			if err := server.Close(); err != nil {
				slog.Warn("WebUI接続終了失敗", "error", err)
			}
		}
	}()
	err := serve()
	close(servingDone)
	<-shutdownDone // Listener closure alone does not mean handlers have finished.
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("WebUIサーバーエラー: %w", err)
	}
	return nil
}
