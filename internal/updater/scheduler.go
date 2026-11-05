package updater

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// SupportsAutomaticUpdates excludes development builds and unsupported platforms.
func (u Updater) SupportsAutomaticUpdates() bool {
	_, err := parseVersion(u.Current)
	return err == nil && (u.OS == "darwin" || u.OS == "linux") && (u.Arch == "arm64" || u.Arch == "amd64")
}

// Schedule applies releases serially until one is installed or ctx is canceled.
// Failed attempts retry after a full interval; each attempt has its own timeout.
func Schedule(ctx context.Context, interval, timeout time.Duration, apply func(context.Context) (Result, error)) (Result, error) {
	if interval <= 0 || timeout <= 0 || apply == nil {
		return Result{}, fmt.Errorf("自動更新の間隔・タイムアウトは正数、更新処理は設定済みである必要があります")
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-timer.C:
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			attempt, cancel := context.WithTimeout(ctx, timeout)
			result, err := apply(attempt)
			cancel()
			if result.Updated && err == nil {
				return result, nil
			}
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			if err != nil {
				slog.Warn("定期Release更新失敗、次の周期に再試行", "error", err, "interval", interval)
			} else {
				slog.Debug("定期Release更新確認、現在の版を維持", "current", result.Current, "latest", result.Latest)
			}
			timer.Reset(interval)
		}
	}
}
