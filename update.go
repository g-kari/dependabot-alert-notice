package main

import (
	"context"
	"fmt"
	"io"

	"github.com/g-kari/dependabot-alert-notice/internal/updater"
)

func runReleaseUpdate(ctx context.Context, u updater.Updater, apply bool, out io.Writer) error {
	var result updater.Result
	var err error
	if apply {
		result, err = u.Apply(ctx)
	} else {
		result, err = u.Check(ctx)
	}
	if err != nil {
		return err
	}
	switch {
	case result.Updated:
		_, err = fmt.Fprintf(out, "%s → %s に更新しました。次回起動から適用されます。\n", result.Current, result.Latest)
	case result.Available:
		_, err = fmt.Fprintf(out, "更新があります: %s → %s（--updateで適用）\n", result.Current, result.Latest)
	default:
		_, err = fmt.Fprintf(out, "現在の版を維持します: %s（最新の安定版Release: %s）\n", result.Current, result.Latest)
	}
	if err != nil {
		return fmt.Errorf("更新結果表示: %w", err)
	}
	return nil
}

func runAndRestart(run func() string, restart func(string, []string, []string) error, args, env []string) error {
	path := run() // All application defers, including DB close, finish before exec.
	if path == "" {
		return nil
	}
	if err := restart(path, args, env); err != nil {
		return fmt.Errorf("更新後の再起動失敗: %w", err)
	}
	return nil
}
