//go:build windows

package updater

import (
	"fmt"
	"os"
)

// installBinary replaces the running executable on Windows.
// A running image cannot be overwritten in place, so the current binary is moved
// aside first. The backup usually stays locked until this process exits and is
// removed by cleanupPreviousBinary on the next start.
func installBinary(candidate, target string) error {
	backup := target + ".old"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("旧バックアップ削除: %w", err)
	}
	if err := os.Rename(target, backup); err != nil {
		return fmt.Errorf("現行バイナリ退避: %w", err)
	}
	if err := os.Rename(candidate, target); err != nil {
		_ = os.Rename(backup, target)
		return fmt.Errorf("更新適用: %w", err)
	}
	_ = os.Remove(backup)
	return nil
}
