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
	return installBinaryWithRename(candidate, target, os.Rename)
}

func installBinaryWithRename(candidate, target string, rename func(string, string) error) error {
	info, err := os.Lstat(candidate)
	if err != nil {
		return fmt.Errorf("更新候補確認: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("更新候補が通常ファイルではありません")
	}
	backup := target + ".old"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("旧バックアップ削除: %w", err)
	}
	if err := rename(target, backup); err != nil {
		return fmt.Errorf("現行バイナリ退避: %w", err)
	}
	if err := rename(candidate, target); err != nil {
		if restoreErr := rename(backup, target); restoreErr != nil {
			return fmt.Errorf("更新適用: %w; 現行バイナリ復元（%sに退避済み）: %w", err, backup, restoreErr)
		}
		return fmt.Errorf("更新適用: %w", err)
	}
	_ = os.Remove(backup)
	return nil
}
