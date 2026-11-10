//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// restartProcess starts the updated binary as a detached child and returns so the
// current process can exit. Windows has no exec(2), so the replacement cannot
// take over this process image; it inherits the arguments, environment, working
// directory and standard handles instead.
func restartProcess(path string, args, env []string) error {
	if len(args) == 0 {
		args = []string{path}
	}
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("更新後の作業ディレクトリ取得: %w", err)
	}
	cmd := exec.Command(path, args[1:]...)
	cmd.Env = env
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("更新後の新プロセス起動: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("更新後のプロセス解放: %w", err)
	}
	return nil
}

// cleanupPreviousBinary removes the backup left behind by the previous Windows
// update. The file is typically still locked while the old process runs, so the
// removal is retried on the next start.
func cleanupPreviousBinary() {
	executable, err := os.Executable()
	if err != nil {
		return
	}
	_ = os.Remove(executable + ".old")
}
