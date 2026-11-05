//go:build linux || darwin

package main

import "syscall"

// Exec keeps the PID, terminal, cwd and environment, including launcher signal handling.
func restartProcess(path string, args, env []string) error {
	return syscall.Exec(path, args, env)
}
