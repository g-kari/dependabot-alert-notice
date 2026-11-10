//go:build !linux && !darwin && !windows

package main

import "fmt"

func restartProcess(string, []string, []string) error {
	return fmt.Errorf("このOSは自動更新・再起動に対応していません")
}

func cleanupPreviousBinary() {}
