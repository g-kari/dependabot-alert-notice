//go:build !linux && !darwin && !windows

package updater

import "fmt"

// installBinary reports that the platform has no automatic replacement path.
func installBinary(candidate, target string) error {
	return fmt.Errorf("このOSは自動更新に対応していません")
}
