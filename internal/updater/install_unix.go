//go:build linux || darwin

package updater

import "os"

// installBinary atomically replaces the executable on Mac/Linux.
func installBinary(candidate, target string) error {
	return os.Rename(candidate, target)
}
