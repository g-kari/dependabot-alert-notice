//go:build !linux

package web

import (
	"context"
	"fmt"
	"os/exec"
)

// Keep ordinary non-Linux test compilation intact. Requested browser QA already
// rejects non-Linux before this helper; there is no unsupervised fallback.
func browserQARunOwnedProcess(context.Context, *exec.Cmd) (map[string]any, error) {
	return map[string]any{"cleanup_complete": false, "scope": "unavailable"}, fmt.Errorf("owned browser-process supervision requires Linux")
}
