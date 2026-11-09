package ghcommand

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// resolveExecutable uses only the captured PATH and origin cwd. It deliberately
// ignores relative/empty search entries (Go's ErrDot protection) but permits an
// explicitly configured relative executable, pinned to its original directory.
func resolveExecutable(name string, environment []string) (string, error) {
	if filepath.IsAbs(name) {
		return filepath.Clean(name), nil
	}
	if strings.ContainsAny(name, "/\\") {
		path, err := filepath.Abs(name)
		if err != nil {
			return "", errors.New("GitHub executable origin directory is unavailable")
		}
		return path, nil
	}
	var search, extensions string
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(key, "PATH") {
			search = value
		}
		if strings.EqualFold(key, "PATHEXT") {
			extensions = value
		}
	}
	suffixes := []string{""}
	if runtime.GOOS == "windows" && filepath.Ext(name) == "" {
		if extensions == "" {
			extensions = ".COM;.EXE;.BAT;.CMD"
		}
		suffixes = strings.Split(extensions, ";")
	}
	for _, directory := range filepath.SplitList(search) {
		if !filepath.IsAbs(directory) {
			continue
		}
		for _, suffix := range suffixes {
			candidate := filepath.Join(directory, name+suffix)
			info, err := os.Stat(candidate)
			if err == nil && !info.IsDir() && (runtime.GOOS == "windows" || info.Mode()&0111 != 0) {
				return candidate, nil
			}
		}
	}
	return "", errors.New("GitHub executable is unavailable in the captured absolute PATH; configure gh_path explicitly")
}
