//go:build !windows

package config

import (
	"errors"
	"os"
	"syscall"
)

func credentialStorageSupported() error { return nil }
func privateCredentialFile(info os.FileInfo) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Size() > 65536 || info.Mode().Perm() != 0600 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("認証ファイルは本人所有の通常ファイル・権限0600である必要があります")
	}
	return nil
}
