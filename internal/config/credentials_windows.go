//go:build windows

package config

import (
	"errors"
	"os"
)

func credentialStorageSupported() error {
	return errors.New("Windows本体では認証ファイル保存は未対応です。環境変数を使用してください")
}
func privateCredentialFile(os.FileInfo) error { return credentialStorageSupported() }
