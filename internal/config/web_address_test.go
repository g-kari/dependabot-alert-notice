package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRejectsMalformedWebBindAddress(t *testing.T) {
	for _, input := range []string{"web: {host: 'http://example.com', port: 8999}", "web: {host: '127.0.0.1:8999', port: 8999}", "web: {port: -1}", "web: {port: 65536}"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("invalid web binding accepted: %s", input)
		}
	}
}

func TestWebAddressesUseConfiguredPortAndIPv6Brackets(t *testing.T) {
	for _, test := range []struct{ host, address, browser string }{
		{"", ":8998", "http://127.0.0.1:8998"},
		{"127.0.0.1", "127.0.0.1:8998", "http://127.0.0.1:8998"},
		{"::1", "[::1]:8998", "http://[::1]:8998"},
		{"::", "[::]:8998", "http://[::1]:8998"},
	} {
		cfg := WebConfig{Host: test.host, Port: 8998}
		if cfg.ListenAddress() != test.address || cfg.BrowserURL() != test.browser {
			t.Fatalf("%q binding: %s %s", test.host, cfg.ListenAddress(), cfg.BrowserURL())
		}
	}
}
