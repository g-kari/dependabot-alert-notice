package config

import (
	"fmt"
	"net"
	"strconv"
)

// ListenAddress returns a correctly bracketed IPv4/IPv6 binding. Empty Host
// preserves existing all-interface configurations; distributions bind loopback.
func (w WebConfig) ListenAddress() string { return net.JoinHostPort(w.Host, strconv.Itoa(w.Port)) }

// BrowserURL replaces unspecified bindings with their local loopback address.
func (w WebConfig) BrowserURL() string {
	host := w.Host
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(w.Port))
}

func (w WebConfig) validate() error {
	if w.Port < 0 || w.Port > 65535 {
		return fmt.Errorf("web.portは0〜65535の範囲で指定してください")
	}
	if w.Host != "" && w.Host != "localhost" && net.ParseIP(w.Host) == nil {
		return fmt.Errorf("web.hostはIPアドレスまたはlocalhostを指定してください")
	}
	return nil
}
