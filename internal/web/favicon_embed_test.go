package web

import (
	"testing"
)

func TestFaviconEmbedded(t *testing.T) {
	data, err := templateFS.ReadFile("static/favicon.ico")
	if err != nil {
		t.Fatalf("static/favicon.ico not embedded: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("favicon.ico is empty")
	}
	t.Logf("favicon.ico size: %d bytes", len(data))
}
