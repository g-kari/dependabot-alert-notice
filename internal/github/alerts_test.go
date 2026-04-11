package github

import (
	"testing"
)

func TestContainsPackageName(t *testing.T) {
	tests := []struct {
		title   string
		pkgName string
		want    bool
	}{
		{"Bump lodash from 4.17.20 to 4.17.21", "lodash", true},
		{"Bump axios from 0.21.0 to 0.21.1", "lodash", false},
		{"Bump @types/node from 14.0.0 to 14.0.1", "@types/node", true},
		{"Update golang.org/x/crypto to v0.17.0", "golang.org/x/crypto", true},
		{"Some random PR", "lodash", false},
		{"Bump LODASH from 4.17.20 to 4.17.21", "lodash", true}, // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			got := containsPackageName(tt.title, tt.pkgName)
			if got != tt.want {
				t.Errorf("containsPackageName(%q, %q) = %v, want %v", tt.title, tt.pkgName, got, tt.want)
			}
		})
	}
}

func TestEqualFold(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"abc", "abc", true},
		{"ABC", "abc", true},
		{"abc", "ABC", true},
		{"abc", "abd", false},
		{"ab", "abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := equalFold(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("equalFold(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
