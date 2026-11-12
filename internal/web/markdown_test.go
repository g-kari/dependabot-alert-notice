package web

import (
	"html/template"
	"strings"
	"testing"
)

func TestMarkdownCommonMarkCompatibility(t *testing.T) {
	markdownFn := templateFuncs["markdown"].(func(string) template.HTML)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"heading", "## Advisory", "<h2>Advisory</h2>\n"},
		{"unicode emphasis", "こんにちは、 **世界** 。", "<p>こんにちは、 <strong>世界</strong> 。</p>\n"},
		{"list", "- first\n- second", "<ul>\n<li>first</li>\n<li>second</li>\n</ul>\n"},
		{"safe link", "[details](https://example.com/advisory)", "<p><a href=\"https://example.com/advisory\">details</a></p>\n"},
		{"escaped code", "`<script>alert(1)</script>`", "<p><code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>\n"},
		{"fenced code", "```text\n<a>&\n```", "<pre><code class=\"language-text\">&lt;a&gt;&amp;\n</code></pre>\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := string(markdownFn(tt.input)); got != tt.want {
				t.Errorf("markdown(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMarkdownRejectsUnsafeHTMLAndURLs(t *testing.T) {
	markdownFn := templateFuncs["markdown"].(func(string) template.HTML)
	tests := []struct {
		name      string
		input     string
		forbidden string
	}{
		{"script block", "<script>alert(1)</script>", "<script"},
		{"inline event handler", "before <img src=x onerror=alert(1)> after", "<img"},
		{"javascript link", "[click](javascript:alert%281%29)", "javascript:"},
		{"mixed case scheme", "[click](JaVaScRiPt:alert%281%29)", "javascript:"},
		{"entity encoded scheme", "[click](jav&#x61;script:alert%281%29)", "javascript:"},
		{"data link", "[click](data:text/html;base64,PHNjcmlwdD4=)", "data:"},
		{"file link", "[click](file:///etc/passwd)", "file:"},
		{"javascript image", "![alt](javascript:alert%281%29)", "javascript:"},
		{"svg data image", "![alt](data:image/svg+xml;base64,PHN2Zz4=)", "data:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := string(markdownFn(tt.input))
			if strings.Contains(strings.ToLower(got), tt.forbidden) {
				t.Errorf("markdown(%q) = %q, must not contain %q", tt.input, got, tt.forbidden)
			}
		})
	}
}
