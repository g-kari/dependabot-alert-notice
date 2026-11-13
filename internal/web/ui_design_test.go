package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var fontSizeRule = regexp.MustCompile(`(?i)font-size\s*:\s*([0-9]*\.?[0-9]+)\s*(px|rem|em)\b`)

func TestHTMLTemplatesKeepTextAtOrAboveTwelvePixels(t *testing.T) {
	paths, err := filepath.Glob("templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for lineNumber, line := range strings.Split(string(raw), "\n") {
			for _, match := range fontSizeRule.FindAllStringSubmatch(line, -1) {
				value, err := strconv.ParseFloat(match[1], 64)
				if err != nil {
					t.Fatal(err)
				}
				unit := strings.ToLower(match[2])
				belowMinimum := unit == "px" && value < 12 || (unit == "rem" || unit == "em") && value < 0.75
				if belowMinimum {
					t.Errorf("%s:%d font-size %s is below 12px", path, lineNumber+1, match[0])
				}
			}
		}
	}
}

func TestHTMLTemplatesDoNotUseDecorativeSubtitles(t *testing.T) {
	for path, forbidden := range map[string][]string{
		"templates/layout.html":            {"Security workspace", "Source-native records"},
		"templates/security_overview.html": {"記録された状況から、次の確認へ。", "保存されている Findings、Assets、収集記録を横断して確認します。"},
		"templates/findings.html":          {"検出元を横断して検索し、根拠と対応状況を確認する。"},
		"templates/assets.html":            {"保存済みの資産と、関連する共通 Findings を調べる。"},
		"templates/integrations.html":      {"保存されている収集の試行と、最後の成功 receipt を分けて確認する。"},
		"templates/settings.html":          {"登録すると定期取得と脆弱性レポートに反映されます。"},
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range forbidden {
			if strings.Contains(string(raw), text) {
				t.Errorf("%s still contains decorative subtitle %q", path, text)
			}
		}
	}
}

func TestHermesSettingsInputsHaveExplicitLabels(t *testing.T) {
	raw, err := os.ReadFile("templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	template := string(raw)
	for _, pair := range [][2]string{
		{`<label for="eval_provider">評価エンジン</label>`, `id="eval_provider"`},
		{`<label for="eval_hermes_model">Hermes model</label>`, `id="eval_hermes_model"`},
		{`<label for="eval_hermes_base_url">Proxy endpoint</label>`, `id="eval_hermes_base_url"`},
	} {
		if !strings.Contains(template, pair[0]) || !strings.Contains(template, pair[1]) {
			t.Errorf("Hermes settings input missing explicit label association %q -> %q", pair[0], pair[1])
		}
	}
	if !strings.Contains(template, `<select id="eval_provider" name="eval_provider" aria-describedby="eval-provider-help">`) || !strings.Contains(template, `<p id="eval-provider-help" class="field-hint">`) {
		t.Error("evaluator provider data-flow hint is not associated with its select")
	}
}

func TestSettingsFormRowsStackOnNarrowScreens(t *testing.T) {
	raw, err := os.ReadFile("templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	style := string(raw)
	for _, rule := range []string{"tr:has(> th)", "grid-template-columns: minmax(0, 1fr)", "max-width: 100%"} {
		if !strings.Contains(style, rule) {
			t.Errorf("mobile settings layout is missing %q", rule)
		}
	}
}
