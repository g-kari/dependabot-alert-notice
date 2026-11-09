package web

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

const testConsolePartBudget = 4096

func TestAssetDetailQueryGeneratedEscapedASCIIAndUnicodeRoundTrip(t *testing.T) {
	for _, tc := range []struct{ name, value string }{{"escaped ASCII", strings.Repeat("#", 256)}, {"escaped UTF-8", strings.Repeat("界", 85) + "#"}} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.value) != 256 || !utf8.ValidString(tc.value) {
				t.Fatal("invalid boundary fixture")
			}
			query := url.Values{"q": {tc.value}, "provider": {tc.value}, "account": {tc.value}, "region": {tc.value}, "source": {"trivy"}, "limit": {"50"}, "offset": {"0"}}
			if err := validateConsoleAssetReturnBudget(query, testConsolePartBudget, 200, 1000000); err != nil {
				t.Fatal(err)
			}
			link := consoleAssetDetailURL("00000000-0000-4000-8000-000000000001", query, "trivy")
			parsed, err := url.Parse(link)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.RawQuery) <= testConsolePartBudget {
				t.Fatal("fixture did not reproduce the old outer-limit failure")
			}
			values, err := parseConsoleAssetDetailValues(parsed.RawQuery, testConsolePartBudget)
			if err != nil {
				t.Fatalf("generated %d-byte detail link rejected: %v", len(parsed.RawQuery), err)
			}
			returned, err := url.ParseQuery(values.Get("assets_query"))
			if err != nil || !reflect.DeepEqual(returned, query) {
				t.Fatalf("inner round trip=%v err=%v", returned, err)
			}
			if values.Get("source") != "trivy" || len(returned.Encode()) > testConsolePartBudget {
				t.Fatal("Finding source or inner budget changed")
			}
			// Back navigation uses the same canonical list query; source belongs to
			// that list, independently of any later detail Finding-filter changes.
			back, err := url.Parse("/assets?" + returned.Encode())
			if err != nil {
				t.Fatal(err)
			}
			if len(back.RawQuery) > testConsolePartBudget || !reflect.DeepEqual(back.Query(), query) {
				t.Fatal("Back URL lost list filters or exceeded original list limit")
			}
			t.Logf("inner=%d outer=%d back=%d bytes", len(query.Encode()), len(parsed.RawQuery), len(back.RawQuery))
		})
	}
}

func TestAssetDetailQueryNearLimitReservesPaginationWidths(t *testing.T) {
	query := url.Values{"q": {strings.Repeat("#", 256)}, "provider": {strings.Repeat("#", 256)}, "account": {strings.Repeat("#", 256)}, "region": {strings.Repeat("#", 256)}, "limit": {"1"}, "offset": {"0"}}
	for _, key := range []string{"environment", "criticality"} {
		for i := 0; i < 256; i++ {
			query.Set(key, query.Get(key)+"#")
			if validateConsoleAssetReturnBudget(query, testConsolePartBudget, 200, 1000000) != nil {
				query.Set(key, strings.TrimSuffix(query.Get(key), "#"))
				break
			}
		}
	}
	if len(query.Encode()) < testConsolePartBudget-16 {
		t.Fatalf("not near the part limit: %d", len(query.Encode()))
	}
	query.Set("limit", "200")
	query.Set("offset", "1000000")
	if err := validateConsoleAssetReturnBudget(query, testConsolePartBudget, 200, 1000000); err != nil {
		t.Fatal(err)
	}
	link, _ := url.Parse(consoleAssetDetailURL("asset", query, ""))
	values, err := parseConsoleAssetDetailValues(link.RawQuery, testConsolePartBudget)
	if err != nil || values.Get("assets_query") != query.Encode() {
		t.Fatalf("near-limit generated link rejected: %v", err)
	}
	query.Set("criticality", query.Get("criticality")+"#")
	if err := validateConsoleAssetReturnBudget(query, testConsolePartBudget, 200, 1000000); err == nil {
		t.Fatal("canonical inner overflow accepted")
	}
}

func TestAssetDetailQueryRejectsNoncanonicalCanonicalOverflow(t *testing.T) {
	value := strings.Repeat("界", 85) + "x"
	raw := "q=" + value + "&provider=" + value + "&account=" + value + "&region=" + value + "&environment=" + value + "&criticality=" + value
	if len(raw) > testConsolePartBudget {
		t.Fatal("raw fixture is not below the existing list budget")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateConsoleAssetReturnBudget(values, testConsolePartBudget, 200, 1000000); err == nil {
		t.Fatal("accepted list would generate an oversized canonical inner/Back query")
	}
}

func TestAssetDetailQueryClearedSourceDoesNotRebindToReturnList(t *testing.T) {
	list := url.Values{"source": {"trivy"}, "q": {"synthetic"}, "limit": {"50"}, "offset": {"0"}}
	for _, blank := range []bool{false, true} {
		link, _ := url.Parse(consoleAssetDetailURL("asset", list, ""))
		outer := link.Query()
		if blank {
			outer.Set("source", "")
		}
		values, err := parseConsoleAssetDetailValues(outer.Encode(), testConsolePartBudget)
		if err != nil {
			t.Fatal(err)
		}
		if values.Get("source") != "" {
			t.Fatal("cleared Finding source inherited the return-list filter")
		}
		returned, err := url.ParseQuery(values.Get("assets_query"))
		if err != nil || returned.Get("source") != "trivy" {
			t.Fatal("original Back list source was lost")
		}
	}
}

func TestAssetDetailQueryStrictBoundsEncodingKeysAndDuplicates(t *testing.T) {
	inner := func(raw string) string { return url.Values{"assets_query": {raw}}.Encode() }
	outerBudget := len("assets_query=") + 3*testConsolePartBudget + 1 + testConsolePartBudget
	for _, raw := range []string{
		strings.Repeat("x", outerBudget+1), inner("q=" + strings.Repeat("x", testConsolePartBudget-1)), "q=" + strings.Repeat("x", testConsolePartBudget),
		"%zz=1", "q=%zz", inner("q=%zz"), "q=a;q=b", inner("q=a;q=b"),
		"unknown=x", inner("unknown=x"), "asset_id=x", "assets_query=x&assets_query=y", "q=x&%71=y", inner("provider=x&%70rovider=y"), "source=x&source=y",
	} {
		if _, err := parseConsoleAssetDetailValues(raw, testConsolePartBudget); err == nil {
			t.Fatalf("invalid query accepted (length=%d): %.100s", len(raw), raw)
		}
	}
	// The full outer budget remains bounded even if both parts contain legal
	// keys; controls/enums/IDs still go through the unchanged semantic validators.
	if _, err := parseConsoleAssetDetailValues("", 0); err == nil {
		t.Fatal("invalid caller budget accepted")
	}
}
