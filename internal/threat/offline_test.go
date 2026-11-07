package threat

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func offlineOptions() OfflineOptions {
	return OfflineOptions{CVEs: []string{"CVE-2025-1234", "CVE-2025-9999"}, ObservedAt: time.Date(2025, 2, 2, 0, 0, 0, 0, time.UTC)}
}

const offlineCSV = "#model_version:v2025.01.01,score_date:2025-02-01\ncve,epss,percentile\nCVE-2025-1234,0,1\nCVE-2025-5678,0.2,0.4\n"
const offlineKEV = `{"catalogVersion":"2025.02.01","dateReleased":"2025-02-01T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2025-1234","dateAdded":"2025-01-01","notes":"ignored"}]}`

func TestOfflineParsersSelectedMissingAndZero(t *testing.T) {
	for _, tc := range []struct{ source, raw string }{{"epss", offlineCSV}, {"kev", offlineKEV}} {
		t.Run(tc.source, func(t *testing.T) {
			f, err := ParseOfflineThreat(strings.NewReader(tc.raw), tc.source, offlineOptions())
			if err != nil {
				t.Fatal(err)
			}
			if len(f.Entries) != 1 || len(f.SelectedCVEs) != 2 {
				t.Fatalf("bad projection: %+v", f)
			}
			if tc.source == "epss" && (f.Entries[0].EPSS == nil || *f.Entries[0].EPSS != 0) {
				t.Fatal("zero lost")
			}
			if err := ValidateOfflineFeed(f); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestOfflineEPSSRejectsInvalidWholeFeed(t *testing.T) {
	cases := []string{strings.Replace(offlineCSV, "score_date:2025-02-01", "", 1), strings.Replace(offlineCSV, "2025-02-01", "2025-02-03", 1), strings.Replace(offlineCSV, "0.2,0.4", "NaN,0.4", 1), offlineCSV + "CVE-2025-1234,0.1,1\n", offlineCSV + "bad,0,1\n", strings.Replace(offlineCSV, "v2025.01.01", "bad secret value", 1), strings.Replace(offlineCSV, "0.2,0.4", "1.1,0.4", 1), strings.Replace(offlineCSV, "0.2,0.4", "0.2,-1", 1), strings.Replace(offlineCSV, "0.2,0.4", "Inf,0.4", 1), offlineCSV + "\xff"}
	for i, raw := range cases {
		f, e := ParseOfflineThreat(strings.NewReader(raw), "epss", offlineOptions())
		if e == nil || f.Source != "" {
			t.Errorf("case %d accepted/partial: %+v %v", i, f, e)
		}
	}
}
func TestOfflineKEVRejectsInvalidWholeFeed(t *testing.T) {
	cases := []string{`null`, `[]`, strings.Replace(offlineKEV, `"count":1`, `"count":2`, 1), strings.Replace(offlineKEV, `"count":1,`, "", 1), strings.Replace(offlineKEV, `"2025-01-01"`, `"2025-02-02"`, 1), strings.Replace(offlineKEV, `"CVE-2025-1234"`, `"GHSA-secret"`, 1), strings.Replace(offlineKEV, `"vulnerabilities":[`, `"vulnerabilities":null,"unused":[`, 1), offlineKEV + ` {}`}
	for i, raw := range cases {
		f, e := ParseOfflineThreat(strings.NewReader(raw), "kev", offlineOptions())
		if e == nil || f.Source != "" {
			t.Errorf("case %d accepted/partial", i)
		}
	}
}

type offlineBadReader struct{}

func (offlineBadReader) Read([]byte) (int, error) { return 0, errors.New("secret token") }
func TestOfflineSanitizesReaderErrors(t *testing.T) {
	_, e := ParseOfflineThreat(offlineBadReader{}, "epss", offlineOptions())
	if e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatalf("unsafe error %v", e)
	}
}
func TestOfflineSelectionNormalization(t *testing.T) {
	got, e := NormalizeOfflineCVEs([]string{" cve-2025-9999 ", "CVE-2025-1234", "CVE-2025-1234"})
	if e != nil || strings.Join(got, ",") != "CVE-2025-1234,CVE-2025-9999" {
		t.Fatalf("%v %v", got, e)
	}
	a, _ := OfflineSelectionScope(got)
	b, _ := OfflineSelectionScope([]string{"cve-2025-9999", "CVE-2025-1234"})
	if a != b || !strings.HasPrefix(a, "cves-sha256:") {
		t.Fatal("unstable scope")
	}
	for _, v := range []string{"CVE-1998-1234", "CVE-2025-123", "CVE-2025-12345678901234567890", "prefix CVE-2025-1234", "GHSA-abcd"} {
		if _, e := NormalizeOfflineCVEs([]string{v}); e == nil {
			t.Errorf("accepted %s", v)
		}
	}
	if _, e := NormalizeOfflineCVEs(nil); e == nil {
		t.Fatal("empty selection")
	}
}
func TestOfflineDuplicatesAndValidation(t *testing.T) {
	f, e := ParseOfflineThreat(strings.NewReader(offlineCSV+"CVE-2025-1234,0,1\n"), "epss", offlineOptions())
	if e != nil || len(f.Entries) != 1 {
		t.Fatal(e)
	}
	n := math.NaN()
	f.Entries[0].EPSS = &n
	if ValidateOfflineFeed(f) == nil {
		t.Fatal("accepted NaN")
	}
}
func TestOfflineSizeLimit(t *testing.T) {
	_, e := ParseOfflineThreat(io.LimitReader(zeroOfflineReader{}, (32<<20)+1), "epss", offlineOptions())
	if e == nil {
		t.Fatal("oversized input")
	}
}

type zeroOfflineReader struct{}

func (zeroOfflineReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestOfflineEPSSMetadataAndRowDates(t *testing.T) {
	for _, date := range []string{"2025-02-01", "2025-02-01T00:00:00Z", "2025-02-01T00:00:00+0000", "2025-02-01 00:00:00"} {
		raw := strings.Replace(offlineCSV, "score_date:2025-02-01", "score_date:"+date, 1)
		if _, err := ParseOfflineThreat(strings.NewReader(raw), "epss", offlineOptions()); err != nil {
			t.Fatalf("date %q: %v", date, err)
		}
	}
	for _, tc := range []struct {
		raw  string
		good bool
	}{
		{"#model_version:v1,score_date:2025-02-01\ncve,epss,percentile,date\nCVE-2025-1234,0.5,0.5,2025-02-01\n", true},
		{"#model_version:v1,score_date:2025-02-01\ncve,epss,percentile,date\nCVE-2025-1234,0.5,0.5,2025-01-31\n", false},
		{strings.Replace(offlineCSV, "score_date:", "score_date:2025-02-01,score_date:", 1), false},
		{strings.Replace(offlineCSV, "cve,epss,percentile", "cve,epss,epss", 1), false},
		{strings.Replace(offlineCSV, "cve,epss,percentile", "cve,epss,percentile,extra", 1), false},
		{strings.Replace(offlineCSV, "CVE-2025-5678", "cve-2025-5678", 1), false},
		{strings.Replace(offlineCSV, "v2025.01.01", strings.Repeat("a", 65), 1), false},
		{strings.Replace(offlineCSV, "v2025.01.01", strings.Repeat("a", 64), 1), true},
	} {
		_, err := ParseOfflineThreat(strings.NewReader(tc.raw), "epss", offlineOptions())
		if (err == nil) != tc.good {
			t.Fatalf("good=%v error=%v", tc.good, err)
		}
	}
}
func TestOfflineKEVDuplicatesAndTypes(t *testing.T) {
	prefix := `{"catalogVersion":"v1","dateReleased":"2025-02-01","count":2,"vulnerabilities":[`
	entry := `{"cveID":"CVE-2025-1234","dateAdded":"2025-01-01"}`
	raw := prefix + entry + "," + entry + "]}"
	f, err := ParseOfflineThreat(strings.NewReader(raw), "kev", offlineOptions())
	if err != nil || len(f.Entries) != 1 {
		t.Fatalf("duplicate: %v", err)
	}
	for _, bad := range []string{
		prefix + entry + "," + strings.Replace(entry, "2025-01-01", "2025-01-02", 1) + "]}",
		strings.Replace(offlineKEV, `"count":1`, `"count":1,"count":1`, 1),
		strings.Replace(offlineKEV, `"count":1`, `"count":null`, 1),
		strings.Replace(offlineKEV, `"count":1`, `"count":1.0`, 1),
		strings.Replace(offlineKEV, `"dateAdded":"2025-01-01"`, `"dateAdded":"2025-01-01T00:00:00Z"`, 1),
		strings.Replace(offlineKEV, `"dateReleased":"2025-02-01T00:00:00Z"`, `"dateReleased":"2025-02-03"`, 1),
	} {
		if _, err := ParseOfflineThreat(strings.NewReader(bad), "kev", offlineOptions()); err == nil {
			t.Fatal("accepted invalid catalog")
		}
	}
}
func TestOfflineSelectionLimitsAndSource(t *testing.T) {
	for _, n := range []int{200, 201} {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = fmt.Sprintf("CVE-2025-%04d", i)
		}
		_, err := NormalizeOfflineCVEs(ids)
		if (err == nil) != (n == 200) {
			t.Fatalf("n=%d error=%v", n, err)
		}
	}
	for _, source := range []string{"EPSS", "", "secret-source"} {
		_, err := ParseOfflineThreat(strings.NewReader(offlineCSV), source, offlineOptions())
		if err == nil || strings.Contains(err.Error(), source) && source != "" && source != "EPSS" {
			t.Fatalf("source error: %v", err)
		}
	}
	for _, tm := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)} {
		opts := offlineOptions()
		opts.ObservedAt = tm
		if _, err := ParseOfflineThreat(strings.NewReader(offlineCSV), "epss", opts); err == nil {
			t.Fatal("accepted invalid observation")
		}
	}
}
func TestOfflineWholeFeedEntryLimits(t *testing.T) {
	for _, n := range []int{offlineMaxCSVRows, offlineMaxCSVRows + 1} {
		raw := "#model_version:v1,score_date:2025-02-01\ncve,epss,percentile\n" + strings.Repeat("CVE-2025-1234,0,1\n", n)
		_, err := ParseOfflineThreat(strings.NewReader(raw), "epss", offlineOptions())
		if (err == nil) != (n == offlineMaxCSVRows) {
			t.Fatalf("rows=%d error=%v", n, err)
		}
	}
	for _, n := range []int{offlineMaxKEVEntries, offlineMaxKEVEntries + 1} {
		raw := fmt.Sprintf(`{"catalogVersion":"v1","dateReleased":"2025-02-01","count":%d,"vulnerabilities":[`, n) + strings.TrimSuffix(strings.Repeat(`{"cveID":"CVE-2025-1234","dateAdded":"2025-01-01"},`, n), ",") + "]}"
		_, err := ParseOfflineThreat(strings.NewReader(raw), "kev", offlineOptions())
		if (err == nil) != (n == offlineMaxKEVEntries) {
			t.Fatalf("entries=%d error=%v", n, err)
		}
	}
}
func TestOfflineValidatorRejectsInvalidProjection(t *testing.T) {
	for _, mutate := range []func(*model.SecurityEnrichmentFeed){
		func(f *model.SecurityEnrichmentFeed) { f.Source = "invalid" },
		func(f *model.SecurityEnrichmentFeed) { f.Version = "" },
		func(f *model.SecurityEnrichmentFeed) { f.PublishedAt = f.ObservedAt.Add(time.Hour) },
		func(f *model.SecurityEnrichmentFeed) { f.SelectedCVEs = []string{"CVE-2025-9999", "CVE-2025-1234"} },
		func(f *model.SecurityEnrichmentFeed) { f.SelectedCVEs = []string{"CVE-2025-1234", "CVE-2025-1234"} },
		func(f *model.SecurityEnrichmentFeed) { f.Entries[0].CVEID = "CVE-2025-5678" },
		func(f *model.SecurityEnrichmentFeed) { f.Entries = append(f.Entries, f.Entries[0]) },
		func(f *model.SecurityEnrichmentFeed) { f.Entries[0].EPSS = nil },
		func(f *model.SecurityEnrichmentFeed) { f.Entries[0].Percentile = nil },
		func(f *model.SecurityEnrichmentFeed) { f.Entries[0].KEV = true },
		func(f *model.SecurityEnrichmentFeed) { f.Entries[0].KEVDateAdded = &f.PublishedAt },
	} {
		f, err := ParseOfflineThreat(strings.NewReader(offlineCSV), "epss", offlineOptions())
		if err != nil {
			t.Fatal(err)
		}
		mutate(&f)
		if ValidateOfflineFeed(f) == nil {
			t.Fatal("invalid projection accepted")
		}
	}
	for _, mutate := range []func(*model.SecurityEnrichmentFeed){
		func(f *model.SecurityEnrichmentFeed) { f.Entries[0].KEV = false },
		func(f *model.SecurityEnrichmentFeed) { f.Entries[0].KEVDateAdded = nil },
		func(f *model.SecurityEnrichmentFeed) { v := 0.0; f.Entries[0].EPSS = &v },
		func(f *model.SecurityEnrichmentFeed) { v := 0.0; f.Entries[0].Percentile = &v },
		func(f *model.SecurityEnrichmentFeed) {
			d := f.PublishedAt.Add(time.Hour)
			f.Entries[0].KEVDateAdded = &d
		},
	} {
		f, err := ParseOfflineThreat(strings.NewReader(offlineKEV), "kev", offlineOptions())
		if err != nil {
			t.Fatal(err)
		}
		mutate(&f)
		if ValidateOfflineFeed(f) == nil {
			t.Fatal("invalid KEV projection accepted")
		}
	}
}

func TestOfflineRejectsNonstandardNumbersAndCaseMismatchedJSONKeys(t *testing.T) {
	for _, number := range []string{"0x1p-1", "0_1", " 0.5", "NaN", "+Inf"} {
		raw := strings.Replace(offlineCSV, "0.2,0.4", number+",0.4", 1)
		if _, err := ParseOfflineThreat(strings.NewReader(raw), "epss", offlineOptions()); err == nil {
			t.Fatalf("accepted numeric syntax %q", number)
		}
	}
	for _, key := range []string{"catalogVersion", "dateReleased", "count", "vulnerabilities", "cveID", "dateAdded"} {
		raw := strings.Replace(offlineKEV, `"`+key+`"`, `"`+strings.ToUpper(key)+`"`, 1)
		if _, err := ParseOfflineThreat(strings.NewReader(raw), "kev", offlineOptions()); err == nil {
			t.Fatalf("accepted key case variant %q", key)
		}
	}
}

func TestOfflineKEVTinyArrayBoundedBeforeMaterialization(t *testing.T) {
	for _, n := range []int{offlineMaxKEVEntries, offlineMaxKEVEntries + 1, 1000000} {
		raw := json.RawMessage("[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]")
		visited := 0
		count, err := offlineKEVArray(raw, func(item json.RawMessage) error {
			visited++
			if len(item) != 1 {
				t.Fatalf("retained more than one tiny entry: %d", len(item))
			}
			return nil
		})
		want := min(n, offlineMaxKEVEntries)
		if count != want || visited != want || (err == nil) != (n <= offlineMaxKEVEntries) {
			t.Fatalf("n=%d count=%d visited=%d err=%v", n, count, visited, err)
		}
		if n > offlineMaxKEVEntries {
			catalog := fmt.Sprintf(`{"catalogVersion":"v1","dateReleased":"2025-02-01","count":%d,"vulnerabilities":%s}`, n, raw)
			feed, err := ParseOfflineThreat(strings.NewReader(catalog), "kev", offlineOptions())
			if err == nil || !strings.Contains(err.Error(), "entry limit") || !reflect.DeepEqual(feed, model.SecurityEnrichmentFeed{}) {
				t.Fatalf("unbounded tiny array: %v", err)
			}
		}
	}
	// A malformed 20001st item must not even be decoded.
	raw := json.RawMessage("[" + strings.Repeat("0,", offlineMaxKEVEntries) + "INVALID]")
	count, err := offlineKEVArray(raw, func(json.RawMessage) error { return nil })
	if count != offlineMaxKEVEntries || err == nil || !strings.Contains(err.Error(), "entry limit") {
		t.Fatalf("decoded beyond bound: %d %v", count, err)
	}
	for _, raw := range []string{"null", "{}", "[0] [1]", "[0"} {
		if _, err := offlineKEVArray(json.RawMessage(raw), func(json.RawMessage) error { return nil }); err == nil {
			t.Fatalf("accepted list %q", raw)
		}
	}
}

func FuzzParseOfflineThreat(f *testing.F) {
	f.Add(offlineCSV, "epss")
	f.Add(offlineKEV, "kev")
	f.Add("null", "kev")
	f.Add("", "epss")
	f.Add(offlineCSV+"CVE-2025-1234,1,1\n", "epss")
	f.Fuzz(func(t *testing.T, raw, source string) {
		feed, err := ParseOfflineThreat(strings.NewReader(raw), source, offlineOptions())
		if err != nil {
			if !reflect.DeepEqual(feed, model.SecurityEnrichmentFeed{}) {
				t.Fatal("partial feed on error")
			}
			return
		}
		if err := ValidateOfflineFeed(feed); err != nil {
			t.Fatalf("successful parse produced invalid feed: %v", err)
		}
	})
}
