package threat

import (
	"strings"
	"testing"
	"time"
)

func TestParseKEV(t *testing.T) {
	got, err := ParseKEV([]byte(`{"vulnerabilities":[{"cveID":"cve-2024-1234","dateAdded":"2024-01-02"}]}`), time.Now())
	if err != nil || !got["CVE-2024-1234"].KEV {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestParseEPSS(t *testing.T) {
	got, err := ParseEPSS(strings.NewReader("cve,epss,percentile\nCVE-2024-1234,0.9,0.99\n"), time.Now())
	if err != nil || got["CVE-2024-1234"].EPSS == nil || *got["CVE-2024-1234"].EPSS != .9 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestParseEPSSPreservesSourceDate(t *testing.T) {
	fetched := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, body := range []string{
		"#model_version:v2026,score_date:2026-09-25\ncve,epss,percentile\nCVE-2026-1234,0.01,0.2\n",
		"cve,epss,percentile,date\nCVE-2026-1234,0.01,0.2,2026-09-25\n",
	} {
		got, err := ParseEPSS(strings.NewReader(body), fetched)
		if err != nil {
			t.Fatal(err)
		}
		date := got["CVE-2026-1234"].EPSSDate
		if date == nil || date.Format("2006-01-02") != "2026-09-25" {
			t.Fatalf("source date lost: %+v", got)
		}
	}
}

func TestParseEPSSRejectsInvalidProbabilitiesAndDates(t *testing.T) {
	for _, row := range []string{
		"CVE-2026-1234,NaN,0.2,2026-10-02",
		"CVE-2026-1234,Inf,0.2,2026-10-02",
		"CVE-2026-1234,-0.1,0.2,2026-10-02",
		"CVE-2026-1234,0.2,1.1,2026-10-02",
		"CVE-2026-1234,0.2,NaN,2026-10-02",
		"CVE-2026-1234,0.2,0.2,not-a-date",
	} {
		if _, err := ParseEPSS(strings.NewReader("cve,epss,percentile,date\n"+row+"\n"), time.Now()); err == nil {
			t.Errorf("invalid row accepted: %s", row)
		}
	}
}
