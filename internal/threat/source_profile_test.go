package threat

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// These inputs are authored synthetic examples of the existing local projection
// parser's subset, not captured provider responses or full wire conformance proof.
const sourceProfileEPSS = "#model_version:synthetic-profile,score_date:2026-11-09\ncve,epss,percentile\nCVE-2026-5678,0.25,0.75\nCVE-2026-1234,0,0\n"

// This fixture includes every required field from CISA's schema at blob
// ec422845b354f58250d2e99cdfcce17a18659423. No catalog data was retrieved.
const sourceProfileKEV = `{
  "catalogVersion": "synthetic-profile.1",
  "dateReleased": "2026-11-09T00:00:00Z",
  "count": 1,
  "vulnerabilities": [{
    "cveID": "CVE-2026-1234",
    "vendorProject": "Synthetic vendor",
    "product": "Synthetic product",
    "vulnerabilityName": "Synthetic test vulnerability",
    "dateAdded": "2026-11-08",
    "shortDescription": "Authored solely for a local projection test.",
    "requiredAction": "No real-world action; synthetic fixture.",
    "dueDate": "2026-11-30"
  }]
}`

func TestOfflineSourceProfileAcceptsCurrentSyntheticEPSSSubset(t *testing.T) {
	observed := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	selected := []string{"CVE-2026-1234", "CVE-2026-5678", "CVE-2026-9999"}
	feed, err := ParseOfflineThreat(strings.NewReader(sourceProfileEPSS), "epss", OfflineOptions{CVEs: selected, ObservedAt: observed})
	if err != nil {
		t.Fatal(err)
	}
	published := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	if feed.Source != "epss" || feed.Version != "synthetic-profile" || !feed.PublishedAt.Equal(published) || !feed.ObservedAt.Equal(observed) || !reflect.DeepEqual(feed.SelectedCVEs, selected) || len(feed.Entries) != 2 {
		t.Fatalf("metadata, selection or independent clocks changed: %+v", feed)
	}
	zero, nonzero := feed.Entries[0], feed.Entries[1]
	if zero.CVEID != selected[0] || zero.EPSS == nil || *zero.EPSS != 0 || zero.Percentile == nil || *zero.Percentile != 0 || nonzero.CVEID != selected[1] || nonzero.EPSS == nil || *nonzero.EPSS != 0.25 || nonzero.Percentile == nil || *nonzero.Percentile != 0.75 {
		t.Fatalf("sorted known zero/nonzero values or missing-CVE absence changed: %+v", feed.Entries)
	}
}

func TestOfflineSourceProfileKEVRequiredFieldFixtureAndProjectionLimits(t *testing.T) {
	observed := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	selected := []string{"CVE-2026-1234", "CVE-2026-9999"}
	options := OfflineOptions{CVEs: selected, ObservedAt: observed}
	full, err := ParseOfflineThreat(strings.NewReader(sourceProfileKEV), "kev", options)
	if err != nil {
		t.Fatal(err)
	}
	published := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	added := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	if full.Source != "kev" || full.Version != "synthetic-profile.1" || !full.PublishedAt.Equal(published) || !full.ObservedAt.Equal(observed) || !reflect.DeepEqual(full.SelectedCVEs, selected) || len(full.Entries) != 1 {
		t.Fatalf("KEV metadata, missing-CVE absence or independent clocks changed: %+v", full)
	}
	entry := full.Entries[0]
	if entry.CVEID != selected[0] || !entry.KEV || entry.KEVDateAdded == nil || !entry.KEVDateAdded.Equal(added) || entry.EPSS != nil || entry.Percentile != nil {
		t.Fatalf("positive-only KEV projection changed: %+v", entry)
	}

	// Characterize existing limits without tightening the public offline API:
	// required narrative/dueDate fields are not enforced, and date-only catalog
	// publication is accepted. These are not full official-schema validation.
	minimal := `{"catalogVersion":"synthetic-profile.1","dateReleased":"2026-11-09T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-11-08"}]}`
	for name, raw := range map[string]string{
		"projection-minimal": minimal,
		"date-only-release":  strings.Replace(minimal, "2026-11-09T00:00:00Z", "2026-11-09", 1),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseOfflineThreat(strings.NewReader(raw), "kev", options)
			if err != nil || !reflect.DeepEqual(got, full) {
				t.Fatalf("existing projection subset changed: got=%+v err=%v", got, err)
			}
		})
	}
}
