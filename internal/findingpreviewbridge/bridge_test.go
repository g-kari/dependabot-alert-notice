package findingpreviewbridge

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreviewwire"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func baseFixture() (model.Finding, model.Asset, time.Time) {
	return model.Finding{ID: "finding-1", AssetID: "asset-1", Category: "vulnerability", VulnerabilityID: "CVE-2099-0001"}, model.Asset{ID: "asset-1"}, time.Date(2099, 1, 4, 0, 0, 0, 0, time.UTC)
}

func TestBuildMatchesWireAndTypedAdapter(t *testing.T) {
	f, a, at := baseFixture()
	zero := 0.0
	date := at.Add(-72 * time.Hour)
	for _, name := range []string{"absent", "zero", "kev", "stale", "boundary"} {
		t.Run(name, func(t *testing.T) {
			at := at
			var e *model.FindingEnrichment
			if name != "absent" {
				e = &model.FindingEnrichment{CVEID: f.VulnerabilityID, EPSS: &model.SecurityEnrichmentEvidence{Source: "epss", Version: "synthetic", RunID: "run", PublishedAt: date, ObservedAt: date, EPSS: &zero, RawRef: "PRIVATE-RAW"}}
				if name == "kev" || name == "stale" {
					e.KEV = &model.SecurityEnrichmentEvidence{Source: "kev", Version: "synthetic", RunID: "run", PublishedAt: date, ObservedAt: date, KEV: true, KEVDateAdded: &date}
				}
			}
			if name == "stale" {
				at = at.Add(time.Nanosecond)
			}
			data, result, err := Build(f, a, "trivy", "native-1", e, at)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := findingpreviewwire.Decode(data)
			if err != nil || !reflect.DeepEqual(result, decoded) {
				t.Fatalf("wire mismatch: %v", err)
			}
			expected, err := findingpreview.Calculate(findingpreview.Input{Finding: f, Asset: a, Observation: &model.Observation{FindingID: f.ID, Source: "trivy", SourceFindingID: "native-1"}, Enrichment: e, At: at})
			if err != nil || !reflect.DeepEqual(result, expected) {
				t.Fatalf("adapter mismatch: %v", err)
			}
			if strings.Contains(string(data), "PRIVATE-RAW") || strings.Contains(string(data), "raw_ref") {
				t.Fatal("raw reference leaked")
			}
			if name == "boundary" && !result.EPSS.Fresh {
				t.Fatal("inclusive boundary lost")
			}
			if name == "stale" && (result.KEV.Fresh || !result.KEV.HistoricalPositive) {
				t.Fatal("historical KEV changed")
			}
			if name == "zero" && (result.InputSnapshot.Threat.EPSS == nil || *result.InputSnapshot.Threat.EPSS != 0) {
				t.Fatal("zero lost")
			}
		})
	}
}

func TestBuildRejectsInvalidProjectionWithoutPartialOutput(t *testing.T) {
	for _, name := range []string{"binding", "cve-binding", "source", "future", "missing-probability", "nan", "wrong-fields", "bad-utf8", "long-string", "long-context", "enum", "half-provenance", "clock", "wrong-zone", "oversize"} {
		t.Run(name, func(t *testing.T) {
			f, a, at := baseFixture()
			v := 0.1
			e := &model.FindingEnrichment{CVEID: f.VulnerabilityID, EPSS: &model.SecurityEnrichmentEvidence{Source: "epss", Version: "v1", RunID: "run", PublishedAt: at, ObservedAt: at, EPSS: &v}}
			source, native := "trivy", "native"
			switch name {
			case "binding":
				a.ID = "other"
			case "cve-binding":
				e.CVEID = "CVE-2099-0002"
			case "source":
				e.EPSS.Source = "kev"
			case "future":
				e.EPSS.ObservedAt = at.Add(time.Nanosecond)
			case "missing-probability":
				e.EPSS.EPSS = nil
			case "nan":
				v = math.NaN()
			case "wrong-fields":
				e.EPSS.KEV = true
			case "bad-utf8":
				f.ID = string([]byte{0xff})
			case "long-string":
				native = strings.Repeat("x", 257)
			case "long-context":
				a.Environment = strings.Repeat("x", 65)
			case "enum":
				f.Severity = "unknown"
			case "half-provenance":
				native = ""
			case "clock":
				at = time.Time{}
			case "wrong-zone":
				at = time.Date(2099, 1, 1, 1, 1, 1, 0, time.FixedZone("bad", 24*3600))
			case "oversize":
				f.ID = strings.Repeat("x", findingpreviewwire.MaxBytes+1)
			}
			data, out, err := Build(f, a, source, native, e, at)
			if err != ErrSnapshot || data != nil || !reflect.DeepEqual(out, findingpreview.Result{}) {
				t.Fatalf("partial result/error: %s %+v %v", data, out, err)
			}
		})
	}
}

func TestBuildUnsupportedAndMissingProvenanceRemainVisible(t *testing.T) {
	for _, category := range []string{"vulnerability", "secret"} {
		f, a, at := baseFixture()
		f.Category = category
		data, out, err := Build(f, a, "", "", nil, at)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err = json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw["provenance"]; ok {
			t.Fatal("fabricated provenance")
		}
		if out.Source != "" || (category == "vulnerability" && len(out.MissingInputs) == 0) {
			t.Fatal("missing provenance hidden")
		}
		if category == "secret" && (out.AdapterState != "unsupported" || out.ScoreResult != nil) {
			t.Fatal("unsupported scored")
		}
	}
	f, a, at := baseFixture()
	f.VulnerabilityID = "GHSA-fictional"
	_, out, err := Build(f, a, "", "", nil, at)
	if err != nil || out.AdapterState != "unsupported" || out.ScoreResult != nil {
		t.Fatal("noncanonical CVE scored")
	}
}
