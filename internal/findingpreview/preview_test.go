package findingpreview

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/scoring"
)

func fixture() Input {
	at := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	b := Binding{FindingID: "finding-a", AssetID: "asset-a", CVE: "CVE-2099-0001", ProfileID: "profile-a", Repo: "synthetic/repo"}
	zero := 0.0
	return Input{At: at, Binding: b, Finding: model.Finding{ID: b.FindingID, AssetID: b.AssetID, Category: "vulnerability", VulnerabilityID: b.CVE, Severity: model.Severity("critical")},
		Asset:       model.Asset{ID: b.AssetID, Criticality: "critical", Environment: "production"},
		Observation: &model.Observation{FindingID: b.FindingID, Source: "trivy", SourceFindingID: "synthetic-a"},
		Profile:     &model.ServiceProfile{ID: b.ProfileID, Repo: b.Repo, Exposure: model.ExposureInternet, BusinessCriticality: model.RiskCritical, MaxOutageMinutes: 60, DataClassification: model.RiskRestricted, IntegrityImpact: model.RiskCritical, PrivilegeScope: model.PrivilegeSharedControl, Environment: model.EnvironmentProduction, Authentication: model.AuthPrivileged},
		Assessment:  &model.CVEAssessment{ProfileID: b.ProfileID, Repo: b.Repo, AdvisoryKey: "cve:" + b.CVE, Applicability: "affected", Reachability: "reachable", Facts: map[string]string{"user_interaction": "required"}},
		CVSS:        &CVSS{Binding: b, Known: true, Score: 7.2, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},
		Enrichment:  &model.FindingEnrichment{CVEID: b.CVE, EPSS: &model.SecurityEnrichmentEvidence{Source: "epss", Version: "synthetic-v1", RunID: "synthetic-epss", EPSS: &zero, Percentile: &zero, PublishedAt: at.Add(-24 * time.Hour), ObservedAt: at.Add(-23 * time.Hour), Fresh: true}},
	}
}
func addKEV(in *Input) {
	date := in.At.Add(-48 * time.Hour)
	in.Enrichment.KEV = &model.SecurityEnrichmentEvidence{Source: "kev", Version: "synthetic-v1", RunID: "synthetic-kev", KEV: true, KEVDateAdded: &date, PublishedAt: in.At.Add(-24 * time.Hour), ObservedAt: in.At.Add(-23 * time.Hour), Fresh: true}
}
func require(t *testing.T, ok bool, message string) {
	t.Helper()
	if !ok {
		t.Fatal(message)
	}
}
func eligible(t *testing.T, in Input) Result {
	t.Helper()
	r, err := Calculate(in)
	if err != nil || r.AdapterState != "eligible" || r.ScoreResult == nil || r.InputSnapshot == nil {
		t.Fatalf("eligible: state=%s err=%v result=%+v", r.AdapterState, err, r)
	}
	oracle, err := scoring.Calculate(*r.InputSnapshot)
	if err != nil || !reflect.DeepEqual(oracle, *r.ScoreResult) {
		t.Fatalf("model result altered: %v %+v vs %+v", err, oracle, r.ScoreResult)
	}
	return r
}
func rejected(t *testing.T, in Input, state string) {
	t.Helper()
	r, err := Calculate(in)
	if r.AdapterState != state || r.ScoreResult != nil || r.InputSnapshot != nil || (state == "invalid" && err == nil) || (state == "unsupported" && err != nil) {
		t.Fatalf("reject %s: %+v %v", state, r, err)
	}
}
func oldEPSS(in *Input) {
	in.Enrichment.EPSS.PublishedAt = in.At.Add(-74 * time.Hour)
	in.Enrichment.EPSS.ObservedAt = in.At.Add(-73 * time.Hour)
}
func expectScore(t *testing.T, r Result, n int, p, s string) {
	t.Helper()
	x := r.ScoreResult
	if x.Lower != n || x.Upper != n || x.Priority != p || x.Status != s {
		t.Fatalf("want %d/%s/%s got %+v", n, p, s, x)
	}
}

func TestContractAcceptance(t *testing.T) {
	t.Run("P01_known_zero_example_A", func(t *testing.T) {
		r := eligible(t, fixture())
		expectScore(t, r, 76, "today", "confirmed")
		require(t, r.PreviewOnly && r.ContractVersion == ContractVersion && r.BasisCommit == BasisCommit && r.ScoreResult.ModelVersion == "urgency-v1", "missing contract identity")
	})
	t.Run("P02_deterministic", func(t *testing.T) {
		in := fixture()
		require(t, reflect.DeepEqual(eligible(t, in), eligible(t, in)), "non-deterministic result")
	})
	t.Run("P03_explicit_clock", func(t *testing.T) { in := fixture(); in.At = time.Time{}; rejected(t, in, "invalid") })
	t.Run("P04_asset_identity", func(t *testing.T) { in := fixture(); in.Asset.ID = "other"; rejected(t, in, "invalid") })
	t.Run("P05_same_CVE_separate_asset", func(t *testing.T) {
		a := eligible(t, fixture())
		in := fixture()
		in.Finding.ID = "finding-b"
		in.Finding.AssetID = "asset-b"
		in.Asset.ID = "asset-b"
		in.Observation = nil
		in.Profile = nil
		in.Assessment = nil
		in.CVSS = nil
		b := eligible(t, in)
		require(t, a.FindingID != b.FindingID && a.AssetID != b.AssetID && b.InputSnapshot.Profile.ID == "" && b.ScoreResult.Status == "provisional", "cross-asset reuse")
	})
	t.Run("P06_binding", func(t *testing.T) {
		for _, mutate := range []func(*Input){func(i *Input) { i.Binding.FindingID = "other" }, func(i *Input) { i.Assessment.Repo = "other" }, func(i *Input) { i.Assessment.ProfileID = "other" }, func(i *Input) { i.CVSS.Binding.AssetID = "other" }} {
			in := fixture()
			mutate(&in)
			rejected(t, in, "invalid")
		}
	})
	t.Run("P07_enrichment_CVE", func(t *testing.T) { in := fixture(); in.Enrichment.CVEID = "CVE-2099-9999"; rejected(t, in, "invalid") })
	t.Run("P08_secret", func(t *testing.T) { in := fixture(); in.Finding.Category = "secret"; rejected(t, in, "unsupported") })
	t.Run("P09_rule_title", func(t *testing.T) {
		in := fixture()
		in.Finding.Category = "code_scanning"
		in.Finding.VulnerabilityID = ""
		in.Finding.Title = "CVE-2099-0001"
		rejected(t, in, "unsupported")
	})
	t.Run("P10_GHSA", func(t *testing.T) {
		in := fixture()
		in.Finding.VulnerabilityID = "GHSA-xxxx-xxxx-xxxx"
		rejected(t, in, "unsupported")
	})
	t.Run("P11_noncanonical", func(t *testing.T) {
		for _, s := range []string{"cve-2099-0001", " CVE-2099-0001", "CVE-2099-001", "CVE-2099-0001 "} {
			in := fixture()
			in.Finding.VulnerabilityID = s
			rejected(t, in, "unsupported")
		}
	})
	t.Run("P12_missing_provenance", func(t *testing.T) {
		in := fixture()
		in.Observation = nil
		r := eligible(t, in)
		require(t, r.Source == "" && r.SourceNativeID == "" && slices.Contains(r.MissingInputs, "source") && slices.Contains(r.MissingInputs, "source_native_id"), "invented provenance")
	})
	t.Run("P13_missing_CVSS", func(t *testing.T) {
		in := fixture()
		in.CVSS = nil
		r := eligible(t, in)
		require(t, !r.InputSnapshot.CVSSKnown && r.InputSnapshot.Technical.Confidentiality == (model.Interval{Low: 0, High: 1}) && r.InputSnapshot.Technical.Privilege.High == 1, "severity inferred technical impact")
	})
	t.Run("P14_invalid_CVSS", func(t *testing.T) {
		for _, n := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 11, -1} {
			in := fixture()
			in.CVSS.Score = n
			rejected(t, in, "invalid")
		}
	})
	t.Run("P15_numeric_only_CVSS", func(t *testing.T) {
		in := fixture()
		in.CVSS.Vector = ""
		r := eligible(t, in)
		require(t, r.InputSnapshot.Technical.Integrity == (model.Interval{Low: 0, High: 1}), "numeric score fixed axes")
	})
	t.Run("P16_missing_profile", func(t *testing.T) {
		in := fixture()
		in.Profile = nil
		in.Assessment = nil
		r := eligible(t, in)
		require(t, r.InputSnapshot.Profile.BusinessCriticality == model.RiskUnknown && r.ScoreResult.Status == "provisional" && slices.Contains(r.MissingInputs, "profile"), "asset criticality reused")
	})
	t.Run("P17_unresolved_profile", func(t *testing.T) { in := fixture(); in.Profile.Extends = "parent"; rejected(t, in, "invalid") })
	t.Run("P18_missing_assessment", func(t *testing.T) {
		in := fixture()
		in.Assessment = nil
		r := eligible(t, in)
		require(t, r.InputSnapshot.Assessment.Applicability == "unknown" && r.InputSnapshot.Assessment.Reachability == "unknown" && len(r.InputSnapshot.Assessment.Facts) == 0, "assessment invented")
	})
	t.Run("P19_evidence_expiry_boundary", func(t *testing.T) {
		in := fixture()
		in.Assessment.Evidence = []model.Evidence{{ExpiresAt: in.At}}
		r := eligible(t, in)
		require(t, r.ScoreResult.Status == "provisional" && slices.Contains(r.ScoreResult.MissingFacts, "根拠の有効期限"), "expiry ignored")
	})
	t.Run("P20_closed_not_not_affected", func(t *testing.T) {
		in := fixture()
		in.Finding.SourceStatus = model.SourceStatusResolved
		in.Finding.TriageStatus = model.TriageStatusClosed
		r := eligible(t, in)
		expectScore(t, r, 76, "today", "confirmed")
		require(t, r.SourceStatus == model.SourceStatusResolved && r.TriageStatus == model.TriageStatusClosed, "lifecycle altered")
	})
	t.Run("P21_missing_threat", func(t *testing.T) {
		in := fixture()
		in.Enrichment = nil
		r := eligible(t, in)
		require(t, r.InputSnapshot.Threat.EPSS == nil && !r.InputSnapshot.Threat.KEVKnown && r.ScoreResult.Status == "provisional", "missing threat became safe")
	})
	t.Run("P22_zero_not_missing", func(t *testing.T) {
		r := eligible(t, fixture())
		require(t, r.InputSnapshot.Threat.EPSS != nil && *r.InputSnapshot.Threat.EPSS == 0 && !slices.Contains(r.MissingInputs, "epss"), "zero lost")
		expectScore(t, r, 76, "today", "confirmed")
	})
	t.Run("P23_invalid_probabilities", func(t *testing.T) {
		for _, n := range []float64{-0.1, 1.1, math.NaN(), math.Inf(1)} {
			for _, percentile := range []bool{false, true} {
				in := fixture()
				if percentile {
					in.Enrichment.EPSS.Percentile = &n
				} else {
					in.Enrichment.EPSS.EPSS = &n
				}
				rejected(t, in, "invalid")
			}
		}
	})
	t.Run("P24_fresh_boundary", func(t *testing.T) {
		in := fixture()
		in.Enrichment.EPSS.PublishedAt = in.At.Add(-72 * time.Hour)
		in.Enrichment.EPSS.ObservedAt = in.Enrichment.EPSS.PublishedAt
		r := eligible(t, in)
		require(t, r.EPSS.Fresh, "inclusive boundary stale")
		expectScore(t, r, 76, "today", "confirmed")
	})
	t.Run("P25_old_publication", func(t *testing.T) {
		in := fixture()
		in.Enrichment.EPSS.PublishedAt = in.At.Add(-72*time.Hour - time.Nanosecond)
		r := eligible(t, in)
		require(t, !r.EPSS.Fresh && r.ScoreResult.Status == "provisional" && slices.Contains(r.ScoreResult.MissingFacts, "EPSSの鮮度") && r.InputSnapshot.Threat.EPSSDate.Equal(in.Enrichment.EPSS.PublishedAt), "publication clock lost")
	})
	t.Run("P26_independent_clocks", func(t *testing.T) {
		in := fixture()
		oldEPSS(&in)
		addKEV(&in)
		r := eligible(t, in)
		require(t, !r.EPSS.Fresh && r.KEV.Fresh && r.InputSnapshot.Threat.EPSSFetchedAt.Equal(in.Enrichment.EPSS.ObservedAt) && r.InputSnapshot.Threat.FetchedAt.Equal(in.Enrichment.KEV.ObservedAt), "KEV refreshed EPSS")
	})
	t.Run("P27_invalid_times", func(t *testing.T) {
		for _, kind := range []string{"publication-zero", "observation-zero", "publication-future", "observation-future"} {
			in := fixture()
			e := in.Enrichment.EPSS
			switch kind {
			case "publication-zero":
				e.PublishedAt = time.Time{}
			case "observation-zero":
				e.ObservedAt = time.Time{}
			case "publication-future":
				e.PublishedAt = in.At.Add(time.Hour)
			case "observation-future":
				e.ObservedAt = in.At.Add(time.Hour)
			}
			rejected(t, in, "invalid")
		}
	})
	t.Run("P28_reversed_times", func(t *testing.T) {
		in := fixture()
		in.Enrichment.EPSS.PublishedAt = in.Enrichment.EPSS.ObservedAt.Add(time.Nanosecond)
		rejected(t, in, "invalid")
	})
	t.Run("P29_reported_fresh_not_trusted", func(t *testing.T) {
		in := fixture()
		oldEPSS(&in)
		r := eligible(t, in)
		require(t, r.EPSS.ReportedFresh && !r.EPSS.Fresh, "API freshness reused")
	})
	t.Run("P30_positive_KEV", func(t *testing.T) {
		in := fixture()
		addKEV(&in)
		r := eligible(t, in)
		expectScore(t, r, 95, "immediate", "confirmed")
		require(t, r.InputSnapshot.Assessment.LocalActivity == "" && r.InputSnapshot.Threat.LocalActivity == "" && r.KEV.RunID != r.EPSS.RunID, "KEV became incident")
	})
	t.Run("P31_historical_KEV", func(t *testing.T) {
		in := fixture()
		addKEV(&in)
		e := in.Enrichment.KEV
		e.PublishedAt = in.At.Add(-74 * time.Hour)
		e.ObservedAt = in.At.Add(-73 * time.Hour)
		d := in.At.Add(-80 * time.Hour)
		e.KEVDateAdded = &d
		r := eligible(t, in)
		expectScore(t, r, 95, "immediate", "confirmed")
		require(t, !r.KEV.Fresh && r.KEV.HistoricalPositive && len(r.MappingWarnings) > 0, "historical warning lost")
	})
	t.Run("P32_missing_KEV_not_negative", func(t *testing.T) {
		r := eligible(t, fixture())
		require(t, !r.InputSnapshot.Threat.KEV && !r.InputSnapshot.Threat.KEVKnown && slices.Contains(r.MissingInputs, "kev"), "missing KEV negative")
	})
	t.Run("P33_invalid_positive_evidence", func(t *testing.T) {
		for _, mutate := range []func(*Input){func(i *Input) { i.Enrichment.KEV.KEV = false }, func(i *Input) { i.Enrichment.KEV.Source = "epss" }, func(i *Input) { i.Enrichment.EPSS.Source = "kev" }} {
			in := fixture()
			addKEV(&in)
			mutate(&in)
			rejected(t, in, "invalid")
		}
	})
	t.Run("P34_stale_EPSS_positive_KEV", func(t *testing.T) {
		in := fixture()
		oldEPSS(&in)
		addKEV(&in)
		r := eligible(t, in)
		expectScore(t, r, 95, "immediate", "confirmed")
		require(t, slices.Contains(r.MappingWarnings, "stale_epss") && !r.EPSS.Fresh, "stale evidence hidden")
	})
	t.Run("P35_explicit_incident", func(t *testing.T) {
		in := fixture()
		in.Assessment.LocalActivity = "confirmed_compromise"
		r := eligible(t, in)
		expectScore(t, r, 100, "incident", "confirmed")
	})
	t.Run("P36_no_mutation_or_aliases", func(t *testing.T) {
		in := fixture()
		addKEV(&in)
		in.Assessment.Evidence = []model.Evidence{{ID: "evidence"}}
		in.Assessment.EvidenceByFact = map[string][]model.Evidence{"x": {{ID: "fact-evidence"}}}
		stamp := in.At
		in.Profile.ReviewedAt = &stamp
		before := mustJSON(t, in)
		r := eligible(t, in)
		eligible(t, in)
		after := mustJSON(t, in)
		require(t, string(before) == string(after), "input mutated")
		r.InputSnapshot.Assessment.Facts["user_interaction"] = "changed"
		r.InputSnapshot.Assessment.Evidence[0].ID = "changed"
		r.InputSnapshot.Assessment.EvidenceByFact["x"][0].ID = "changed"
		*r.InputSnapshot.Profile.ReviewedAt = time.Time{}
		*r.InputSnapshot.Threat.EPSS = 0.9
		*r.InputSnapshot.Threat.KEVDate = time.Time{}
		after = mustJSON(t, in)
		require(t, string(before) == string(after), "result aliases caller data")
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMissingEverythingRemainsUnknown(t *testing.T) {
	in := fixture()
	in.Profile = nil
	in.Assessment = nil
	in.CVSS = nil
	in.Enrichment = nil
	r := eligible(t, in)
	require(t, r.ScoreResult.Status == "provisional" && r.ScoreResult.Confidence == "insufficient", "example C must not become safe")
	require(t, r.InputOrigins["profile.exposure"].Source == "missing_input_default" && r.InputOrigins["technical.integrity"].Source == "existing_cvss_normalizer" && r.InputOrigins["technical.integrity"].MissingReason != "", "input origins missing")
}

func TestAdditionalMalformedInputs(t *testing.T) {
	cases := map[string]func(*Input){
		"empty_finding": func(i *Input) { i.Finding.ID = "" }, "empty_asset": func(i *Input) { i.Asset.ID = "" },
		"wrong_observation":       func(i *Input) { i.Observation.FindingID = "other" },
		"unknown_CVSS_with_value": func(i *Input) { i.CVSS.Known = false },
		"missing_version":         func(i *Input) { i.Enrichment.EPSS.Version = "" },
		"missing_run":             func(i *Input) { i.Enrichment.EPSS.RunID = "" },
		"missing_probability":     func(i *Input) { i.Enrichment.EPSS.EPSS = nil },
		"KEV_future":              func(i *Input) { addKEV(i); i.Enrichment.KEV.ObservedAt = i.At.Add(time.Hour) },
		"KEV_missing_clock":       func(i *Input) { addKEV(i); i.Enrichment.KEV.PublishedAt = time.Time{} },
		"KEV_missing_added":       func(i *Input) { addKEV(i); i.Enrichment.KEV.KEVDateAdded = nil },
		"KEV_future_added":        func(i *Input) { addKEV(i); x := i.At.Add(time.Hour); i.Enrichment.KEV.KEVDateAdded = &x },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) { in := fixture(); mutate(&in); rejected(t, in, "invalid") })
	}
}

func TestExampleAIndependentMapping(t *testing.T) {
	in := fixture()
	r := eligible(t, in)
	actual := r.InputSnapshot
	require(t, reflect.DeepEqual(actual.Profile, *in.Profile) && reflect.DeepEqual(actual.Assessment, *in.Assessment), "bound snapshots changed")
	zero := 0.0
	pub := in.At.Add(-24 * time.Hour)
	obs := in.At.Add(-23 * time.Hour)
	want := model.ThreatSnapshot{AdvisoryKey: "cve:CVE-2099-0001", EPSS: &zero, EPSSPercentile: &zero, EPSSDate: &pub, EPSSFetchedAt: &obs}
	require(t, reflect.DeepEqual(actual.Threat, want), "independent threat input mismatch")
	one := model.Interval{Low: 1, High: 1}
	none := model.Interval{}
	require(t, actual.Technical.Confidentiality == one && actual.Technical.Integrity == one && actual.Technical.Availability == one && actual.Technical.Privilege == none && actual.CVSS == 7.2 && actual.CVSSKnown && actual.At.Equal(in.At), "independent score inputs mismatch")
	require(t, r.InputOrigins["profile.exposure"].Source == "bound_resolved_profile" && r.InputOrigins["profile.exposure"].MissingReason == "", "explicit origin lost")
}
