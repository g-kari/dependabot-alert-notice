package scoring

import (
	"slices"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestCalculateEPSSFreshnessUsesSnapshotClock(t *testing.T) {
	at := time.Date(2000, 1, 1, 12, 0, 0, 0, time.UTC)
	epss := .001
	for _, tc := range []struct {
		name    string
		fetched time.Time
		stale   bool
	}{
		{"historical fresh snapshot", at.Add(-time.Hour), false},
		{"expired", at.Add(-73 * time.Hour), true},
		{"future timestamp", at.Add(time.Hour), true},
		{"missing timestamp", time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := model.ScoreInput{At: at,
				Profile:    model.ServiceProfile{Exposure: model.ExposureInternet, BusinessCriticality: model.RiskHigh, MaxOutageMinutes: 240, DataClassification: model.RiskConfidential, IntegrityImpact: model.RiskHigh, PrivilegeScope: model.PrivilegeServiceOnly},
				Assessment: model.CVEAssessment{Applicability: "affected", Reachability: "reachable", Facts: map[string]string{"required_privilege": "none"}},
				Threat:     model.ThreatSnapshot{KEVKnown: true, EPSS: &epss, FetchedAt: tc.fetched},
				Technical:  model.TechnicalImpact{Confidentiality: model.Interval{Low: 1, High: 1}},
			}
			result, err := Calculate(input)
			if err != nil {
				t.Fatal(err)
			}
			if tc.stale {
				if result.Status != "provisional" || result.Likelihood.High != 100 || !slices.Contains(result.MissingFacts, "EPSSの鮮度") {
					t.Fatalf("stale EPSS treated as safe: %+v", result)
				}
			} else if result.Status != "confirmed" || result.Likelihood.Low != result.Likelihood.High {
				t.Fatalf("fresh snapshot depends on wall clock: %+v", result)
			}
		})
	}
}

func TestCalculateEPSSFreshnessKeepsSourceAndFetchClocksSeparate(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	old := at.Add(-96 * time.Hour)
	epss := .001
	for _, threat := range []model.ThreatSnapshot{
		{EPSS: &epss, FetchedAt: at, EPSSFetchedAt: &old},
		{EPSS: &epss, FetchedAt: at, EPSSDate: &old},
	} {
		result, err := Calculate(model.ScoreInput{At: at, Profile: model.ServiceProfile{Exposure: model.ExposureInternet}, Threat: threat, Assessment: model.CVEAssessment{Facts: map[string]string{"required_privilege": "none"}}})
		if err != nil {
			t.Fatal(err)
		}
		if result.Likelihood.High != 100 || !slices.Contains(result.MissingFacts, "EPSSの鮮度") {
			t.Fatalf("stale source treated as fresh: %+v", result)
		}
		threat.KEV = true
		result, err = Calculate(model.ScoreInput{At: at, Profile: model.ServiceProfile{Exposure: model.ExposureInternet}, Threat: threat})
		if err != nil {
			t.Fatal(err)
		}
		if result.Likelihood.Low < 85 {
			t.Fatalf("stale EPSS erased KEV positive: %+v", result)
		}
	}
}
