package scoring

import (
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestCalculate_ExploitedPublicCriticalServiceIsImmediate(t *testing.T) {
	now := time.Now()
	result, err := Calculate(model.ScoreInput{
		At: now, CVSS: 9.8, CVSSKnown: true,
		Profile:    model.ServiceProfile{Exposure: model.ExposureInternet, BusinessCriticality: model.RiskCritical, MaxOutageMinutes: 60, PrivilegeScope: model.PrivilegeProductionWrite},
		Assessment: model.CVEAssessment{Applicability: "affected", Reachability: "reachable", LocalActivity: "external_exploitation", Facts: map[string]string{"attack_type": "unauthenticated_rce"}},
		Threat:     model.ThreatSnapshot{KEV: true},
		Technical:  model.TechnicalImpact{Confidentiality: model.Interval{Low: 1, High: 1}, Integrity: model.Interval{Low: 1, High: 1}, Availability: model.Interval{Low: 1, High: 1}, Privilege: model.Interval{Low: 1, High: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Lower != 99 || result.Upper != 100 || result.Priority != "immediate" {
		t.Fatalf("result = %+v", result)
	}
}

func TestCalculate_UnknownReachabilityProducesRange(t *testing.T) {
	result, err := Calculate(model.ScoreInput{
		At: time.Now(), CVSSKnown: true, CVSS: 9.8,
		Profile:    model.ServiceProfile{Exposure: model.ExposureInternet, BusinessCriticality: model.RiskCritical, MaxOutageMinutes: 60, PrivilegeScope: model.PrivilegeProductionWrite},
		Assessment: model.CVEAssessment{Applicability: "affected", Reachability: "unknown"},
		Technical:  model.TechnicalImpact{Confidentiality: model.Interval{Low: 1, High: 1}, Integrity: model.Interval{Low: 1, High: 1}, Availability: model.Interval{Low: 1, High: 1}, Privilege: model.Interval{Low: 1, High: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "provisional" || result.Upper <= result.Lower || len(result.MissingFacts) == 0 {
		t.Fatalf("result = %+v", result)
	}
}

func TestCalculate_InvalidCVSS(t *testing.T) {
	_, err := Calculate(model.ScoreInput{At: time.Now(), CVSSKnown: true, CVSS: 11})
	if err == nil {
		t.Fatal("expected invalid CVSS error")
	}
}

func TestCalculate_GoldenEscalationAtNinetyFive(t *testing.T) {
	result, err := Calculate(model.ScoreInput{
		At: time.Now(), CVSSKnown: true, CVSS: 8,
		Profile:    model.ServiceProfile{Exposure: model.ExposureInternal, BusinessCriticality: model.RiskHigh, DataClassification: model.RiskConfidential, IntegrityImpact: model.RiskHigh, MaxOutageMinutes: 240, PrivilegeScope: model.PrivilegeProductionWrite},
		Assessment: model.CVEAssessment{Applicability: "affected", Reachability: "reachable", Facts: map[string]string{"required_privilege": "user"}},
		Threat:     model.ThreatSnapshot{KEV: true, KEVKnown: true},
		Technical:  model.TechnicalImpact{Confidentiality: model.Interval{Low: 1, High: 1}, Integrity: model.Interval{Low: 1, High: 1}, Availability: model.Interval{Low: 1, High: 1}, Privilege: model.Interval{Low: 1, High: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Lower != 95 || result.Upper != 95 || result.Priority != "immediate" {
		t.Fatalf("result=%+v", result)
	}
}

func TestCalculate_GoldenPublicUnauthenticatedRCE(t *testing.T) {
	result, err := Calculate(model.ScoreInput{
		At: time.Now(), CVSSKnown: true, CVSS: 9,
		Profile:    model.ServiceProfile{Exposure: model.ExposureInternet, BusinessCriticality: model.RiskCritical, DataClassification: model.RiskRestricted, IntegrityImpact: model.RiskCritical, MaxOutageMinutes: 60, PrivilegeScope: model.PrivilegeSharedControl},
		Assessment: model.CVEAssessment{Applicability: "affected", Reachability: "reachable", Facts: map[string]string{"attack_type": "unauthenticated_rce"}},
		Threat:     model.ThreatSnapshot{KEVKnown: true, KEV: false},
		Technical:  model.TechnicalImpact{Confidentiality: model.Interval{Low: 1, High: 1}, Integrity: model.Interval{Low: 1, High: 1}, Availability: model.Interval{Low: 1, High: 1}, Privilege: model.Interval{Low: 1, High: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Lower != 90 || result.Upper != 100 || result.Priority != "immediate" {
		t.Fatalf("result=%+v", result)
	}
}
