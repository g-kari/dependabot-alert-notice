package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestDetailDisplaysSavedRiskHistoryAndDeadline(t *testing.T) {
	srv, s, _ := newTestServer(t)
	t.Cleanup(func() { _ = s.Close() })
	saveAlert(s, 1, "pkg", model.SeverityHigh)
	rec := s.List()[0]
	rec.Alert.CVEID = "CVE-2026-1234"
	s.Save(rec)
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for i, upper := range []int{75, 95} {
		input := model.ScoreInput{At: at.Add(time.Duration(i) * time.Minute), Profile: model.ServiceProfile{ID: "production-api", Environment: model.EnvironmentProduction}}
		result := model.ScoreResult{ModelVersion: "urgency-v1", Status: "provisional", Priority: "immediate", Lower: upper - 10, Upper: upper, MissingFacts: []string{"fixture-evidence"}}
		if _, err := s.SaveRiskEvaluation(context.Background(), "production-api", "testorg/testrepo", "cve:CVE-2026-1234", fmt.Sprint(i), input, result, at.Add(time.Hour), false); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("/alerts/%d", rec.Alert.ID), nil))
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	for _, want := range []string{"評価履歴", "対応期限", "production-api", "2026-10-02 13:00", "fixture-evidence", "85〜95", "65〜75", "urgency-v1"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("saved timeline missing %q", want)
		}
	}
}

func TestScoreAlertChoosesHighestUrgencyAcrossProfiles(t *testing.T) {
	rec := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", CVEID: "CVE-2026-1234", CVSSKnown: true, CVSSScore: 9.8, CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	low := model.ServiceProfile{ID: "staging", Owner: "org", Repo: "api", Exposure: model.ExposureInternal, BusinessCriticality: model.RiskLow, MaxOutageMinutes: 10000, DataClassification: model.RiskPublic, IntegrityImpact: model.RiskLow, PrivilegeScope: model.PrivilegeSandbox}
	high := low
	high.ID = "production"
	high.Exposure = model.ExposureInternet
	high.BusinessCriticality = model.RiskCritical
	high.DataClassification = model.RiskRestricted
	high.IntegrityImpact = model.RiskCritical
	high.PrivilegeScope = model.PrivilegeSharedControl
	high.MaxOutageMinutes = 60
	assessments := []model.CVEAssessment{}
	for _, id := range []string{"staging", "production"} {
		assessments = append(assessments, model.CVEAssessment{ProfileID: id, AdvisoryKey: "cve:CVE-2026-1234", Applicability: "affected", Reachability: "reachable", Facts: map[string]string{"required_privilege": "none"}})
	}
	score := scoreAlertWithThreat([]model.ServiceProfile{low, high}, assessments, map[string]model.ThreatSnapshot{"cve:CVE-2026-1234": {KEV: true}}, rec)
	if score.Upper < 95 {
		t.Fatalf("first profile masked critical production service: %+v", score)
	}
	if score.ProfileID != "production" {
		t.Fatalf("representative profile=%q", score.ProfileID)
	}
}
