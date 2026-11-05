// Package scoring はサービス属性と脆弱性情報から対応緊急度を計算する。
package scoring

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

const modelVersion = "urgency-v1"

// Calculate は外部通信を行わず、入力スナップショットから緊急度を計算する。
func Calculate(in model.ScoreInput) (model.ScoreResult, error) {
	result := model.ScoreResult{ModelVersion: modelVersion, ProfileID: in.Profile.ID, Status: "confirmed", Confidence: "verified"}
	if in.At.IsZero() {
		return result, fmt.Errorf("評価時刻が未設定です")
	}
	if in.CVSSKnown && (in.CVSS < 0 || in.CVSS > 10 || math.IsNaN(in.CVSS) || math.IsInf(in.CVSS, 0)) {
		return result, fmt.Errorf("CVSSスコアが不正です: %v", in.CVSS)
	}

	result.Impact = impactInterval(in.Profile, in.Technical)
	result.Likelihood = likelihoodInterval(in.Profile, in.Assessment, in.Threat, in.At)
	if in.Assessment.Applicability == "not_affected" {
		result.Status = "not_affected"
		result.Confidence = "verified"
	}
	if in.Assessment.Mitigation == "fully_mitigated" {
		result.Status = "mitigated"
		result.Confidence = "verified"
	}
	if in.Assessment.LocalActivity == "confirmed_compromise" && in.Assessment.Applicability == "not_affected" {
		result.Status = "conflict"
		result.Confidence = "insufficient"
	}
	if evidenceExpired(in.Assessment, in.At) && in.Assessment.LocalActivity != "confirmed_compromise" {
		result.Status = "provisional"
		result.Confidence = "insufficient"
	}
	if result.Status == "confirmed" && (hasUnknown(in.Profile, in.Assessment, in.Technical, in.Threat, in.At) || evidenceExpired(in.Assessment, in.At)) {
		result.Status = "provisional"
		result.Confidence = "insufficient"
	}
	if result.Status == "provisional" {
		result.MissingFacts = missingFacts(in)
	}

	low := int(math.Round(0.55*result.Impact.Low + 0.45*result.Likelihood.Low))
	high := int(math.Round(0.55*result.Impact.High + 0.45*result.Likelihood.High))
	if low < 0 {
		low = 0
	}
	if low > 100 {
		low = 100
	}
	if high < 0 {
		high = 0
	}
	if high > 100 {
		high = 100
	}
	if high < low {
		high = low
	}
	result.Lower, result.Upper = low, high
	result.Reasons = append(result.Reasons,
		model.Reason{RuleID: "impact-max-axis", Text: fmt.Sprintf("影響区間 %.0f〜%.0f", result.Impact.Low, result.Impact.High)},
		model.Reason{RuleID: "likelihood-weighted", Text: fmt.Sprintf("切迫性区間 %.0f〜%.0f", result.Likelihood.Low, result.Likelihood.High)},
	)

	applyEscalations(&result, in)
	if result.Status == "not_affected" || result.Status == "mitigated" {
		result.Priority = "planned"
	} else if result.Priority == "incident" {
		// confirmed compromise is an incident regardless of numeric thresholds.
	} else {
		result.Priority = priority(result.Upper)
	}
	if result.Lower == result.Upper && result.Status == "confirmed" {
		result.Confidence = "verified"
	}
	return result, nil
}

func interval(v float64, known bool) model.Interval {
	if known {
		return model.Interval{Low: clamp(v), High: clamp(v)}
	}
	return model.Interval{Low: 0.5, High: 1}
}

func levelValue(level model.RiskLevel) float64 {
	switch level {
	case model.RiskLow:
		return .25
	case model.RiskStandard:
		return .5
	case model.RiskHigh:
		return .75
	case model.RiskCritical, model.RiskRestricted:
		return 1
	case model.RiskConfidential:
		return .75
	case model.RiskInternal:
		return .5
	case model.RiskPublic:
		return .25
	}
	return .5
}

func pathValue(path model.ExposurePath) float64 {
	switch path {
	case model.ExposureInternet:
		return 1
	case model.ExposurePartner:
		return .75
	case model.ExposureInternal:
		return .5
	case model.ExposureIsolated:
		return .25
	}
	return .5
}

func privilegeValue(scope model.PrivilegeScope) float64 {
	switch scope {
	case model.PrivilegeSharedControl:
		return 1
	case model.PrivilegeProductionWrite:
		return .75
	case model.PrivilegeServiceOnly:
		return .5
	case model.PrivilegeSandbox:
		return .25
	}
	return .5
}

func impactInterval(p model.ServiceProfile, t model.TechnicalImpact) model.Interval {
	c, i, a, x := t.Confidentiality, t.Integrity, t.Availability, t.Privilege
	if t.C != (model.Interval{}) {
		c = t.C
	}
	if t.I != (model.Interval{}) {
		i = t.I
	}
	if t.A != (model.Interval{}) {
		a = t.A
	}
	if t.X != (model.Interval{}) {
		x = t.X
	}
	bc := interval(levelValue(p.DataClassification), p.DataClassification != model.RiskUnknown && p.DataClassification != "")
	bd := interval(levelValue(p.IntegrityImpact), p.IntegrityImpact != model.RiskUnknown && p.IntegrityImpact != "")
	baValue := math.Max(levelValue(p.BusinessCriticality), outageValue(p.MaxOutageMinutes))
	ba := interval(baValue, p.BusinessCriticality != model.RiskUnknown && p.BusinessCriticality != "" && p.MaxOutageMinutes > 0)
	bx := interval(privilegeValue(p.PrivilegeScope), p.PrivilegeScope != model.PrivilegeUnknown && p.PrivilegeScope != "")
	return model.Interval{Low: 100 * max4(c.Low*bc.Low, i.Low*bd.Low, a.Low*ba.Low, x.Low*bx.Low), High: 100 * max4(c.High*bc.High, i.High*bd.High, a.High*ba.High, x.High*bx.High)}
}

func outageValue(minutes int) float64 {
	if minutes <= 60 {
		return 1
	}
	if minutes <= 240 {
		return .75
	}
	if minutes <= 1440 {
		return .5
	}
	return .25
}

func likelihoodInterval(p model.ServiceProfile, a model.CVEAssessment, t model.ThreatSnapshot, at time.Time) model.Interval {
	threatLow, threatHigh := .3, 1.0
	if a.LocalActivity == "confirmed_compromise" {
		threatLow = 1
		threatHigh = 1
	} else if t.KEV || a.LocalActivity == "external_exploitation" {
		threatLow = .95
		threatHigh = 1
	} else if t.EPSS != nil && epssFresh(t, at) {
		threatLow = epssValue(*t.EPSS)
		threatHigh = threatLow
	}
	rLow, rHigh := pathValue(p.Exposure), pathValue(p.Exposure)
	if p.Exposure == model.ExposureUnknown || p.Exposure == "" {
		rLow, rHigh = .5, 1
	}
	fLow, fHigh := .2, 1.0
	fKnown := false
	if len(a.Facts) > 0 {
		fKnown = true
		fLow = 1
		if a.Facts["special_condition"] == "true" {
			fLow -= .2
		}
		if a.Facts["user_interaction"] == "required" {
			fLow, fHigh = .2, .2
		}
	}
	if len(a.Facts) > 0 && a.Facts["required_privilege"] == "user" {
		fLow, fHigh = math.Min(fLow, .7), math.Min(fHigh, .7)
	} else if len(a.Facts) > 0 && a.Facts["required_privilege"] == "admin" {
		fLow, fHigh = math.Min(fLow, .4), math.Min(fHigh, .4)
	}
	if !fKnown {
		fLow, fHigh = .2, 1
	}
	return model.Interval{Low: 100 * (.6*threatLow + .25*rLow + .15*fLow), High: 100 * (.6*threatHigh + .25*rHigh + .15*fHigh)}
}

func epssValue(v float64) float64 {
	switch {
	case v >= .5:
		return .85
	case v >= .1:
		return .7
	case v >= .01:
		return .5
	default:
		return .3
	}
}
func hasUnknown(p model.ServiceProfile, a model.CVEAssessment, t model.TechnicalImpact, threat model.ThreatSnapshot, at time.Time) bool {
	return p.Exposure == model.ExposureUnknown || p.Exposure == "" || p.BusinessCriticality == model.RiskUnknown || p.BusinessCriticality == "" || p.DataClassification == model.RiskUnknown || p.DataClassification == "" || p.IntegrityImpact == model.RiskUnknown || p.IntegrityImpact == "" || p.PrivilegeScope == model.PrivilegeUnknown || p.PrivilegeScope == "" || p.MaxOutageMinutes <= 0 || len(a.Facts) == 0 || a.Applicability == "unknown" || a.Applicability == "" || a.Reachability == "unknown" || a.Reachability == "" || t.Confidentiality.Low != t.Confidentiality.High || t.Integrity.Low != t.Integrity.High || t.Availability.Low != t.Availability.High || (!threat.KEVKnown && !threat.KEV && threat.EPSS == nil) || (threat.EPSS != nil && !threat.KEV && !epssFresh(threat, at))
}

func inFreshness(fetched, at time.Time) bool {
	return !fetched.IsZero() && !fetched.After(at) && at.Sub(fetched) <= 72*time.Hour
}

func epssFresh(threat model.ThreatSnapshot, at time.Time) bool {
	fetched := threat.FetchedAt
	if threat.EPSSFetchedAt != nil {
		fetched = *threat.EPSSFetchedAt
	}
	if !inFreshness(fetched, at) {
		return false
	}
	return threat.EPSSDate == nil || inFreshness(*threat.EPSSDate, at)
}
func missingFacts(in model.ScoreInput) []string {
	var out []string
	if in.Profile.Exposure == model.ExposureUnknown {
		out = append(out, "公開経路")
	}
	if in.Profile.BusinessCriticality == model.RiskUnknown {
		out = append(out, "業務重要度")
	}
	if in.Profile.PrivilegeScope == model.PrivilegeUnknown {
		out = append(out, "権限・波及範囲")
	}
	if !in.Threat.KEVKnown && !in.Threat.KEV && in.Threat.EPSS == nil {
		out = append(out, "脅威情報")
	}
	if in.Threat.EPSS != nil && !in.Threat.KEV && !epssFresh(in.Threat, in.At) {
		out = append(out, "EPSSの鮮度")
	}
	if in.Assessment.Reachability == "unknown" || in.Assessment.Reachability == "" {
		out = append(out, "到達性")
	}
	if in.Assessment.Applicability == "unknown" || in.Assessment.Applicability == "" {
		out = append(out, "適用性")
	}
	if evidenceExpired(in.Assessment, in.At) {
		out = append(out, "根拠の有効期限")
	}
	return out
}

func evidenceExpired(a model.CVEAssessment, at time.Time) bool {
	for _, evidence := range a.Evidence {
		if !evidence.ExpiresAt.IsZero() && !at.Before(evidence.ExpiresAt) {
			return true
		}
	}
	for _, evidenceList := range a.EvidenceByFact {
		for _, evidence := range evidenceList {
			if !evidence.ExpiresAt.IsZero() && !at.Before(evidence.ExpiresAt) {
				return true
			}
		}
	}
	return false
}
func applyEscalations(r *model.ScoreResult, in model.ScoreInput) {
	impactKnown := r.Impact.Low >= 75
	impactPossible := r.Impact.High >= 75
	reachable := in.Assessment.Reachability == "reachable"
	reachPossible := reachable || in.Assessment.Reachability == "unknown" || in.Assessment.Reachability == ""
	affected := in.Assessment.Applicability == "affected"
	affectPossible := affected || in.Assessment.Applicability == "unknown" || in.Assessment.Applicability == ""
	exploited := in.Threat.KEV || in.Assessment.LocalActivity == "external_exploitation" || in.Assessment.LocalActivity == "confirmed_compromise"
	if in.Assessment.LocalActivity == "confirmed_compromise" {
		r.Lower, r.Upper = 100, 100
		r.Priority = "incident"
		r.ConfirmedRules = append(r.ConfirmedRules, "confirmed-compromise")
		r.Reasons = append(r.Reasons, model.Reason{RuleID: "confirmed-compromise", Text: "侵害確認済み"})
		return
	}
	if exploited && affected && reachable && impactKnown {
		r.Lower = maxInt(r.Lower, 95)
		r.Upper = maxInt(r.Upper, 95)
		r.ConfirmedRules = append(r.ConfirmedRules, "exploited-affected-reachable-high-impact")
		r.Reasons = append(r.Reasons, model.Reason{RuleID: "exploited-affected-reachable-high-impact", Text: "KEVまたは悪用確認かつ到達可能・重大影響"})
	} else if exploited && affectPossible && reachPossible && impactPossible {
		r.Upper = maxInt(r.Upper, 95)
		r.PossibleRules = append(r.PossibleRules, "exploited-affected-reachable-high-impact")
	}
	if in.Profile.Exposure == model.ExposureInternet && affected && reachable && in.Assessment.Facts["attack_type"] == "unauthenticated_rce" && impactKnown {
		r.Lower = maxInt(r.Lower, 90)
		r.Upper = maxInt(r.Upper, 90)
		r.ConfirmedRules = append(r.ConfirmedRules, "public-unauthenticated-rce")
		r.Reasons = append(r.Reasons, model.Reason{RuleID: "public-unauthenticated-rce", Text: "インターネット公開の未認証RCE"})
	} else if (in.Profile.Exposure == model.ExposureInternet || in.Profile.Exposure == model.ExposureUnknown || in.Profile.Exposure == "") && affectPossible && reachPossible && in.Assessment.Facts["attack_type"] == "unauthenticated_rce" && impactPossible {
		r.Upper = maxInt(r.Upper, 90)
		r.PossibleRules = append(r.PossibleRules, "public-unauthenticated-rce")
	}
	if exploited && affected && reachable && !impactKnown {
		r.Lower = maxInt(r.Lower, 80)
		r.Upper = maxInt(r.Upper, 80)
		r.ConfirmedRules = append(r.ConfirmedRules, "exploited-affected-reachable")
	}
}
func priority(score int) string {
	switch {
	case score >= 90:
		return "immediate"
	case score >= 75:
		return "today"
	case score >= 50:
		return "next_business_day"
	default:
		return "planned"
	}
}
func max4(a, b, c, d float64) float64 { return math.Max(math.Max(a, b), math.Max(c, d)) }
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func clamp(v float64) float64 { return math.Max(0, math.Min(1, v)) }

// ModelVersion は現在の計算モデルの識別子を返す。
func ModelVersion() string { return modelVersion }

// ExplainScore は画面表示用の短い根拠を生成する。
func ExplainScore(r model.ScoreResult) string { return strings.Join(r.MissingFacts, ", ") }
