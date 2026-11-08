package findingpreviewwire

import (
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// AssessmentSchemaVersion identifies the separately opted-in assessment core schema.
const AssessmentSchemaVersion = "finding-preview-assessment-core-v0.1"

// DecodeAssessment validates a bound assessment with one expiring evidence claim.
// It does not verify the claim's truth, source, or authority. Model conclusions
// remain previews, even when supplied not_affected yields verified/planned.
// Decode and DecodeProfile continue to reject this version and assessment fields.
func DecodeAssessment(data []byte) (findingpreview.Result, error) {
	return decode(data, assessmentInput)
}

func assessmentInput(root object) (findingpreview.Input, error) {
	f := fields{m: root}
	m := f.obj("assessment", true)
	if f.err != nil {
		return findingpreview.Input{}, f.err
	}
	in, err := boundProfileInput(root, AssessmentSchemaVersion)
	if err != nil {
		return in, err
	}
	f = fields{m: m}
	a := model.CVEAssessment{
		ProfileID:     f.str("profile_id", true, true, 256),
		Repo:          f.str("repo", true, true, 256),
		AdvisoryKey:   f.str("advisory_key", true, true, 68),
		Applicability: f.str("applicability", true, false, 256),
		Reachability:  f.str("reachability", true, false, 256),
		Facts:         map[string]string{},
	}
	evidence := f.obj("evidence", true)
	if !oneOf(a.Applicability, "", "unknown", "affected", "not_affected") ||
		!oneOf(a.Reachability, "", "unknown", "reachable", "unreachable") {
		f.bad(Error("enum"))
	}
	if err := f.done(); err != nil {
		return in, err
	}
	if a.ProfileID != in.Profile.ID || a.Repo != in.Profile.Repo || a.AdvisoryKey != "cve:"+in.Finding.VulnerabilityID {
		return in, Error("binding")
	}
	f = fields{m: evidence}
	e := model.Evidence{ID: f.str("id", true, true, 256), Source: f.str("source", true, true, 256),
		ObservedAt: f.stamp("observed_at"), ExpiresAt: f.stamp("expires_at")}
	// Already-expired evidence is valid input. Equality with At is expired
	// according to the existing scorer; do not alter or infer that conclusion.
	if e.ObservedAt.After(in.At) || !e.ObservedAt.Before(e.ExpiresAt) {
		f.bad(Error("time"))
	}
	if err := f.done(); err != nil {
		return in, err
	}
	a.Evidence = []model.Evidence{e}
	in.Assessment = &a
	return in, nil
}
