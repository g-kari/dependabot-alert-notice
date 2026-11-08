package findingpreviewwire

import (
	"encoding/json"
	"strconv"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ProfileSchemaVersion identifies the separately opted-in bound profile schema.
const ProfileSchemaVersion = "finding-preview-profile-v0.1"

// DecodeProfile validates a fully explicit, caller-resolved profile and binding.
// It never selects or resolves a profile, authenticates its claims, or adds an
// assessment or CVSS. Decode continues to reject this version and these fields.
func DecodeProfile(data []byte) (findingpreview.Result, error) {
	return decode(data, profileInput)
}

func profileInput(root object) (findingpreview.Input, error) {
	return boundProfileInput(root, ProfileSchemaVersion)
}

func boundProfileInput(root object, version string) (findingpreview.Input, error) {
	f := fields{m: root}
	profile := f.obj("profile", true)
	binding := f.obj("binding", true)
	if f.err != nil {
		return findingpreview.Input{}, f.err
	}
	in, err := baseInput(root, version)
	if err != nil {
		return in, err
	}
	p, err := resolvedProfile(profile)
	if err != nil {
		return in, err
	}
	f = fields{m: binding}
	b := findingpreview.Binding{FindingID: f.str("finding_id", true, true, 256), AssetID: f.str("asset_id", true, true, 256), CVE: f.str("cve", true, false, 64), ProfileID: f.str("profile_id", true, true, 256), Repo: f.str("repo", true, true, 256)}
	if err := f.done(); err != nil {
		return in, err
	}
	if b.FindingID != in.Finding.ID || b.AssetID != in.Asset.ID || b.CVE != in.Finding.VulnerabilityID || b.ProfileID != p.ID || b.Repo != p.Repo {
		return in, Error("binding")
	}
	in.Profile = &p
	in.Binding = b
	return in, nil
}

func resolvedProfile(m object) (model.EffectiveProfile, error) {
	f := fields{m: m}
	p := model.EffectiveProfile{
		ID: f.str("id", true, true, 256), Repo: f.str("repo", true, true, 256),
		Environment:         model.ServiceEnvironment(f.str("environment", true, false, 256)),
		Exposure:            model.ExposurePath(f.str("exposure", true, false, 256)),
		Authentication:      model.AuthenticationBoundary(f.str("authentication", true, false, 256)),
		BusinessCriticality: model.RiskLevel(f.str("business_criticality", true, false, 256)),
		MaxOutageMinutes:    f.outageMinutes(),
		DataClassification:  model.RiskLevel(f.str("data_classification", true, false, 256)),
		IntegrityImpact:     model.RiskLevel(f.str("integrity_impact", true, false, 256)),
		PrivilegeScope:      model.PrivilegeScope(f.str("privilege_scope", true, false, 256)),
	}
	// Match model/config vocabulary, including the shared broad RiskLevel set.
	// Empty and unknown are explicit values, not a request to infer asset context.
	if !oneOf(string(p.Environment), "", "production", "staging", "development", "ci", "unknown") ||
		!oneOf(string(p.Exposure), "", "internet", "partner", "internal", "isolated", "unknown") ||
		!oneOf(string(p.Authentication), "", "none", "customer", "employee", "privileged", "unknown") ||
		!oneOf(string(p.PrivilegeScope), "", "shared_control", "production_write", "service_only", "sandbox", "unknown") {
		f.bad(Error("enum"))
	}
	for _, v := range []model.RiskLevel{p.BusinessCriticality, p.DataClassification, p.IntegrityImpact} {
		if !oneOf(string(v), "", "unknown", "low", "standard", "high", "critical", "restricted", "confidential", "internal", "public") {
			f.bad(Error("enum"))
		}
	}
	if err := f.done(); err != nil {
		return model.EffectiveProfile{}, err
	}
	return p, nil
}

func (f *fields) outageMinutes() int {
	v := f.take("max_outage_minutes", true)
	if v == nil {
		return 0
	}
	n, ok := v.(json.Number)
	if !ok {
		f.bad(Error("type"))
		return 0
	}
	// A canonical unsigned decimal integer only, bounded for 32-bit int parity.
	// Reject -0, fractions, exponents and alternate encodings rather than coerce.
	s := string(n)
	value, err := strconv.ParseUint(s, 10, 31)
	if err != nil || strconv.FormatUint(value, 10) != s {
		f.bad(Error("number"))
		return 0
	}
	return int(value)
}
