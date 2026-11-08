// Package findingpreview provides an in-memory, non-operational view of common
// findings through the existing urgency model. It performs no I/O or persistence.
package findingpreview

import (
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/scoring"
)

const (
	// ContractVersion identifies the internal adapter contract, not a wire API.
	ContractVersion = "v0.1"
	// BasisCommit identifies the reviewed model and common finding schema.
	BasisCommit = "84fee44ff5447bac1f4233da0095e597455ed9b6"
)

var canonicalCVE = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// Binding explicitly attaches optional evidence to one finding and asset.
// ProfileID and Repo must additionally match when a profile is supplied.
type Binding struct{ FindingID, AssetID, CVE, ProfileID, Repo string }

// CVSS contains explicitly supplied, previously validated CVSS evidence.
// This adapter does not implement a CVSS specification validator.
type CVSS struct {
	Binding         Binding
	Known           bool
	Score           float64
	Version, Vector string
}

// Input contains snapshots selected by the caller, never live service handles.
// An assessment requires a bound, resolved profile. An observation is optional
// and provides only source provenance; raw payloads and references are omitted.
type Input struct {
	Finding     model.Finding
	Asset       model.Asset
	Observation *model.Observation
	Enrichment  *model.FindingEnrichment
	Profile     *model.EffectiveProfile
	Assessment  *model.CVEAssessment
	Binding     Binding
	CVSS        *CVSS
	At          time.Time
}

// EvidenceState distinguishes caller-reported freshness from the fixed-clock
// view. HistoricalPositive is not a statement of current compromise.
type EvidenceState struct {
	Source, Version, RunID                   string
	PublishedAt, ObservedAt                  time.Time
	ReportedFresh, Fresh, HistoricalPositive bool
}

// InputOrigin records why a mapped value exists, independently of model confidence.
type InputOrigin struct{ Source, MissingReason string }

// Result separates adapter validity and missing inputs from model conclusions.
// ScoreResult is returned without modification, and is never an actual deadline.
type Result struct {
	ContractVersion, BasisCommit, ModelVersion      string
	PreviewOnly                                     bool
	AsOf                                            time.Time
	FindingID, AssetID, CVE, Source, SourceNativeID string
	Severity                                        model.Severity
	SourceStatus                                    model.SourceStatus
	TriageStatus                                    model.TriageStatus
	AssetEnvironment, AssetCriticality              string
	AdapterState                                    string
	InputSnapshot                                   *model.ScoreInput
	InputOrigins                                    map[string]InputOrigin
	EPSS, KEV                                       *EvidenceState
	MappingWarnings, MissingInputs                  []string
	ScoreResult                                     *model.ScoreResult
}

// Calculate maps one explicit snapshot into the existing pure scoring function.
// Invalid and unsupported inputs have no score. At is mandatory; there is no
// implicit clock, profile resolution, inference from severity, or state update.
func Calculate(in Input) (Result, error) {
	out := Result{ContractVersion: ContractVersion, BasisCommit: BasisCommit, ModelVersion: scoring.ModelVersion(), PreviewOnly: true,
		AsOf: in.At.UTC(), FindingID: in.Finding.ID, AssetID: in.Finding.AssetID,
		CVE: in.Finding.VulnerabilityID, Severity: in.Finding.Severity,
		SourceStatus: in.Finding.SourceStatus, TriageStatus: in.Finding.TriageStatus,
		AssetEnvironment: in.Asset.Environment, AssetCriticality: in.Asset.Criticality,
		AdapterState: "invalid"}
	invalid := func(reason string) (Result, error) { return out, fmt.Errorf("finding preview: %s", reason) }
	if !validTime(in.At) {
		return invalid("explicit valid evaluation time required")
	}
	if in.Finding.ID == "" || in.Asset.ID == "" || in.Finding.AssetID != in.Asset.ID {
		return invalid("finding and asset identities must match")
	}
	if in.Finding.Category != "vulnerability" || !canonicalCVE.MatchString(out.CVE) || len(out.CVE) > 64 {
		out.AdapterState = "unsupported"
		out.MappingWarnings = append(out.MappingWarnings, "canonical vulnerability CVE required; identifiers are not inferred")
		return out, nil
	}
	if in.Observation != nil {
		if in.Observation.FindingID != out.FindingID {
			return invalid("observation binding mismatch")
		}
		out.Source = in.Observation.Source
		out.SourceNativeID = in.Observation.SourceFindingID
	}
	if out.Source == "" {
		out.MissingInputs = append(out.MissingInputs, "source")
	}
	if out.SourceNativeID == "" {
		out.MissingInputs = append(out.MissingInputs, "source_native_id")
	}
	score := model.ScoreInput{At: in.At.UTC(), Profile: unknownProfile(),
		Assessment: model.CVEAssessment{Applicability: "unknown", Reachability: "unknown", Facts: map[string]string{}},
		Threat:     model.ThreatSnapshot{AdvisoryKey: "cve:" + out.CVE}}
	if in.Profile != nil {
		p := *in.Profile
		if !matches(in.Binding, in) || p.ID == "" || p.Repo == "" || in.Binding.ProfileID != p.ID || in.Binding.Repo != p.Repo {
			return invalid("profile binding mismatch")
		}
		if p.Extends != "" {
			return invalid("profile inheritance must already be resolved")
		}
		p.ReviewedAt = copyPtr(p.ReviewedAt)
		p.ReviewDueAt = copyPtr(p.ReviewDueAt)
		score.Profile = p
	} else {
		out.MissingInputs = append(out.MissingInputs, "profile")
	}
	if in.Assessment != nil {
		a := in.Assessment
		if len(a.Facts) > 128 || len(a.Evidence) > 128 || len(a.EvidenceByFact) > 128 {
			return invalid("assessment exceeds input bounds")
		}
		for _, e := range a.EvidenceByFact {
			if len(e) > 128 {
				return invalid("assessment fact evidence exceeds input bounds")
			}
		}
		if in.Profile == nil || !matches(in.Binding, in) || a.ProfileID != score.Profile.ID || a.Repo != score.Profile.Repo || a.AdvisoryKey != score.Threat.AdvisoryKey {
			return invalid("assessment binding mismatch")
		}
		score.Assessment = cloneAssessment(*a)
	} else {
		out.MissingInputs = append(out.MissingInputs, "assessment")
	}
	if in.CVSS != nil {
		c := in.CVSS
		if len(c.Vector) > 2048 || len(c.Version) > 32 {
			return invalid("CVSS evidence exceeds input bounds")
		}
		if !matches(c.Binding, in) {
			return invalid("CVSS binding mismatch")
		}
		if !finiteRange(c.Score, 10) || (!c.Known && (c.Score != 0 || c.Vector != "" || c.Version != "")) {
			return invalid("invalid CVSS known/value combination")
		}
		score.CVSS = c.Score
		score.CVSSKnown = c.Known
		score.Technical = scoring.NormalizeCVSS(c.Score, c.Known, c.Version, c.Vector)
	} else {
		score.Technical = scoring.NormalizeCVSS(0, false, "", "")
	}
	if !score.CVSSKnown {
		out.MissingInputs = append(out.MissingInputs, "cvss")
	}
	if in.Enrichment != nil {
		e := in.Enrichment
		if e.CVEID != out.CVE {
			return invalid("enrichment CVE mismatch")
		}
		if e.EPSS != nil {
			x := e.EPSS
			if !validEvidence(x, "epss", in.At) || x.EPSS == nil || !finiteRange(*x.EPSS, 1) || (x.Percentile != nil && !finiteRange(*x.Percentile, 1)) || x.KEV || x.KEVDateAdded != nil {
				return invalid("invalid EPSS evidence")
			}
			score.Threat.EPSS = copyPtr(x.EPSS)
			score.Threat.EPSSPercentile = copyPtr(x.Percentile)
			score.Threat.EPSSDate = copyPtr(&x.PublishedAt)
			score.Threat.EPSSFetchedAt = copyPtr(&x.ObservedAt)
			out.EPSS = evidenceState(x, in.At)
			if !out.EPSS.Fresh {
				out.MappingWarnings = append(out.MappingWarnings, "stale_epss")
			}
		}
		if e.KEV != nil {
			x := e.KEV
			if !validEvidence(x, "kev", in.At) || !x.KEV || x.EPSS != nil || x.Percentile != nil || x.KEVDateAdded == nil || !validTime(*x.KEVDateAdded) || x.KEVDateAdded.After(x.PublishedAt) {
				return invalid("invalid positive KEV evidence")
			}
			score.Threat.KEV = true
			score.Threat.KEVKnown = true
			score.Threat.KEVDate = copyPtr(x.KEVDateAdded)
			score.Threat.FetchedAt = x.ObservedAt
			out.KEV = evidenceState(x, in.At)
			if !out.KEV.Fresh {
				out.KEV.HistoricalPositive = true
				out.MappingWarnings = append(out.MappingWarnings, "historical_kev_positive: model retains positive KEV without freshness suppression")
			}
		}
	}
	if score.Threat.EPSS == nil {
		out.MissingInputs = append(out.MissingInputs, "epss")
	}
	if score.Threat.EPSSPercentile == nil {
		out.MissingInputs = append(out.MissingInputs, "epss_percentile")
	}
	if !score.Threat.KEVKnown {
		out.MissingInputs = append(out.MissingInputs, "kev")
	}
	collectMissing(&out, score)
	out.InputOrigins = inputOrigins(in, out.MissingInputs)
	result, err := scoring.Calculate(score)
	if err != nil {
		return out, fmt.Errorf("finding preview calculate: %w", err)
	}
	out.AdapterState = "eligible"
	out.InputSnapshot = &score
	out.ScoreResult = &result
	return out, nil
}

func matches(b Binding, in Input) bool {
	return b.FindingID == in.Finding.ID && b.AssetID == in.Asset.ID && b.CVE == in.Finding.VulnerabilityID
}
func finiteRange(n, max float64) bool {
	return !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 && n <= max
}
func copyPtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	x := *p
	return &x
}
func validTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 }
func validEvidence(e *model.SecurityEnrichmentEvidence, source string, at time.Time) bool {
	return e.Source == source && e.Version != "" && e.RunID != "" && validTime(e.PublishedAt) && validTime(e.ObservedAt) &&
		!e.PublishedAt.After(e.ObservedAt) && !e.ObservedAt.After(at)
}
func evidenceState(e *model.SecurityEnrichmentEvidence, at time.Time) *EvidenceState {
	return &EvidenceState{Source: e.Source, Version: e.Version, RunID: e.RunID, PublishedAt: e.PublishedAt, ObservedAt: e.ObservedAt,
		ReportedFresh: e.Fresh, Fresh: at.Sub(e.PublishedAt) <= 72*time.Hour && at.Sub(e.ObservedAt) <= 72*time.Hour}
}
func unknownProfile() model.ServiceProfile {
	return model.ServiceProfile{Environment: model.EnvironmentUnknown, Exposure: model.ExposureUnknown, Authentication: model.AuthUnknown,
		BusinessCriticality: model.RiskUnknown, DataClassification: model.RiskUnknown, IntegrityImpact: model.RiskUnknown, PrivilegeScope: model.PrivilegeUnknown}
}
func cloneAssessment(a model.CVEAssessment) model.CVEAssessment {
	a.Facts = maps.Clone(a.Facts)
	a.Evidence = slices.Clone(a.Evidence)
	a.EvidenceByFact = maps.Clone(a.EvidenceByFact)
	for k, v := range a.EvidenceByFact {
		a.EvidenceByFact[k] = slices.Clone(v)
	}
	return a
}
func collectMissing(out *Result, in model.ScoreInput) {
	fields := []struct{ name, value string }{
		{"profile.environment", string(in.Profile.Environment)}, {"profile.exposure", string(in.Profile.Exposure)},
		{"profile.authentication", string(in.Profile.Authentication)}, {"profile.business_criticality", string(in.Profile.BusinessCriticality)},
		{"profile.data_classification", string(in.Profile.DataClassification)}, {"profile.integrity_impact", string(in.Profile.IntegrityImpact)},
		{"profile.privilege_scope", string(in.Profile.PrivilegeScope)}, {"assessment.applicability", in.Assessment.Applicability},
		{"assessment.reachability", in.Assessment.Reachability}, {"assessment.local_activity", in.Assessment.LocalActivity},
	}
	for _, f := range fields {
		if f.value == "" || f.value == "unknown" {
			out.MissingInputs = append(out.MissingInputs, f.name)
		}
	}
	if in.Profile.MaxOutageMinutes <= 0 {
		out.MissingInputs = append(out.MissingInputs, "profile.max_outage_minutes")
	}
	if len(in.Assessment.Facts) == 0 {
		out.MissingInputs = append(out.MissingInputs, "assessment.facts")
	}
	for _, axis := range []struct {
		name  string
		value model.Interval
	}{
		{"confidentiality", in.Technical.Confidentiality}, {"integrity", in.Technical.Integrity}, {"availability", in.Technical.Availability}, {"privilege", in.Technical.Privilege},
	} {
		if axis.value.Low != axis.value.High {
			out.MissingInputs = append(out.MissingInputs, "technical."+axis.name)
		}
	}
}

func inputOrigins(in Input, missing []string) map[string]InputOrigin {
	out := map[string]InputOrigin{"at": {Source: "explicit_evaluation_time"}, "cvss": {Source: "bound_cvss"}, "cvss_known": {Source: "bound_cvss"}, "threat.advisory_key": {Source: "finding.vulnerability_id"}, "threat.local_activity": {Source: "not_inferred", MissingReason: "adapter does not infer local activity from feeds"}}
	groups := []struct {
		prefix, source string
		fields         []string
	}{
		{"profile.", "bound_resolved_profile", []string{"id", "extends", "owner", "repo", "environment", "exposure", "authentication", "business_criticality", "max_outage_minutes", "data_classification", "integrity_impact", "privilege_scope", "owner_team", "reviewed_by", "reviewed_at", "review_due_at"}},
		{"assessment.", "bound_assessment", []string{"profile_id", "repo", "advisory_key", "applicability", "reachability", "mitigation", "local_activity", "facts", "evidence", "evidence_by_fact", "deployment_revision"}},
		{"technical.", "existing_cvss_normalizer", []string{"confidentiality", "integrity", "availability", "privilege", "cvss_version", "cvss_vector"}},
		{"threat.", "epss_evidence", []string{"epss", "epss_percentile", "epss_date", "epss_fetched_at"}},
		{"threat.", "positive_kev_evidence", []string{"kev", "kev_known", "kev_date", "fetched_at"}},
	}
	for _, g := range groups {
		for _, field := range g.fields {
			origin := InputOrigin{Source: g.source}
			absent := (g.prefix == "profile." && in.Profile == nil) || (g.prefix == "assessment." && in.Assessment == nil) || (g.source == "epss_evidence" && (in.Enrichment == nil || in.Enrichment.EPSS == nil)) || (g.source == "positive_kev_evidence" && (in.Enrichment == nil || in.Enrichment.KEV == nil))
			if absent {
				origin.Source = "missing_input_default"
				origin.MissingReason = "optional input not supplied; unknown or absent representation"
			}
			out[g.prefix+field] = origin
		}
	}
	if in.CVSS == nil {
		out["cvss"] = InputOrigin{Source: "missing_input_default", MissingReason: "CVSS evidence not supplied"}
		out["cvss_known"] = out["cvss"]
	}
	for _, key := range missing {
		if key == "epss" || key == "epss_percentile" || key == "kev" {
			key = "threat." + key
		}
		origin, ok := out[key]
		if !ok {
			continue
		}
		if origin.MissingReason == "" {
			origin.MissingReason = "supplied input is unknown, empty, or unresolved by the existing normalizer"
		}
		out[key] = origin
	}
	return out
}
