// Package findingpreviewbridge projects selected stored evidence into the closed
// base wire contract. It performs no I/O and never invents missing evidence.
package findingpreviewbridge

import (
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreviewwire"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ErrSnapshot is deliberately independent of input values and internal errors.
var ErrSnapshot = errors.New("finding preview: invalid_snapshot")

// Build validates a minimal projection and returns the exact replayable base
// snapshot and its full result. Returned bytes are owned by the caller.
func Build(f model.Finding, a model.Asset, source, nativeID string, e *model.FindingEnrichment, at time.Time) (json.RawMessage, findingpreview.Result, error) {
	fail := func() (json.RawMessage, findingpreview.Result, error) {
		return nil, findingpreview.Result{}, ErrSnapshot
	}
	// encoding/json replaces malformed UTF-8. Reject it before marshaling rather
	// than silently repairing stored identities. Bounds also limit allocation.
	valid := func(values ...string) bool {
		for _, v := range values {
			if !utf8.ValidString(v) || len(v) > 256 {
				return false
			}
		}
		return true
	}
	if !valid(f.ID, f.AssetID, f.Category, f.VulnerabilityID, string(f.Severity), string(f.SourceStatus), string(f.TriageStatus), a.ID, a.Environment, a.Criticality, source, nativeID) {
		return fail()
	}
	snapshot := map[string]any{
		"schema_version": findingpreviewwire.SchemaVersion, "as_of": at,
		"finding": map[string]any{"id": f.ID, "asset_id": f.AssetID, "category": f.Category, "vulnerability_id": f.VulnerabilityID, "severity": f.Severity, "source_status": f.SourceStatus, "triage_status": f.TriageStatus},
		"asset":   map[string]any{"id": a.ID, "environment": a.Environment, "criticality": a.Criticality},
	}
	if source != "" || nativeID != "" {
		snapshot["provenance"] = map[string]any{"finding_id": f.ID, "source": source, "source_native_id": nativeID}
	}
	if e != nil {
		if !valid(e.CVEID) {
			return fail()
		}
		enrichment := map[string]any{"cve_id": e.CVEID}
		for _, item := range []struct {
			name     string
			evidence *model.SecurityEnrichmentEvidence
		}{{"epss", e.EPSS}, {"kev", e.KEV}} {
			x := item.evidence
			if x == nil {
				continue
			}
			if x.Source != item.name || !valid(x.Version, x.RunID) {
				return fail()
			}
			evidence := map[string]any{"version": x.Version, "run_id": x.RunID, "published_at": x.PublishedAt, "observed_at": x.ObservedAt, "reported_fresh": x.Fresh}
			if item.name == "epss" {
				if x.EPSS == nil || x.KEV || x.KEVDateAdded != nil {
					return fail()
				}
				evidence["probability"] = *x.EPSS
				if x.Percentile != nil {
					evidence["percentile"] = *x.Percentile
				}
			} else {
				if !x.KEV || x.EPSS != nil || x.Percentile != nil || x.KEVDateAdded == nil {
					return fail()
				}
				evidence["positive"] = x.KEV
				evidence["date_added"] = *x.KEVDateAdded
			}
			enrichment[item.name] = evidence
		}
		snapshot["enrichment"] = enrichment
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return fail()
	}
	result, err := findingpreviewwire.Decode(data)
	if err != nil {
		return fail()
	}
	return data, result, nil
}
