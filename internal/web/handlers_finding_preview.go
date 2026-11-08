package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreviewbridge"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

const findingPreviewAPIVersion = "finding-priority-preview-api-v0.1"
const findingPreviewWarning = "Preview only: supplied claims are not verified; priorities are not operational deadlines. Do not use this output to close findings, accept risk, or suppress notifications. as_of evaluates the current snapshot; it does not reconstruct historical state."

var findingPreviewTime = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$`)

type findingPreviewResponse struct {
	SchemaVersion string                `json:"schema_version"`
	Warning       string                `json:"warning"`
	InputSnapshot json.RawMessage       `json:"input_snapshot"`
	Result        findingpreview.Result `json:"result"`
}

func (s *Server) handleFindingPriorityPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		findingsAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !validFindingAPIID(r.PathValue("id")) {
		findingsAPIError(w, http.StatusNotFound, "not_found")
		return
	}
	values, err := parseFindingsAPIValues(r.URL.RawQuery, "as_of")
	raw := values.Get("as_of")
	if err != nil || !findingPreviewTime.MatchString(raw) {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || at.IsZero() || at.Year() < 1 || at.Year() > 9999 || at.UTC().Year() < 1 || at.UTC().Year() > 9999 {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	// Go accepts out-of-range numeric timezone components; keep wire semantics.
	if raw[len(raw)-1] != 'Z' {
		zone := raw[len(raw)-6:]
		if zone[1:3] > "23" || zone[4:6] > "59" {
			findingsAPIError(w, http.StatusBadRequest, "invalid_query")
			return
		}
	}
	snapshot, err := s.store.GetFindingPreviewSnapshot(r.Context(), r.PathValue("id"), at)
	if errors.Is(err, store.ErrFindingNotFound) {
		findingsAPIError(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		findingsAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	data, result, err := findingpreviewbridge.Build(snapshot.Finding.Finding, snapshot.Asset, snapshot.Finding.Source, snapshot.Finding.SourceFindingID, snapshot.Enrichment, at)
	if err != nil {
		findingsAPIError(w, http.StatusUnprocessableEntity, "invalid_snapshot")
		return
	}
	writeFindingsAPIJSON(w, http.StatusOK, findingPreviewResponse{findingPreviewAPIVersion, findingPreviewWarning, data, result})
}
