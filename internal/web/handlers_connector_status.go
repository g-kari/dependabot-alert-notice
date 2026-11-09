package web

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func (s *Server) handleConnectorStatusAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		findingsAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	values, err := parseFindingsAPIValues(r.URL.RawQuery, "source", "scope", "as_of", "limit", "offset")
	if err != nil {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	limit, offset, err := findingsAPIPagination(values)
	if err != nil || (values.Has("source") && !store.IsConnectorStatusSource(values.Get("source"))) || (values.Has("scope") && (strings.TrimSpace(values.Get("scope")) == "" || strings.TrimSpace(values.Get("scope")) != values.Get("scope") || !validFindingsAPIText(values.Get("scope"), 256) || strings.ContainsFunc(values.Get("scope"), func(r rune) bool { return unicode.Is(unicode.Cf, r) }))) {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	raw := values.Get("as_of")
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || !findingPreviewTime.MatchString(raw) || at.IsZero() || at.Year() < 1 || at.Year() > 9999 || at.UTC().Year() < 1 || at.UTC().Year() > 9999 {
		findingsAPIError(w, http.StatusBadRequest, "invalid_query")
		return
	}
	if raw[len(raw)-1] != 'Z' {
		zone := raw[len(raw)-6:]
		if zone[1:3] > "23" || zone[4:6] > "59" {
			findingsAPIError(w, http.StatusBadRequest, "invalid_query")
			return
		}
	}
	page, err := s.store.QueryConnectorStatusPage(r.Context(), store.ConnectorStatusQuery{Source: values.Get("source"), Scope: values.Get("scope"), AsOf: at, Limit: limit, Offset: offset})
	if errors.Is(err, store.ErrInvalidConnectorSnapshot) {
		findingsAPIError(w, http.StatusUnprocessableEntity, "invalid_snapshot")
		return
	}
	if err != nil {
		findingsAPIError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeFindingsAPIJSON(w, http.StatusOK, page)
}
