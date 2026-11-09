package web

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type nativeOverviewPage struct {
	Title           string
	Overview        store.SecurityOverview
	Collections     store.ConnectorStatusPage
	CollectionError bool
	CollectionsURL  string
}
type nativeAssetsPage struct {
	Title                string
	Query                store.ConsoleAssetQuery
	Page                 store.ConsoleAssetPage
	PreviousURL, NextURL string
}
type nativeAssetPage struct {
	Title                                      string
	Detail                                     store.ConsoleAssetDetail
	Query                                      store.FindingQuery
	Rows                                       []nativeFindingRow
	PreviousURL, NextURL, FindingsURL, BackURL string
}
type nativeIntegrationsPage struct {
	Title                        string
	Query                        store.ConnectorStatusQuery
	Page                         store.ConnectorStatusPage
	HasEvaluation                bool
	PreviousURL, NextURL, APIURL string
}

func nativeConsolePath(path string) bool {
	for _, root := range []string{"/findings", "/security", "/assets", "/integrations"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func (s *Server) registerSecurityConsole(mux *http.ServeMux) {
	mux.HandleFunc("GET /security", s.handleNativeOverview)
	mux.HandleFunc("GET /assets", s.handleNativeAssets)
	mux.HandleFunc("GET /assets/{id}", s.handleNativeAsset)
	mux.HandleFunc("GET /integrations", s.handleNativeIntegrations)
	for _, path := range []string{"/security/", "/assets/", "/integrations/"} {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			if s.nativeFindingsGET(w, r) {
				s.nativeConsoleError(w, r, http.StatusNotFound)
			}
		})
	}
}

func (s *Server) consoleTime() time.Time {
	if s.consoleNow != nil {
		return s.consoleNow().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) nativeConsoleError(w http.ResponseWriter, r *http.Request, status int) {
	message := "画面を読み込めません。時間をおいて再度お試しください。"
	if status == http.StatusBadRequest {
		message = "検索条件、評価時点またはページ指定が無効です。条件を確認してください。"
	}
	if status == http.StatusNotFound {
		message = "指定された画面または Asset は見つかりません。一覧を確認してください。"
	}
	s.renderNativeFindings(w, r, status, "findings_error.html", struct {
		Title, Message string
		Status         int
	}{"読み取り画面を確認できません", message, status})
}

func (s *Server) handleNativeOverview(w http.ResponseWriter, r *http.Request) {
	if !s.nativeFindingsGET(w, r) {
		return
	}
	if _, err := parseFindingsAPIValues(r.URL.RawQuery); err != nil {
		s.nativeConsoleError(w, r, http.StatusBadRequest)
		return
	}
	at := s.consoleTime()
	overview, err := s.store.QuerySecurityOverview(r.Context(), at)
	if err != nil {
		slog.ErrorContext(r.Context(), "Security overview read failed", "error", err)
		s.nativeConsoleError(w, r, http.StatusInternalServerError)
		return
	}
	data := nativeOverviewPage{Title: "Overview", Overview: overview}
	data.Collections, err = s.store.QueryConnectorStatusPage(r.Context(), store.ConnectorStatusQuery{AsOf: at, Limit: 5})
	data.CollectionError = err != nil
	if err != nil {
		slog.ErrorContext(r.Context(), "Overview collection summary read failed", "error", err)
	}
	data.CollectionsURL = "/integrations?" + url.Values{"as_of": {at.Format(time.RFC3339Nano)}}.Encode()
	s.renderNativeFindings(w, r, http.StatusOK, "security_overview.html", data)
}

func parseConsoleAssetQuery(raw string) (store.ConsoleAssetQuery, error) {
	values, err := parseFindingsAPIValues(raw, "q", "provider", "account", "region", "environment", "criticality", "source", "limit", "offset")
	if err != nil {
		return store.ConsoleAssetQuery{}, err
	}
	limit, offset, err := findingsAPIPagination(values)
	if err != nil {
		return store.ConsoleAssetQuery{}, err
	}
	query := store.ConsoleAssetQuery{Search: values.Get("q"), Provider: values.Get("provider"), Account: values.Get("account"), Region: values.Get("region"), Environment: values.Get("environment"), Criticality: values.Get("criticality"), Source: values.Get("source"), Limit: limit, Offset: offset}
	if err := store.ValidateConsoleAssetQuery(query); err != nil {
		return store.ConsoleAssetQuery{}, err
	}
	if err := validateConsoleAssetReturnBudget(consoleAssetValues(query), findingsAPIMaxRawQuery, findingsAPIMaxLimit, findingsAPIMaxOffset); err != nil {
		return store.ConsoleAssetQuery{}, err
	}
	return query, nil
}
func consoleAssetValues(query store.ConsoleAssetQuery) url.Values {
	values := url.Values{"limit": {strconv.Itoa(query.Limit)}, "offset": {strconv.Itoa(query.Offset)}}
	for key, value := range map[string]string{"q": query.Search, "provider": query.Provider, "account": query.Account, "region": query.Region, "environment": query.Environment, "criticality": query.Criticality, "source": query.Source} {
		if value != "" {
			values.Set(key, value)
		}
	}
	return values
}
func (s *Server) handleNativeAssets(w http.ResponseWriter, r *http.Request) {
	if !s.nativeFindingsGET(w, r) {
		return
	}
	query, err := parseConsoleAssetQuery(r.URL.RawQuery)
	if err != nil {
		s.nativeConsoleError(w, r, http.StatusBadRequest)
		return
	}
	page, err := s.store.QueryConsoleAssetsPage(r.Context(), query)
	if err != nil {
		slog.ErrorContext(r.Context(), "Console assets read failed", "error", err)
		s.nativeConsoleError(w, r, http.StatusInternalServerError)
		return
	}
	data := nativeAssetsPage{Title: "Assets", Query: query, Page: page}
	data.PreviousURL, data.NextURL = nativeFindingPagination("/assets", consoleAssetValues(query), page.Total, page.Limit, page.Offset)
	s.renderNativeFindings(w, r, http.StatusOK, "assets.html", data)
}
func (s *Server) handleNativeAsset(w http.ResponseWriter, r *http.Request) {
	if !s.nativeFindingsGET(w, r) {
		return
	}
	id := r.PathValue("id")
	if !validFindingAPIID(id) {
		s.nativeConsoleError(w, r, http.StatusNotFound)
		return
	}
	// A return URL is limited to this app's validated asset query, never arbitrary URLs.
	values, err := parseConsoleAssetDetailValues(r.URL.RawQuery, findingsAPIMaxRawQuery)
	if err != nil {
		s.nativeConsoleError(w, r, http.StatusBadRequest)
		return
	}
	back := "/assets"
	if raw := values.Get("assets_query"); raw != "" {
		q, err := parseConsoleAssetQuery(raw)
		if err != nil {
			s.nativeConsoleError(w, r, http.StatusBadRequest)
			return
		}
		back += "?" + consoleAssetValues(q).Encode()
	}
	backQuery := values.Get("assets_query")
	values.Del("assets_query")
	query, err := parseNativeFindingsQuery(values.Encode())
	if err != nil {
		s.nativeConsoleError(w, r, http.StatusBadRequest)
		return
	}
	detail, err := s.store.GetConsoleAssetDetail(r.Context(), id, query)
	if errors.Is(err, store.ErrAssetNotFound) {
		s.nativeConsoleError(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "Console asset detail read failed", "error", err)
		s.nativeConsoleError(w, r, http.StatusInternalServerError)
		return
	}
	data := nativeAssetPage{Title: "Asset 詳細", Detail: detail, Query: query, Rows: nativeFindingRows(detail.Findings), BackURL: back}
	query.AssetID = id
	data.FindingsURL = "/findings?" + nativeFindingQueryValues(query).Encode()
	paging := nativeFindingQueryValues(query)
	paging.Del("asset_id")
	if backQuery != "" {
		paging.Set("assets_query", backQuery)
	}
	data.PreviousURL, data.NextURL = nativeFindingPagination("/assets/"+id, paging, detail.Findings.Total, query.Limit, query.Offset)
	s.renderNativeFindings(w, r, http.StatusOK, "asset_detail.html", data)
}

func parseConsoleIntegrationQuery(raw string) (store.ConnectorStatusQuery, bool, error) {
	values, err := parseFindingsAPIValues(raw, "source", "scope", "as_of", "limit", "offset")
	if err != nil {
		return store.ConnectorStatusQuery{}, false, err
	}
	limit, offset, err := findingsAPIPagination(values)
	if err != nil {
		return store.ConnectorStatusQuery{}, false, err
	}
	query := store.ConnectorStatusQuery{Source: values.Get("source"), Scope: values.Get("scope"), Limit: limit, Offset: offset}
	if (query.Source != "" && !store.IsConnectorStatusSource(query.Source)) || (query.Scope != "" && (strings.TrimSpace(query.Scope) != query.Scope || !validFindingsAPIText(query.Scope, 256) || strings.ContainsFunc(query.Scope, func(r rune) bool { return unicode.Is(unicode.Cf, r) }))) {
		return query, false, fmt.Errorf("invalid collection filter")
	}
	rawTime := values.Get("as_of")
	if rawTime == "" {
		if len(values) > 0 {
			return query, false, fmt.Errorf("explicit evaluation time required")
		}
		return query, false, nil
	}
	at, err := time.Parse(time.RFC3339Nano, rawTime)
	if err != nil || !findingPreviewTime.MatchString(rawTime) || at.IsZero() || at.Year() < 1 || at.Year() > 9999 || at.UTC().Year() < 1 || at.UTC().Year() > 9999 {
		return query, false, fmt.Errorf("invalid evaluation time")
	}
	if rawTime[len(rawTime)-1] != 'Z' {
		zone := rawTime[len(rawTime)-6:]
		if zone[1:3] > "23" || zone[4:6] > "59" {
			return query, false, fmt.Errorf("invalid evaluation timezone")
		}
	}
	query.AsOf = at.UTC()
	return query, true, nil
}
func consoleIntegrationValues(query store.ConnectorStatusQuery) url.Values {
	values := url.Values{"as_of": {query.AsOf.Format(time.RFC3339Nano)}, "limit": {strconv.Itoa(query.Limit)}, "offset": {strconv.Itoa(query.Offset)}}
	if query.Source != "" {
		values.Set("source", query.Source)
	}
	if query.Scope != "" {
		values.Set("scope", query.Scope)
	}
	return values
}
func (s *Server) handleNativeIntegrations(w http.ResponseWriter, r *http.Request) {
	if !s.nativeFindingsGET(w, r) {
		return
	}
	query, evaluate, err := parseConsoleIntegrationQuery(r.URL.RawQuery)
	if err != nil {
		s.nativeConsoleError(w, r, http.StatusBadRequest)
		return
	}
	data := nativeIntegrationsPage{Title: "Recorded Integrations", Query: query, HasEvaluation: evaluate}
	if evaluate {
		data.Page, err = s.store.QueryConnectorStatusPage(r.Context(), query)
		if err != nil {
			slog.ErrorContext(r.Context(), "Recorded integrations read failed", "error", err)
			s.nativeConsoleError(w, r, http.StatusInternalServerError)
			return
		}
		data.APIURL = "/api/v1/connectors/status?" + consoleIntegrationValues(query).Encode()
		data.PreviousURL, data.NextURL = nativeFindingPagination("/integrations", consoleIntegrationValues(query), data.Page.Total, query.Limit, query.Offset)
	}
	s.renderNativeFindings(w, r, http.StatusOK, "integrations.html", data)
}

func consoleTemplateFuncs(page string) template.FuncMap {
	funcs := template.FuncMap{}
	for key, value := range templateFuncs {
		funcs[key] = value
	}
	current := map[string]string{"dashboard.html": "/", "detail.html": "/", "logs.html": "/logs", "settings.html": "/settings", "connectivity.html": "/settings", "vulnerability_report.html": "/reports/vulnerabilities", "findings.html": "/findings", "finding_detail.html": "/findings", "security_overview.html": "/security", "assets.html": "/assets", "asset_detail.html": "/assets", "integrations.html": "/integrations"}[page]
	funcs["consoleNavCurrent"] = func(path string) bool { return path == current }
	funcs["consoleAssetURL"] = func(id string, query store.ConsoleAssetQuery) string {
		return consoleAssetDetailURL(id, consoleAssetValues(query), query.Source)
	}
	return funcs
}
