package web

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type nativeFindingSignal struct {
	Name      string
	Value     string
	Freshness string
	Evidence  *model.SecurityEnrichmentEvidence
}

type nativeFindingRow struct {
	store.FindingView
	EPSS nativeFindingSignal
	KEV  nativeFindingSignal
}

type nativeSourceCount struct {
	Name  string
	Count int
}

type nativeFindingsPage struct {
	Title       string
	Query       store.FindingQuery
	Page        store.FindingPage
	Rows        []nativeFindingRow
	Sources     []nativeSourceCount
	Active      int
	Resolved    int
	First       int
	Last        int
	PreviousURL string
	NextURL     string
	APIURL      string
}

type nativeFindingDetailPage struct {
	Title       string
	Detail      store.FindingDetail
	EPSS        nativeFindingSignal
	KEV         nativeFindingSignal
	Related     store.RelatedFindingPage
	Rows        []nativeFindingRow
	PreviousURL string
	NextURL     string
	RelatedURL  string
}

// registerFindingsConsole uses the same listener and access boundary as the
// legacy UI. It exposes no ingestion, triage or approval operation.
func (s *Server) registerFindingsConsole(mux *http.ServeMux) {
	mux.HandleFunc("GET /findings", s.handleNativeFindings)
	mux.HandleFunc("GET /findings/{id}", s.handleNativeFindingDetail)
	mux.HandleFunc("GET /findings/", func(w http.ResponseWriter, r *http.Request) {
		s.nativeFindingsError(w, r, http.StatusNotFound)
	})
}

func nativeFindingsHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func (s *Server) nativeFindingsGET(w http.ResponseWriter, r *http.Request) bool {
	nativeFindingsHeaders(w)
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	s.nativeFindingsError(w, r, http.StatusMethodNotAllowed)
	return false
}

func (s *Server) nativeFindingsError(w http.ResponseWriter, r *http.Request, status int) {
	message := "読み込みに失敗しました。時間をおいて再度お試しください。"
	switch status {
	case http.StatusBadRequest:
		message = "検索条件またはページ指定が無効です。条件をリセットしてやり直してください。"
	case http.StatusNotFound:
		message = "指定された Finding は見つかりません。ID または一覧を確認してください。"
	case http.StatusMethodNotAllowed:
		message = "この画面は読み取り専用です。GET または HEAD でアクセスしてください。"
	}
	s.renderNativeFindings(w, r, status, "findings_error.html", struct {
		Title   string
		Message string
		Status  int
	}{"Findings を確認できません", message, status})
}

// parseNativeFindingsQuery accepts blank optional fields from a standard GET
// form but delegates all actual validation and bounds to the API contract.
func parseNativeFindingsQuery(raw string) (store.FindingQuery, error) {
	values, err := parseFindingsAPIValues(raw, "q", "source", "severity", "source_status", "asset_id", "cve", "limit", "offset")
	if err != nil {
		return store.FindingQuery{}, err
	}
	for _, key := range []string{"q", "source", "severity", "source_status", "asset_id", "cve"} {
		if values.Get(key) == "" {
			values.Del(key)
		}
	}
	return parseFindingsAPIQuery(values.Encode())
}

func nativeFindingQueryValues(query store.FindingQuery) url.Values {
	values := url.Values{"limit": {strconv.Itoa(query.Limit)}, "offset": {strconv.Itoa(query.Offset)}}
	for key, value := range map[string]string{
		"q": query.Search, "source": query.Source, "severity": query.Severity,
		"source_status": query.SourceStatus, "asset_id": query.AssetID, "cve": query.CVEID,
	} {
		if value != "" {
			values.Set(key, value)
		}
	}
	return values
}

func nativeFindingPagination(path string, values url.Values, total, limit, offset int) (string, string) {
	previous, next := "", ""
	if offset > 0 {
		values.Set("offset", strconv.Itoa(max(0, offset-limit)))
		previous = path + "?" + values.Encode()
	}
	if offset+limit < total && offset+limit <= findingsAPIMaxOffset {
		values.Set("offset", strconv.Itoa(offset+limit))
		next = path + "?" + values.Encode()
	}
	return previous, next
}

func (s *Server) handleNativeFindings(w http.ResponseWriter, r *http.Request) {
	if !s.nativeFindingsGET(w, r) {
		return
	}
	query, err := parseNativeFindingsQuery(r.URL.RawQuery)
	if err != nil {
		s.nativeFindingsError(w, r, http.StatusBadRequest)
		return
	}
	page, err := s.store.QueryFindingsPage(r.Context(), query)
	if err != nil {
		slog.ErrorContext(r.Context(), "Native Findings read failed", "operation", "query_findings", "error", err)
		s.nativeFindingsError(w, r, http.StatusInternalServerError)
		return
	}
	data := nativeFindingsPage{Title: "Findings", Query: query, Page: page, Rows: nativeFindingRows(page)}
	data.APIURL = "/api/v1/findings?" + nativeFindingQueryValues(query).Encode()
	data.PreviousURL, data.NextURL = nativeFindingPagination("/findings", nativeFindingQueryValues(query), page.Total, page.Limit, page.Offset)
	if len(page.Items) > 0 {
		data.First, data.Last = page.Offset+1, page.Offset+len(page.Items)
	}
	counts := map[string]int{}
	for _, item := range page.Items {
		source := item.Source
		if source == "" {
			source = "unknown"
		}
		counts[source]++
		if item.SourceStatus == model.SourceStatusActive {
			data.Active++
		}
		if item.SourceStatus == model.SourceStatusResolved {
			data.Resolved++
		}
	}
	for name, count := range counts {
		data.Sources = append(data.Sources, nativeSourceCount{name, count})
	}
	sort.Slice(data.Sources, func(i, j int) bool { return data.Sources[i].Name < data.Sources[j].Name })
	s.renderNativeFindings(w, r, http.StatusOK, "findings.html", data)
}

func (s *Server) handleNativeFindingDetail(w http.ResponseWriter, r *http.Request) {
	if !s.nativeFindingsGET(w, r) {
		return
	}
	id := r.PathValue("id")
	if !validFindingAPIID(id) {
		s.nativeFindingsError(w, r, http.StatusNotFound)
		return
	}
	values, err := parseFindingsAPIValues(r.URL.RawQuery, "limit", "offset")
	if err != nil {
		s.nativeFindingsError(w, r, http.StatusBadRequest)
		return
	}
	if !values.Has("limit") {
		values.Set("limit", "20")
	}
	limit, offset, err := findingsAPIPagination(values)
	if err != nil {
		s.nativeFindingsError(w, r, http.StatusBadRequest)
		return
	}
	detail, err := s.store.GetFindingDetail(r.Context(), id)
	if err != nil {
		s.nativeFindingReadError(w, r, "get_finding", err)
		return
	}
	related, err := s.store.QueryRelatedFindings(r.Context(), id, store.FindingQuery{Limit: limit, Offset: offset})
	if err != nil {
		s.nativeFindingReadError(w, r, "query_related", err)
		return
	}
	epss, kev := nativeFindingSignals(detail.Enrichment)
	data := nativeFindingDetailPage{Title: "Finding 詳細", Detail: detail, EPSS: epss, KEV: kev, Related: related, Rows: nativeFindingRows(related.FindingPage)}
	data.RelatedURL = "/api/v1/findings/" + id + "/related?" + values.Encode()
	data.PreviousURL, data.NextURL = nativeFindingPagination("/findings/"+id, values, related.Total, limit, offset)
	if data.PreviousURL != "" {
		data.PreviousURL += "#related"
	}
	if data.NextURL != "" {
		data.NextURL += "#related"
	}
	s.renderNativeFindings(w, r, http.StatusOK, "finding_detail.html", data)
}

func (s *Server) nativeFindingReadError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	if errors.Is(err, store.ErrFindingNotFound) {
		s.nativeFindingsError(w, r, http.StatusNotFound)
		return
	}
	slog.ErrorContext(r.Context(), "Native Finding read failed", "operation", operation, "error", err)
	s.nativeFindingsError(w, r, http.StatusInternalServerError)
}

func nativeFindingRows(page store.FindingPage) []nativeFindingRow {
	rows := make([]nativeFindingRow, 0, len(page.Items))
	for _, item := range page.Items {
		enrichment := page.Enrichments[item.ID]
		epss, kev := nativeFindingSignals(&enrichment)
		rows = append(rows, nativeFindingRow{item, epss, kev})
	}
	return rows
}

func nativeFindingSignals(enrichment *model.FindingEnrichment) (nativeFindingSignal, nativeFindingSignal) {
	epss := nativeFindingSignal{Name: "EPSS", Value: "不明", Freshness: "証拠なし"}
	kev := nativeFindingSignal{Name: "KEV", Value: "不明", Freshness: "証拠なし"}
	if enrichment == nil {
		return epss, kev
	}
	if evidence := enrichment.EPSS; evidence != nil {
		epss.Evidence, epss.Freshness = evidence, nativeFindingFreshness(evidence)
		if evidence.EPSS != nil {
			epss.Value = fmt.Sprintf("%.6g%%", *evidence.EPSS*100)
		}
	}
	if evidence := enrichment.KEV; evidence != nil {
		kev.Evidence, kev.Freshness = evidence, nativeFindingFreshness(evidence)
		if evidence.KEV {
			kev.Value = "掲載あり"
		}
	}
	return epss, kev
}

func nativeFindingFreshness(evidence *model.SecurityEnrichmentEvidence) string {
	if evidence.Fresh {
		return "Fresh"
	}
	return "Stale / 時点外"
}

func nativeFindingTime(at time.Time) string {
	if at.IsZero() {
		return "不明"
	}
	return at.UTC().Format(time.RFC3339Nano)
}

func nativeFindingSeverityClass(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "badge-critical"
	case model.SeverityHigh:
		return "badge-high"
	case model.SeverityMedium:
		return "badge-medium"
	case model.SeverityLow:
		return "badge-low"
	default:
		return "badge-pending"
	}
}

// Buffer before writing headers so a template failure never returns partial HTML
// with a successful status. All evidence remains html/template-escaped text.
func (s *Server) renderNativeFindings(w http.ResponseWriter, r *http.Request, status int, page string, data any) {
	nativeFindingsHeaders(w)
	funcs := consoleTemplateFuncs(page)
	nativeFuncs := map[string]any{
		"findingTime": nativeFindingTime, "findingSeverityClass": nativeFindingSeverityClass,
		"findingOrUnknown": func(value string) string {
			if value == "" {
				return "不明"
			}
			return value
		},
	}
	for key, value := range nativeFuncs {
		funcs[key] = value
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/findings_shell.html", "templates/"+page)
	var body bytes.Buffer
	if err == nil {
		err = tmpl.ExecuteTemplate(&body, "layout", data)
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "Native Findings render failed", "page", page, "error", err)
		http.Error(w, "Findings page unavailable", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		if _, err := w.Write(body.Bytes()); err != nil {
			slog.ErrorContext(r.Context(), "Native Findings response failed", "page", page, "error", err)
		}
	}
}
