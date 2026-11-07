package threat

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

const offlineMaxBytes = 32 << 20
const offlineMaxCSVRows = 1000000
const offlineMaxKEVEntries = 20000

var offlineCVEPattern = regexp.MustCompile(`^CVE-([0-9]{4})-[0-9]{4,19}$`)
var offlineNumberPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
var offlineVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// OfflineOptions specifies explicit CVEs and the caller's observation time.
type OfflineOptions struct {
	CVEs       []string
	ObservedAt time.Time
}

func offlineError(reason string) error { return fmt.Errorf("offline threat: %w", errors.New(reason)) }
func offlineCanonicalCVE(v string) bool {
	m := offlineCVEPattern.FindStringSubmatch(v)
	return m != nil && m[1] >= "1999"
}
func offlineValidTime(v time.Time) bool { return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999 }

// NormalizeOfflineCVEs returns a sorted, unique explicit selection, without inference.
func NormalizeOfflineCVEs(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > 200 {
		return nil, offlineError("selection must contain 1 to 200 CVEs")
	}
	seen := make(map[string]bool, len(input))
	out := make([]string, 0, len(input))
	for _, v := range input {
		v = strings.ToUpper(strings.TrimSpace(v))
		if !offlineCanonicalCVE(v) {
			return nil, offlineError("invalid CVE selection")
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, nil
}

// OfflineSelectionScope hashes the canonical JSON selection for receipt isolation.
func OfflineSelectionScope(input []string) (string, error) {
	v, e := NormalizeOfflineCVEs(input)
	if e != nil {
		return "", e
	}
	b, e := json.Marshal(v)
	if e != nil {
		return "", offlineError("cannot encode selection")
	}
	return fmt.Sprintf("cves-sha256:%x", sha256.Sum256(b)), nil
}

// ValidateOfflineFeed independently validates an already projected feed before storage.
func ValidateOfflineFeed(f model.SecurityEnrichmentFeed) error {
	if f.Source != "epss" && f.Source != "kev" {
		return offlineError("unsupported source")
	}
	if !offlineVersionPattern.MatchString(f.Version) {
		return offlineError("invalid source version")
	}
	if !offlineValidTime(f.PublishedAt) || !offlineValidTime(f.ObservedAt) || f.PublishedAt.After(f.ObservedAt) {
		return offlineError("invalid source chronology")
	}
	selected, e := NormalizeOfflineCVEs(f.SelectedCVEs)
	if e != nil {
		return e
	}
	if len(selected) != len(f.SelectedCVEs) {
		return offlineError("selection must be canonical")
	}
	allowed := map[string]bool{}
	for i, v := range selected {
		if v != f.SelectedCVEs[i] {
			return offlineError("selection must be canonical")
		}
		allowed[v] = true
	}
	if len(f.Entries) > 200 {
		return offlineError("too many selected entries")
	}
	seen := map[string]bool{}
	for _, v := range f.Entries {
		if !offlineCanonicalCVE(v.CVEID) || !allowed[v.CVEID] || seen[v.CVEID] {
			return offlineError("invalid selected entry")
		}
		seen[v.CVEID] = true
		if f.Source == "epss" {
			if !offlineProbability(v.EPSS) || !offlineProbability(v.Percentile) || v.KEV || v.KEVDateAdded != nil {
				return offlineError("invalid EPSS evidence")
			}
		} else if !v.KEV || v.KEVDateAdded == nil || !offlineValidTime(*v.KEVDateAdded) || v.KEVDateAdded.After(f.PublishedAt) || v.EPSS != nil || v.Percentile != nil {
			return offlineError("invalid KEV evidence")
		}
	}
	return nil
}
func offlineProbability(v *float64) bool {
	return v != nil && !math.IsNaN(*v) && !math.IsInf(*v, 0) && *v >= 0 && *v <= 1
}
func offlineDate(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700", "2006-01-02", "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if v, e := time.Parse(layout, s); e == nil && offlineValidTime(v) {
			return v.UTC(), nil
		}
	}
	return time.Time{}, offlineError("invalid source date")
}

// ParseOfflineThreat validates the entire bounded local input and retains only selected CVEs.
// Errors never include feed content or underlying reader error text.
func ParseOfflineThreat(r io.Reader, source string, options OfflineOptions) (model.SecurityEnrichmentFeed, error) {
	empty := model.SecurityEnrichmentFeed{}
	selected, e := NormalizeOfflineCVEs(options.CVEs)
	if e != nil {
		return empty, e
	}
	if source != "epss" && source != "kev" {
		return empty, offlineError("unsupported source")
	}
	if !offlineValidTime(options.ObservedAt) {
		return empty, offlineError("invalid observation time")
	}
	if r == nil {
		return empty, offlineError("missing input")
	}
	data, e := io.ReadAll(io.LimitReader(r, offlineMaxBytes+1))
	if e != nil {
		return empty, offlineError("cannot read local input")
	}
	if len(data) > offlineMaxBytes {
		return empty, offlineError("input exceeds size limit")
	}
	if !utf8.Valid(data) {
		return empty, offlineError("input is not UTF-8")
	}
	f := model.SecurityEnrichmentFeed{Source: source, ObservedAt: options.ObservedAt.UTC(), SelectedCVEs: selected, Entries: []model.SecurityEnrichmentEntry{}}
	if source == "epss" {
		e = parseOfflineEPSS(data, &f)
	} else {
		e = parseOfflineKEV(data, &f)
	}
	if e != nil {
		return empty, e
	}
	sort.Slice(f.Entries, func(i, j int) bool { return f.Entries[i].CVEID < f.Entries[j].CVEID })
	if e = ValidateOfflineFeed(f); e != nil {
		return empty, e
	}
	return f, nil
}
func offlineSelected(f *model.SecurityEnrichmentFeed, cve string) bool {
	i := sort.SearchStrings(f.SelectedCVEs, cve)
	return i < len(f.SelectedCVEs) && f.SelectedCVEs[i] == cve
}
func parseOfflineEPSS(data []byte, f *model.SecurityEnrichmentFeed) error {
	// Only a first-line metadata comment is supported; comments elsewhere fail closed.
	newline := bytes.IndexByte(data, '\n')
	if newline < 0 || len(data) == 0 || data[0] != '#' {
		return offlineError("missing EPSS metadata")
	}
	metadata := strings.TrimSuffix(string(data[1:newline]), "\r")
	fields, e := csv.NewReader(strings.NewReader(metadata)).Read()
	if e != nil {
		return offlineError("invalid EPSS metadata")
	}
	meta := map[string]string{}
	for _, field := range fields {
		key, value, ok := strings.Cut(strings.TrimSpace(field), ":")
		if !ok {
			return offlineError("invalid EPSS metadata")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if _, exists := meta[key]; exists {
			return offlineError("duplicate EPSS metadata")
		}
		if key != "model_version" && key != "score_date" {
			return offlineError("unsupported EPSS metadata")
		}
		meta[key] = value
	}
	f.Version = meta["model_version"]
	f.PublishedAt, e = offlineDate(meta["score_date"])
	if e != nil {
		return e
	}
	cr := csv.NewReader(bytes.NewReader(data[newline+1:]))
	header, e := cr.Read()
	if e != nil {
		return offlineError("missing EPSS header")
	}
	if len(header) != 3 && len(header) != 4 {
		return offlineError("unsupported EPSS columns")
	}
	indexes := map[string]int{}
	for i, v := range header {
		if _, exists := indexes[v]; exists {
			return offlineError("duplicate EPSS column")
		}
		indexes[v] = i
	}
	for _, name := range []string{"cve", "epss", "percentile"} {
		if _, ok := indexes[name]; !ok {
			return offlineError("unsupported EPSS columns")
		}
	}
	if len(header) == 4 {
		if _, ok := indexes["date"]; !ok {
			return offlineError("unsupported EPSS columns")
		}
	}
	type scores struct{ epss, percentile float64 }
	seen := map[string]scores{}
	for count := 0; ; count++ {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return offlineError("invalid EPSS row")
		}
		if count >= offlineMaxCSVRows {
			return offlineError("EPSS row limit exceeded")
		}
		cve := row[indexes["cve"]]
		if !offlineCanonicalCVE(cve) {
			return offlineError("invalid EPSS CVE")
		}
		if !offlineNumberPattern.MatchString(row[indexes["epss"]]) || !offlineNumberPattern.MatchString(row[indexes["percentile"]]) {
			return offlineError("invalid EPSS numeric format")
		}
		score, err := strconv.ParseFloat(row[indexes["epss"]], 64)
		if err != nil || !offlineProbability(&score) {
			return offlineError("invalid EPSS probability")
		}
		percentile, err := strconv.ParseFloat(row[indexes["percentile"]], 64)
		if err != nil || !offlineProbability(&percentile) {
			return offlineError("invalid EPSS percentile")
		}
		if len(header) == 4 {
			d, err := offlineDate(row[indexes["date"]])
			if err != nil || d.Format("2006-01-02") != f.PublishedAt.Format("2006-01-02") {
				return offlineError("inconsistent EPSS row date")
			}
		}
		value := scores{score, percentile}
		if old, ok := seen[cve]; ok {
			if old != value {
				return offlineError("conflicting EPSS duplicate")
			}
			continue
		}
		seen[cve] = value
		if offlineSelected(f, cve) {
			f.Entries = append(f.Entries, model.SecurityEnrichmentEntry{CVEID: cve, EPSS: &score, Percentile: &percentile})
		}
	}
	return nil
}
func parseOfflineKEV(data []byte, f *model.SecurityEnrichmentFeed) error {
	var catalog struct {
		Version string          `json:"catalogVersion"`
		Date    string          `json:"dateReleased"`
		Count   *int            `json:"count"`
		Entries json.RawMessage `json:"vulnerabilities"`
	}
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return offlineError("invalid KEV object")
	}
	if e := offlineUniqueJSON(data); e != nil {
		return e
	}
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(data, &fields); e != nil {
		return offlineError("invalid KEV catalog")
	}
	for key, target := range map[string]any{"catalogVersion": &catalog.Version, "dateReleased": &catalog.Date, "count": &catalog.Count, "vulnerabilities": &catalog.Entries} {
		value, ok := fields[key]
		if !ok || json.Unmarshal(value, target) != nil {
			return offlineError("invalid KEV catalog field")
		}
	}
	if catalog.Count == nil || *catalog.Count < 0 || *catalog.Count > offlineMaxKEVEntries {
		return offlineError("invalid KEV count or list")
	}
	f.Version = catalog.Version
	var e error
	f.PublishedAt, e = offlineDate(catalog.Date)
	if e != nil {
		return e
	}
	seen := map[string]time.Time{}
	count, err := offlineKEVArray(catalog.Entries, func(raw json.RawMessage) error {
		var entry struct {
			CVE  string `json:"cveID"`
			Date string `json:"dateAdded"`
		}
		var fields map[string]json.RawMessage
		if e := json.Unmarshal(raw, &fields); e != nil {
			return offlineError("invalid KEV entry")
		}
		for key, target := range map[string]any{"cveID": &entry.CVE, "dateAdded": &entry.Date} {
			value, ok := fields[key]
			if !ok || json.Unmarshal(value, target) != nil {
				return offlineError("invalid KEV entry field")
			}
		}
		if !offlineCanonicalCVE(entry.CVE) {
			return offlineError("invalid KEV CVE")
		}
		date, e := time.Parse("2006-01-02", entry.Date)
		if e != nil || !offlineValidTime(date) || date.After(f.PublishedAt) {
			return offlineError("invalid KEV added date")
		}
		if old, ok := seen[entry.CVE]; ok {
			if !old.Equal(date) {
				return offlineError("conflicting KEV duplicate")
			}
			return nil
		}
		seen[entry.CVE] = date
		if offlineSelected(f, entry.CVE) {
			f.Entries = append(f.Entries, model.SecurityEnrichmentEntry{CVEID: entry.CVE, KEV: true, KEVDateAdded: &date})
		}
		return nil
	})
	if err != nil {
		return err
	}
	if count != *catalog.Count {
		return offlineError("invalid KEV count")
	}
	return nil
}

// offlineUniqueJSON rejects ambiguous duplicate object keys, including metadata.
func offlineUniqueJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var readValue func(int, bool) error
	readValue = func(depth int, boundedArray bool) error {
		if depth > 100 {
			return offlineError("KEV JSON nesting limit exceeded")
		}
		token, err := dec.Token()
		if err != nil {
			return offlineError("invalid KEV JSON")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return offlineError("invalid KEV JSON")
				}
				key, ok := keyToken.(string)
				if !ok || keys[key] {
					return offlineError("duplicate KEV JSON key")
				}
				keys[key] = true
				if err := readValue(depth+1, depth == 0 && key == "vulnerabilities"); err != nil {
					return err
				}
			}
		case '[':
			for count := 0; dec.More(); count++ {
				if boundedArray && count >= offlineMaxKEVEntries {
					return offlineError("KEV entry limit exceeded")
				}
				if err := readValue(depth+1, false); err != nil {
					return err
				}
			}
		default:
			return offlineError("invalid KEV JSON")
		}
		if _, err := dec.Token(); err != nil {
			return offlineError("invalid KEV JSON")
		}
		return nil
	}
	if err := readValue(0, false); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return offlineError("trailing KEV JSON")
	}
	return nil
}

// offlineKEVArray visits one item at a time and never retains the input list.
// The limit is checked before decoding item 20001, even when all items duplicate.
func offlineKEVArray(raw json.RawMessage, visit func(json.RawMessage) error) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('[') {
		return 0, offlineError("invalid KEV list")
	}
	count := 0
	for dec.More() {
		if count >= offlineMaxKEVEntries {
			return count, offlineError("KEV entry limit exceeded")
		}
		var entry json.RawMessage
		if err := dec.Decode(&entry); err != nil {
			return count, offlineError("invalid KEV entry")
		}
		count++
		if err := visit(entry); err != nil {
			return count, err
		}
	}
	if token, err := dec.Token(); err != nil || token != json.Delim(']') {
		return count, offlineError("invalid KEV list")
	}
	if _, err := dec.Token(); err != io.EOF {
		return count, offlineError("trailing KEV list data")
	}
	return count, nil
}
