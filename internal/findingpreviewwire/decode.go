// Package findingpreviewwire validates one bounded in-memory JSON snapshot.
// It has no transport, persistence, notifications, or implicit clock.
package findingpreviewwire

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// SchemaVersion is independent of the internal preview adapter version.
const SchemaVersion = "finding-preview-base-v0.1"

// MaxBytes is the inclusive limit on the complete JSON document, including whitespace.
const MaxBytes = 64 * 1024

// MaxDepth counts nested JSON containers, with the root at depth one.
const MaxDepth = 8

// Error is a fixed diagnostic code. It never contains input or decoder errors.
type Error string

func (e Error) Error() string { return "finding preview input: " + string(e) }

// Decode validates all supplied fields before calling the pure adapter once.
// Errors return a zero Result, never a partially populated input projection.
// Valid unsupported findings retain the adapter's unsupported result, without a score.
func Decode(data []byte) (findingpreview.Result, error) {
	fail := func(e error) (findingpreview.Result, error) { return findingpreview.Result{}, e }
	if len(data) > MaxBytes {
		return fail(Error("size"))
	}
	if !utf8.Valid(data) || !validEscapes(data) {
		return fail(Error("encoding"))
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	v, err := readValue(d, 0)
	if err != nil {
		return fail(err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fail(Error("syntax"))
	}
	root, ok := v.(object)
	if !ok {
		return fail(Error("type"))
	}
	in, err := input(root)
	if err != nil {
		return fail(err)
	}
	out, err := findingpreview.Calculate(in)
	if err != nil {
		return fail(Error("adapter"))
	}
	return out, nil
}

type object map[string]any

// readValue checks container depth before recursing and duplicate decoded keys
// before inserting. No raw JSON is unmarshaled into a model struct.
func readValue(d *json.Decoder, depth int) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, Error("syntax")
	}
	if t == nil {
		return nil, Error("null")
	}
	delim, container := t.(json.Delim)
	if !container {
		return t, nil
	}
	if depth >= MaxDepth {
		return nil, Error("depth")
	}
	if delim != '{' {
		return nil, Error("type")
	}
	m := object{}
	for d.More() {
		k, err := d.Token()
		if err != nil {
			return nil, Error("syntax")
		}
		key, ok := k.(string)
		if !ok {
			return nil, Error("syntax")
		}
		if _, exists := m[key]; exists {
			return nil, Error("duplicate")
		}
		value, err := readValue(d, depth+1)
		if err != nil {
			return nil, err
		}
		m[key] = value
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return nil, Error("syntax")
	}
	return m, nil
}

// validEscapes prevents encoding/json's replacement of lone UTF-16 surrogates.
// Syntax itself is still checked by the JSON decoder.
func validEscapes(b []byte) bool {
	quoted := false
	for i := 0; i < len(b); i++ {
		if b[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		n, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

type fields struct {
	m   object
	err error
}

func (f *fields) take(k string, required bool) any {
	v, ok := f.m[k]
	delete(f.m, k)
	if !ok && required && f.err == nil {
		f.err = Error("required")
	}
	return v
}
func (f *fields) bad(code Error) {
	if f.err == nil {
		f.err = code
	}
}
func (f *fields) str(k string, required, nonempty bool, max int) string {
	v := f.take(k, required)
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		f.bad(Error("type"))
		return ""
	}
	if len(s) > max || (nonempty && strings.TrimSpace(s) == "") {
		f.bad(Error("string"))
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			f.bad(Error("string"))
		}
	}
	return s
}
func (f *fields) obj(k string, required bool) object {
	v := f.take(k, required)
	if v == nil {
		return nil
	}
	m, ok := v.(object)
	if !ok {
		f.bad(Error("type"))
	}
	return m
}
func (f *fields) boolean(k string, required bool) bool {
	v := f.take(k, required)
	if v == nil {
		return false
	}
	b, ok := v.(bool)
	if !ok {
		f.bad(Error("type"))
	}
	return b
}
func (f *fields) stamp(k string) time.Time {
	s := f.str(k, true, true, 256)
	// Go's parser otherwise accepts a one-digit hour, comma fraction, and
	// out-of-range zone offsets. Require the RFC3339 lexical form as well.
	valid := len(s) >= 20 && s[4] == '-' && s[7] == '-' && s[10] == 'T' && s[13] == ':' && s[16] == ':'
	if valid {
		for _, i := range []int{0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18} {
			if s[i] < '0' || s[i] > '9' {
				valid = false
			}
		}
		rest := s[19:]
		if strings.HasPrefix(rest, ".") {
			rest = rest[1:]
			n := 0
			for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
				n++
			}
			if n < 1 || n > 9 {
				valid = false
			}
			rest = rest[n:]
		}
		if rest != "Z" {
			if len(rest) != 6 || (rest[0] != '+' && rest[0] != '-') || rest[3] != ':' {
				valid = false
			} else {
				h, e1 := strconv.Atoi(rest[1:3])
				m, e2 := strconv.Atoi(rest[4:6])
				if e1 != nil || e2 != nil || h > 23 || m > 59 || h < 0 || m < 0 {
					valid = false
				}
				for _, i := range []int{1, 2, 4, 5} {
					if rest[i] < '0' || rest[i] > '9' {
						valid = false
					}
				}
			}
		}
	}
	t, err := time.ParseInLocation(time.RFC3339Nano, s, time.UTC)
	if !valid || err != nil || t.IsZero() || t.Year() < 1 || t.Year() > 9999 || t.UTC().Year() < 1 || t.UTC().Year() > 9999 {
		f.bad(Error("time"))
	}
	return t
}
func (f *fields) probability(k string, required bool) *float64 {
	v := f.take(k, required)
	if v == nil {
		return nil
	}
	n, ok := v.(json.Number)
	if !ok {
		f.bad(Error("type"))
		return nil
	}
	x, err := n.Float64()
	if err != nil || !unitDecimal(string(n)) || x < 0 || x > 1 {
		f.bad(Error("number"))
		return nil
	}
	// Do not silently turn a positive, unrepresentably small input into zero.
	if x == 0 && strings.ContainsAny(strings.Split(strings.ToLower(string(n)), "e")[0], "123456789") {
		f.bad(Error("number"))
		return nil
	}
	return &x
}

// unitDecimal compares the decimal value exactly against [0,1], including a
// value just above one which would round to one in binary floating point.
// Exponents saturate relative to document length, so no giant integer is built.
func unitDecimal(s string) bool {
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	parts := strings.Split(strings.ToLower(s), "e")
	mant := parts[0]
	exp := 0
	if len(parts) == 2 {
		es := parts[1]
		neg := strings.HasPrefix(es, "-")
		es = strings.TrimLeft(es, "+-")
		for _, c := range es {
			if exp <= MaxBytes {
				exp = exp*10 + int(c-'0')
			}
		}
		if neg {
			exp = -exp
		}
	}
	point := strings.IndexByte(mant, '.')
	if point < 0 {
		point = len(mant)
	}
	digits := strings.ReplaceAll(mant, ".", "")
	leading := len(digits) - len(strings.TrimLeft(digits, "0"))
	digits = digits[leading:]
	if digits == "" {
		return true
	}
	if negative {
		return false
	}
	magnitude := point - leading + exp
	if magnitude < 1 {
		return true
	}
	if magnitude > 1 {
		return false
	}
	return digits[0] == '1' && strings.Trim(digits[1:], "0") == ""
}
func (f *fields) done() error {
	if f.err != nil {
		return f.err
	}
	if len(f.m) > 0 {
		return Error("field")
	}
	return nil
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}

func input(root object) (findingpreview.Input, error) {
	var in findingpreview.Input
	f := fields{m: root}
	version := f.str("schema_version", true, true, 256)
	if version != SchemaVersion {
		f.bad(Error("version"))
	}
	in.At = f.stamp("as_of")
	finding := f.obj("finding", true)
	asset := f.obj("asset", true)
	provenance := f.obj("provenance", false)
	enrichment := f.obj("enrichment", false)
	if err := f.done(); err != nil {
		return in, err
	}
	f = fields{m: finding}
	in.Finding = model.Finding{ID: f.str("id", true, true, 256), AssetID: f.str("asset_id", true, true, 256), Category: f.str("category", true, true, 256), VulnerabilityID: f.str("vulnerability_id", true, false, 64), Severity: model.Severity(f.str("severity", false, false, 256)), SourceStatus: model.SourceStatus(f.str("source_status", false, false, 256)), TriageStatus: model.TriageStatus(f.str("triage_status", false, false, 256))}
	if !oneOf(string(in.Finding.Severity), "", "critical", "high", "medium", "low") || !oneOf(string(in.Finding.SourceStatus), "", "active", "resolved", "suppressed", "unknown") || !oneOf(string(in.Finding.TriageStatus), "", "new", "triaged", "in_progress", "risk_accepted", "closed") {
		f.bad(Error("enum"))
	}
	if err := f.done(); err != nil {
		return in, err
	}
	f = fields{m: asset}
	in.Asset = model.Asset{ID: f.str("id", true, true, 256), Environment: f.str("environment", false, false, 64), Criticality: f.str("criticality", false, false, 64)}
	if err := f.done(); err != nil {
		return in, err
	}
	if in.Finding.AssetID != in.Asset.ID {
		return in, Error("binding")
	}
	if provenance != nil {
		f = fields{m: provenance}
		in.Observation = &model.Observation{FindingID: f.str("finding_id", true, true, 256), Source: f.str("source", true, true, 256), SourceFindingID: f.str("source_native_id", true, true, 256)}
		if err := f.done(); err != nil {
			return in, err
		}
		if in.Observation.FindingID != in.Finding.ID {
			return in, Error("binding")
		}
	}
	if enrichment != nil {
		f = fields{m: enrichment}
		e := &model.FindingEnrichment{CVEID: f.str("cve_id", true, true, 64)}
		epss := f.obj("epss", false)
		kev := f.obj("kev", false)
		if err := f.done(); err != nil {
			return in, err
		}
		if e.CVEID != in.Finding.VulnerabilityID {
			return in, Error("binding")
		}
		var err error
		if epss != nil {
			e.EPSS, err = evidence(epss, "epss", in.At)
			if err != nil {
				return in, err
			}
		}
		if kev != nil {
			e.KEV, err = evidence(kev, "kev", in.At)
			if err != nil {
				return in, err
			}
		}
		in.Enrichment = e
	}
	return in, nil
}
func evidence(m object, source string, at time.Time) (*model.SecurityEnrichmentEvidence, error) {
	f := fields{m: m}
	e := &model.SecurityEnrichmentEvidence{Source: source, Version: f.str("version", true, true, 256), RunID: f.str("run_id", true, true, 256), PublishedAt: f.stamp("published_at"), ObservedAt: f.stamp("observed_at"), Fresh: f.boolean("reported_fresh", false)}
	if source == "epss" {
		e.EPSS = f.probability("probability", true)
		e.Percentile = f.probability("percentile", false)
	} else {
		e.KEV = f.boolean("positive", true)
		date := f.stamp("date_added")
		e.KEVDateAdded = &date
		if !e.KEV {
			f.bad(Error("positive"))
		}
		if date.After(e.PublishedAt) {
			f.bad(Error("time"))
		}
	}
	if e.PublishedAt.After(e.ObservedAt) || e.ObservedAt.After(at) {
		f.bad(Error("time"))
	}
	if err := f.done(); err != nil {
		return nil, err
	}
	return e, nil
}
