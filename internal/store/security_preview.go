package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

// FindingPreviewSnapshot contains only the stored context needed for base preview.
// It does not load histories, raw source references, profiles or assessments.
type FindingPreviewSnapshot struct {
	Finding    FindingView
	Asset      model.Asset
	Enrichment *model.FindingEnrichment
}

// GetFindingPreviewSnapshot reads current evidence in one transaction. at is an
// explicit evaluation clock, not a request to reconstruct historical DB state.
// This method never opens a database or starts a migration or application worker.
func (s *Store) GetFindingPreviewSnapshot(ctx context.Context, id string, at time.Time) (FindingPreviewSnapshot, error) {
	if id == "" || !validSecurityQueryText(id, 128) {
		return FindingPreviewSnapshot{}, fmt.Errorf("get finding preview: %w", ErrFindingNotFound)
	}
	if !securityTime(at) {
		return FindingPreviewSnapshot{}, fmt.Errorf("get finding preview: invalid time")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return FindingPreviewSnapshot{}, fmt.Errorf("begin finding preview: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var findingBody, assetBody, assetID string
	err = tx.QueryRowContext(ctx, `SELECT f.body_json,a.body_json,a.id FROM findings AS f JOIN assets AS a ON a.id=f.asset_id WHERE f.id=?`, id).Scan(&findingBody, &assetBody, &assetID)
	if errors.Is(err, sql.ErrNoRows) {
		return FindingPreviewSnapshot{}, fmt.Errorf("get finding preview: %w", ErrFindingNotFound)
	}
	if err != nil {
		return FindingPreviewSnapshot{}, fmt.Errorf("read finding preview: %w", err)
	}
	var out FindingPreviewSnapshot
	var f model.Finding
	if err = decodePreviewStoredJSON(findingBody, &f); err != nil {
		return FindingPreviewSnapshot{}, fmt.Errorf("decode preview finding: %w", err)
	}
	if err = decodePreviewStoredJSON(assetBody, &out.Asset); err != nil {
		return FindingPreviewSnapshot{}, fmt.Errorf("decode preview asset: %w", err)
	}
	if f.ID != id || f.AssetID != assetID || out.Asset.ID != assetID {
		return FindingPreviewSnapshot{}, fmt.Errorf("read finding preview: inconsistent binding")
	}
	out.Finding, err = projectFinding(ctx, tx, f, "")
	if err != nil {
		return FindingPreviewSnapshot{}, fmt.Errorf("read preview provenance: %w", err)
	}
	out.Enrichment, err = readPreviewEnrichment(ctx, tx, f, at)
	if err != nil {
		return FindingPreviewSnapshot{}, fmt.Errorf("read preview enrichment: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return FindingPreviewSnapshot{}, fmt.Errorf("finish finding preview: %w", err)
	}
	return out, nil
}

// Use the same latest-evidence order as the existing API, but reject invalid
// stored encoding before decoding. Existing API semantics remain untouched.
func readPreviewEnrichment(ctx context.Context, tx *sql.Tx, f model.Finding, at time.Time) (*model.FindingEnrichment, error) {
	if f.Category != "vulnerability" {
		return nil, nil
	}
	cves, err := threat.NormalizeOfflineCVEs([]string{f.VulnerabilityID})
	if err != nil || len(cves) != 1 || cves[0] != f.VulnerabilityID {
		return nil, nil
	}
	out := &model.FindingEnrichment{CVEID: f.VulnerabilityID}
	for _, source := range []string{"epss", "kev"} {
		var body, runID, storedSource, published, observed string
		err := tx.QueryRowContext(ctx, `SELECT body_json,ingest_run_id,source,published_at,observed_at FROM security_enrichment_observations WHERE cve_id=? AND source=? ORDER BY `+securityTimeDescending("published_at")+`,`+securityTimeDescending("observed_at")+`,id DESC LIMIT 1`, f.VulnerabilityID, source).Scan(&body, &runID, &storedSource, &published, &observed)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read preview evidence: %w", err)
		}
		var x model.SecurityEnrichmentEvidence
		if err := decodePreviewStoredJSON(body, &x); err != nil {
			return nil, fmt.Errorf("decode preview evidence: %w", err)
		}
		pub, pubErr := time.Parse(time.RFC3339Nano, published)
		obs, obsErr := time.Parse(time.RFC3339Nano, observed)
		if pubErr != nil || obsErr != nil || storedSource != source || x.Source != source || x.RunID != runID || !pub.Equal(x.PublishedAt) || !obs.Equal(x.ObservedAt) {
			return nil, fmt.Errorf("preview evidence binding mismatch")
		}
		x.Fresh = securityTime(at) && securityTime(x.PublishedAt) && securityTime(x.ObservedAt) && !x.PublishedAt.After(at) && !x.ObservedAt.After(at) && at.Sub(x.PublishedAt) <= 72*time.Hour && at.Sub(x.ObservedAt) <= 72*time.Hour
		if source == "epss" {
			out.EPSS = &x
		} else {
			out.KEV = &x
		}
	}
	if out.EPSS == nil && out.KEV == nil {
		return nil, nil
	}
	return out, nil
}

func decodePreviewStoredJSON(body string, out any) error {
	if !utf8.ValidString(body) || !validPreviewStoredEscapes([]byte(body)) {
		return fmt.Errorf("invalid stored encoding")
	}
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	if err := checkPreviewStoredValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("invalid stored JSON")
	}
	if err := json.Unmarshal([]byte(body), out); err != nil {
		return fmt.Errorf("decode stored snapshot: %w", err)
	}
	return nil
}

// validPreviewStoredEscapes rejects JSON surrogate replacement before unmarshal.
func validPreviewStoredEscapes(b []byte) bool {
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

// Stored models may contain arrays and unrelated fields, but duplicate keys
// (including case aliases accepted by encoding/json) must not choose evidence
// or identities through last-key-wins decoding.
func checkPreviewStoredValue(d *json.Decoder, depth int) error {
	if depth > 128 {
		return fmt.Errorf("stored JSON depth exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return fmt.Errorf("invalid stored JSON")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return fmt.Errorf("invalid stored JSON")
			}
			name, ok := key.(string)
			if !ok || keys[previewFoldKey(name)] {
				return fmt.Errorf("duplicate stored JSON key")
			}
			keys[previewFoldKey(name)] = true
			if err := checkPreviewStoredValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkPreviewStoredValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid stored JSON")
	}
	end, err := d.Token()
	if err != nil || (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) {
		return fmt.Errorf("invalid stored JSON")
	}
	return nil
}

// Match encoding/json's Unicode SimpleFold field-name equivalence, including
// long s and Kelvin sign, without quadratic pairwise comparisons of object keys.
func previewFoldKey(s string) string {
	return strings.Map(func(r rune) rune {
		start := r
		for next := unicode.SimpleFold(r); next != start; next = unicode.SimpleFold(next) {
			if next < r {
				r = next
			}
		}
		return r
	}, s)
}
