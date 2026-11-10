package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

const refreshMaxTargets = 200
const refreshMaxFindingBytes = 64 << 10

// SecurityEnrichmentRefreshTarget binds an exact canonical CVE to a finding row.
// Revision is an opaque snapshot digest, not permission to mutate the finding.
type SecurityEnrichmentRefreshTarget struct {
	FindingID string
	CVEID     string
	Revision  string
}

// SecurityEnrichmentRefreshTargetPage bounds scanned rows, including ineligible
// rows. After is the last scanned ID, never the last accepted target ID.
type SecurityEnrichmentRefreshTargetPage struct {
	Targets []SecurityEnrichmentRefreshTarget
	After   string
	Scanned int
}

// QuerySecurityEnrichmentRefreshTargets selects at most limit current rows by
// binary ID keyset. It neither normalizes identifiers nor infers CVEs from text.
func (s *Store) QuerySecurityEnrichmentRefreshTargets(ctx context.Context, after string, limit int) (SecurityEnrichmentRefreshTargetPage, error) {
	if limit < 1 || limit > refreshMaxTargets || (after != "" && !validSecurityQueryText(after, 128)) {
		return SecurityEnrichmentRefreshTargetPage{}, fmt.Errorf("invalid refresh target query")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SecurityEnrichmentRefreshTargetPage{}, fmt.Errorf("begin refresh targets: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id,category,asset_id,canonical_key,CASE WHEN length(CAST(body_json AS BLOB))<=65536 THEN body_json ELSE '' END FROM findings WHERE id COLLATE BINARY>? ORDER BY id COLLATE BINARY LIMIT ?`, after, limit)
	if err != nil {
		return SecurityEnrichmentRefreshTargetPage{}, fmt.Errorf("query refresh targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	page := SecurityEnrichmentRefreshTargetPage{Targets: []SecurityEnrichmentRefreshTarget{}}
	for rows.Next() {
		var id, category, asset, key, body string
		if err := rows.Scan(&id, &category, &asset, &key, &body); err != nil {
			return SecurityEnrichmentRefreshTargetPage{}, fmt.Errorf("scan refresh target: %w", err)
		}
		if id == "" || !validSecurityQueryText(id, 128) {
			return SecurityEnrichmentRefreshTargetPage{}, ErrIngestConflict
		}
		page.After, page.Scanned = id, page.Scanned+1
		if target, ok := refreshTarget(id, category, asset, key, body); ok {
			page.Targets = append(page.Targets, target)
		}
	}
	if err := rows.Err(); err != nil {
		return SecurityEnrichmentRefreshTargetPage{}, fmt.Errorf("iterate refresh targets: %w", err)
	}
	if err := rows.Close(); err != nil {
		return SecurityEnrichmentRefreshTargetPage{}, fmt.Errorf("close refresh targets: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return SecurityEnrichmentRefreshTargetPage{}, fmt.Errorf("finish refresh targets: %w", err)
	}
	return page, nil
}

func refreshTarget(id, category, asset, key, body string) (SecurityEnrichmentRefreshTarget, bool) {
	var f model.Finding
	if category != "vulnerability" || len(body) > refreshMaxFindingBytes || decodePreviewStoredJSON(body, &f) != nil || f.ID != id || f.Category != category || f.AssetID != asset || f.CanonicalKey != key {
		return SecurityEnrichmentRefreshTarget{}, false
	}
	cves, err := threat.NormalizeOfflineCVEs([]string{f.VulnerabilityID})
	if err != nil || cves[0] != f.VulnerabilityID {
		return SecurityEnrichmentRefreshTarget{}, false
	}
	identity, err := json.Marshal([]string{id, category, asset, key, body})
	if err != nil {
		return SecurityEnrichmentRefreshTarget{}, false
	}
	digest := sha256.Sum256(identity)
	return SecurityEnrichmentRefreshTarget{id, f.VulnerabilityID, hex.EncodeToString(digest[:])}, true
}

func validateCurrentRefreshTargets(ctx context.Context, tx *sql.Tx, targets []SecurityEnrichmentRefreshTarget) error {
	for _, target := range targets {
		var id, category, asset, key, body string
		if err := tx.QueryRowContext(ctx, `SELECT id,category,asset_id,canonical_key,CASE WHEN length(CAST(body_json AS BLOB))<=65536 THEN body_json ELSE '' END FROM findings WHERE id=?`, target.FindingID).Scan(&id, &category, &asset, &key, &body); err != nil {
			if err == sql.ErrNoRows {
				return ErrIngestConflict
			}
			return fmt.Errorf("read current refresh target: %w", err)
		}
		if current, ok := refreshTarget(id, category, asset, key, body); !ok || current != target {
			return ErrIngestConflict
		}
	}
	return nil
}

// SecurityEnrichmentRefreshAttempt reserves a caller-generated UUID and its
// exact source/scope/target manifest before any future external fetch.
type SecurityEnrichmentRefreshAttempt struct {
	RunID     string
	Connector string
	Scope     string
	StartedAt time.Time
	Targets   []SecurityEnrichmentRefreshTarget
}

// SecurityEnrichmentRefreshCompletion supplies independently recorded source
// publication, observation and completion clocks. No clock is synthesized.
type SecurityEnrichmentRefreshCompletion struct {
	Attempt        SecurityEnrichmentRefreshAttempt
	Feed           model.SecurityEnrichmentFeed
	OriginalDigest string
	FinishedAt     time.Time
}

// SecurityEnrichmentRefreshState reports bounded same-ID readback. Unknown is
// never evidence of success/failure and must not trigger a new-UUID resend.
type SecurityEnrichmentRefreshState struct {
	State   string
	Receipt string
}
