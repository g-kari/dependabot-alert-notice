package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

// SecurityEnrichmentImportResult describes an atomic offline enrichment import.
type SecurityEnrichmentImportResult struct {
	Entries int  `json:"entries"`
	Replay  bool `json:"replay"`
}

// ValidateSecurityEnrichmentImport checks all input before opening a database.
func ValidateSecurityEnrichmentImport(run model.IngestRun, feed model.SecurityEnrichmentFeed) error {
	_, _, _, err := normalizeSecurityEnrichmentImport(run, feed)
	return err
}

func normalizeSecurityEnrichmentImport(run model.IngestRun, feed model.SecurityEnrichmentFeed) (model.IngestRun, model.SecurityEnrichmentFeed, string, error) {
	if err := threat.ValidateOfflineFeed(feed); err != nil {
		return run, feed, "", fmt.Errorf("validate enrichment feed: %w", err)
	}
	scope, err := threat.OfflineSelectionScope(feed.SelectedCVEs)
	if err != nil {
		return run, feed, "", fmt.Errorf("validate enrichment selection: %w", err)
	}
	if !securityUUID(run.ID) || run.Connector != feed.Source+"_offline" || run.Scope != scope || !securityTime(run.StartedAt) || run.FinishedAt == nil || !securityTime(*run.FinishedAt) || run.FinishedAt.Before(run.StartedAt) || !run.StartedAt.Equal(feed.ObservedAt) || run.Result != model.IngestResultSuccess || run.Coverage != model.IngestCoveragePartial || run.Error != "" || !strings.HasPrefix(run.Cursor, "sha256:") || !securityDigest(strings.TrimPrefix(run.Cursor, "sha256:")) {
		return run, feed, "", errors.New("invalid enrichment run metadata")
	}
	feed = cloneSecurityEnrichmentFeed(feed)
	run.StartedAt = run.StartedAt.UTC()
	finished := run.FinishedAt.UTC()
	run.FinishedAt = &finished
	if !securityTime(run.StartedAt) || !securityTime(finished) {
		return run, feed, "", errors.New("invalid UTC enrichment run time")
	}
	if err := threat.ValidateOfflineFeed(feed); err != nil {
		return run, feed, "", fmt.Errorf("validate UTC enrichment feed: %w", err)
	}
	body, err := json.Marshal(struct {
		Run  model.IngestRun
		Feed model.SecurityEnrichmentFeed
	}{run, feed})
	if err != nil {
		return run, feed, "", fmt.Errorf("encode enrichment receipt: %w", err)
	}
	digest := sha256.Sum256(body)
	return run, feed, run.Connector + "-v1:" + run.Cursor + ":" + hex.EncodeToString(digest[:]), nil
}

// ImportSecurityEnrichment appends evidence atomically without modifying findings,
// lifecycle state, legacy threat snapshots, scores, approvals or notifications.
func (s *Store) ImportSecurityEnrichment(ctx context.Context, run model.IngestRun, feed model.SecurityEnrichmentFeed) (SecurityEnrichmentImportResult, error) {
	run, feed, receipt, err := normalizeSecurityEnrichmentImport(run, feed)
	if err != nil {
		return SecurityEnrichmentImportResult{}, fmt.Errorf("validate enrichment import: %w", err)
	}
	result := SecurityEnrichmentImportResult{Entries: len(feed.Entries)}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SecurityEnrichmentImportResult{}, fmt.Errorf("begin enrichment import: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var cursor, connector, scope string
	err = tx.QueryRowContext(ctx, `SELECT cursor,connector,scope FROM ingest_runs WHERE id=?`, run.ID).Scan(&cursor, &connector, &scope)
	if err == nil {
		if cursor != receipt || connector != run.Connector || scope != run.Scope {
			return SecurityEnrichmentImportResult{}, ErrIngestConflict
		}
		result.Replay = true
		return result, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return SecurityEnrichmentImportResult{}, fmt.Errorf("read enrichment run: %w", err)
	}
	originalDigest := run.Cursor
	run.Cursor = receipt
	if err := insertIngestRun(ctx, tx, run); err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	if err := appendSecurityEnrichment(ctx, tx, run, feed, originalDigest); err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return SecurityEnrichmentImportResult{}, fmt.Errorf("commit enrichment import: %w", err)
	}
	return result, nil
}

func cloneSecurityEnrichmentFeed(feed model.SecurityEnrichmentFeed) model.SecurityEnrichmentFeed {
	feed.SelectedCVEs = slices.Clone(feed.SelectedCVEs)
	feed.PublishedAt, feed.ObservedAt = feed.PublishedAt.UTC(), feed.ObservedAt.UTC()
	feed.Entries = slices.Clone(feed.Entries)
	if feed.Entries == nil {
		feed.Entries = []model.SecurityEnrichmentEntry{}
	}
	for i := range feed.Entries {
		if feed.Entries[i].KEVDateAdded != nil {
			at := feed.Entries[i].KEVDateAdded.UTC()
			feed.Entries[i].KEVDateAdded = &at
		}
	}
	slices.SortFunc(feed.Entries, func(a, b model.SecurityEnrichmentEntry) int { return strings.Compare(a.CVEID, b.CVEID) })
	return feed
}

func appendSecurityEnrichment(ctx context.Context, tx *sql.Tx, run model.IngestRun, feed model.SecurityEnrichmentFeed, originalDigest string) error {
	selected, err := json.Marshal(feed.SelectedCVEs)
	if err != nil {
		return fmt.Errorf("encode enrichment manifest: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_enrichment_runs(ingest_run_id,source,version,published_at,observed_at,selected_cves_json,entries,original_digest) VALUES(?,?,?,?,?,?,?,?)`, run.ID, feed.Source, feed.Version, feed.PublishedAt.Format(time.RFC3339Nano), feed.ObservedAt.Format(time.RFC3339Nano), string(selected), len(feed.Entries), originalDigest); err != nil {
		return fmt.Errorf("insert enrichment manifest: %w", err)
	}
	for _, entry := range feed.Entries {
		identity, body, id, err := securityEnrichmentEvidenceJSON(run.ID, feed, entry)
		if err != nil {
			return err
		}
		var conflicts int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_enrichment_observations WHERE source=? AND cve_id=? AND published_at=? AND evidence_identity<>?`, feed.Source, entry.CVEID, feed.PublishedAt.Format(time.RFC3339Nano), identity).Scan(&conflicts); err != nil {
			return fmt.Errorf("check enrichment publication: %w", err)
		}
		if conflicts > 0 {
			return fmt.Errorf("conflicting enrichment publication: %w", ErrIngestConflict)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_enrichment_observations(id,ingest_run_id,source,cve_id,published_at,observed_at,evidence_identity,body_json) VALUES(?,?,?,?,?,?,?,?)`, id, run.ID, feed.Source, entry.CVEID, feed.PublishedAt.Format(time.RFC3339Nano), feed.ObservedAt.Format(time.RFC3339Nano), identity, body); err != nil {
			return fmt.Errorf("insert enrichment evidence: %w", err)
		}
	}
	return nil
}

func securityEnrichmentEvidenceJSON(runID string, feed model.SecurityEnrichmentFeed, entry model.SecurityEnrichmentEntry) (string, string, string, error) {
	identity, err := json.Marshal(struct {
		Version string
		Entry   model.SecurityEnrichmentEntry
	}{feed.Version, entry})
	if err != nil {
		return "", "", "", fmt.Errorf("encode enrichment identity: %w", err)
	}
	ref := "https://www.first.org/epss/data"
	if feed.Source == "kev" {
		ref = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
	}
	evidence := model.SecurityEnrichmentEvidence{Source: feed.Source, Version: feed.Version, RunID: runID, RawRef: ref, PublishedAt: feed.PublishedAt, ObservedAt: feed.ObservedAt, EPSS: entry.EPSS, Percentile: entry.Percentile, KEV: entry.KEV, KEVDateAdded: entry.KEVDateAdded}
	body, err := json.Marshal(evidence)
	if err != nil {
		return "", "", "", fmt.Errorf("encode enrichment evidence: %w", err)
	}
	id := sha256.Sum256([]byte(runID + "\x00" + feed.Source + "\x00" + entry.CVEID))
	return string(identity), string(body), hex.EncodeToString(id[:]), nil
}

func readFindingEnrichments(ctx context.Context, tx *sql.Tx, findings []model.Finding, now time.Time) (map[string]model.FindingEnrichment, error) {
	var result map[string]model.FindingEnrichment
	cache := map[string]model.FindingEnrichment{}
	for _, finding := range findings {
		if finding.Category != "vulnerability" {
			continue
		}
		cves, err := threat.NormalizeOfflineCVEs([]string{finding.VulnerabilityID})
		if err != nil || len(cves) != 1 || cves[0] != finding.VulnerabilityID {
			continue
		}
		cve := cves[0]
		enrichment, seen := cache[cve]
		if !seen {
			enrichment.CVEID = cve
			for _, source := range []string{"epss", "kev"} {
				var body string
				err := tx.QueryRowContext(ctx, `SELECT body_json FROM security_enrichment_observations WHERE cve_id=? AND source=? ORDER BY `+securityTimeDescending("published_at")+`,`+securityTimeDescending("observed_at")+`,id DESC LIMIT 1`, cve, source).Scan(&body)
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				if err != nil {
					return nil, fmt.Errorf("read enrichment evidence: %w", err)
				}
				var evidence model.SecurityEnrichmentEvidence
				if err := json.Unmarshal([]byte(body), &evidence); err != nil {
					return nil, fmt.Errorf("decode enrichment evidence: %w", err)
				}
				evidence.Fresh = securityTime(now) && securityTime(evidence.PublishedAt) && securityTime(evidence.ObservedAt) && !evidence.PublishedAt.After(now) && !evidence.ObservedAt.After(now) && now.Sub(evidence.PublishedAt) <= 72*time.Hour && now.Sub(evidence.ObservedAt) <= 72*time.Hour
				if source == "epss" {
					enrichment.EPSS = &evidence
				} else {
					enrichment.KEV = &evidence
				}
			}
			cache[cve] = enrichment
		}
		if enrichment.EPSS != nil || enrichment.KEV != nil {
			if result == nil {
				result = make(map[string]model.FindingEnrichment)
			}
			result[finding.ID] = enrichment
		}
	}
	return result, nil
}
