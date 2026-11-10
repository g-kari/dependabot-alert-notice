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

func normalizeRefreshAttempt(a SecurityEnrichmentRefreshAttempt) (SecurityEnrichmentRefreshAttempt, model.IngestRun, []string, error) {
	if !securityUUID(a.RunID) || (a.Connector != "epss_feed" && a.Connector != "kev_feed") || !securityTime(a.StartedAt) || !securityTime(a.StartedAt.UTC()) || len(a.Targets) < 1 || len(a.Targets) > refreshMaxTargets {
		return a, model.IngestRun{}, nil, fmt.Errorf("invalid refresh attempt")
	}
	a.StartedAt = a.StartedAt.UTC()
	a.Targets = slices.Clone(a.Targets)
	slices.SortFunc(a.Targets, func(x, y SecurityEnrichmentRefreshTarget) int { return strings.Compare(x.FindingID, y.FindingID) })
	var cves []string
	for i, t := range a.Targets {
		cv, err := threat.NormalizeOfflineCVEs([]string{t.CVEID})
		if t.FindingID == "" || !validSecurityQueryText(t.FindingID, 128) || !securityDigest(t.Revision) || err != nil || cv[0] != t.CVEID || (i > 0 && a.Targets[i-1].FindingID == t.FindingID) {
			return a, model.IngestRun{}, nil, fmt.Errorf("invalid refresh target manifest")
		}
		cves = append(cves, t.CVEID)
	}
	slices.Sort(cves)
	cves = slices.Compact(cves)
	scope, err := threat.OfflineSelectionScope(cves)
	if err != nil || scope != a.Scope {
		return a, model.IngestRun{}, nil, fmt.Errorf("invalid refresh scope")
	}
	data, err := json.Marshal(a)
	if err != nil {
		return a, model.IngestRun{}, nil, fmt.Errorf("encode refresh attempt: %w", err)
	}
	digest := sha256.Sum256(data)
	run := model.IngestRun{ID: a.RunID, Connector: a.Connector, Scope: a.Scope, StartedAt: a.StartedAt, Result: model.IngestResultRunning, Coverage: model.IngestCoverageUnknown, Cursor: "refresh-attempt-v1:sha256:" + hex.EncodeToString(digest[:])}
	return a, run, cves, nil
}

func normalizeRefreshCompletion(c SecurityEnrichmentRefreshCompletion) (SecurityEnrichmentRefreshCompletion, model.IngestRun, model.IngestRun, error) {
	a, running, cves, err := normalizeRefreshAttempt(c.Attempt)
	if err != nil {
		return c, model.IngestRun{}, model.IngestRun{}, err
	}
	if err := threat.ValidateOfflineFeed(c.Feed); err != nil {
		return c, running, model.IngestRun{}, fmt.Errorf("validate refresh feed: %w", err)
	}
	if a.Connector != c.Feed.Source+"_feed" || !slices.Equal(cves, c.Feed.SelectedCVEs) || !strings.HasPrefix(c.OriginalDigest, "sha256:") || !securityDigest(strings.TrimPrefix(c.OriginalDigest, "sha256:")) || !securityTime(c.FinishedAt) || !securityTime(c.FinishedAt.UTC()) || c.Feed.ObservedAt.Before(a.StartedAt) || c.FinishedAt.Before(c.Feed.ObservedAt) {
		return c, running, model.IngestRun{}, fmt.Errorf("invalid refresh completion")
	}
	c.Attempt = a
	c.Feed = cloneSecurityEnrichmentFeed(c.Feed)
	c.FinishedAt = c.FinishedAt.UTC()
	if err := threat.ValidateOfflineFeed(c.Feed); err != nil {
		return c, running, model.IngestRun{}, fmt.Errorf("validate UTC refresh feed: %w", err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		return c, running, model.IngestRun{}, fmt.Errorf("encode refresh receipt: %w", err)
	}
	digest := sha256.Sum256(data)
	success := running
	success.Result = model.IngestResultSuccess
	success.Coverage = model.IngestCoveragePartial
	success.FinishedAt = &c.FinishedAt
	success.Cursor = "refresh-success-v1:sha256:" + hex.EncodeToString(digest[:])
	return c, running, success, nil
}

// BeginSecurityEnrichmentRefresh reserves the caller's UUID and target manifest.
// Repeating the identical running attempt is read-only. This does not fetch data.
func (s *Store) BeginSecurityEnrichmentRefresh(ctx context.Context, attempt SecurityEnrichmentRefreshAttempt) (bool, error) {
	a, run, _, err := normalizeRefreshAttempt(attempt)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin refresh attempt: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	replay, err := beginSecurityEnrichmentRefreshTx(ctx, tx, a, run)
	if err != nil {
		return false, err
	}
	if replay {
		return true, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit refresh attempt: %w", err)
	}
	return false, nil
}

// CompleteSecurityEnrichmentRefresh validates the current targets and commits
// provenance, positive observations and the same UUID's success in one transaction.
// A commit error is uncertain: reconcile this same completion before any retry.
func (s *Store) CompleteSecurityEnrichmentRefresh(ctx context.Context, completion SecurityEnrichmentRefreshCompletion) (SecurityEnrichmentImportResult, error) {
	c, running, success, err := normalizeRefreshCompletion(completion)
	if err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SecurityEnrichmentImportResult{}, fmt.Errorf("begin refresh completion: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := completeSecurityEnrichmentRefreshTx(ctx, tx, c, running, success)
	if err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	if result.Replay {
		return result, nil
	}
	if err := tx.Commit(); err != nil {
		return SecurityEnrichmentImportResult{}, fmt.Errorf("commit refresh completion: %w", err)
	}
	return result, nil
}

func refreshFailureCode(code string) bool {
	switch code {
	case "fetch_failed", "parse_failed", "invalid_metadata", "target_changed", "store_failed", "canceled":
		return true
	}
	return false
}

// FailSecurityEnrichmentRefresh records only a closed machine code, preserves
// last-good evidence and never downgrades a completed success. No feed is fetched.
func (s *Store) FailSecurityEnrichmentRefresh(ctx context.Context, attempt SecurityEnrichmentRefreshAttempt, code string, finishedAt time.Time) (bool, error) {
	_, running, _, err := normalizeRefreshAttempt(attempt)
	if err != nil {
		return false, err
	}
	if !refreshFailureCode(code) || !securityTime(finishedAt) || !securityTime(finishedAt.UTC()) || finishedAt.Before(running.StartedAt) {
		return false, fmt.Errorf("invalid refresh failure")
	}
	finish := finishedAt.UTC()
	failed := running
	failed.FinishedAt = &finish
	failed.Result = model.IngestResultFailed
	failed.Error = code
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin refresh failure: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	replay, err := failSecurityEnrichmentRefreshTx(ctx, tx, running, failed)
	if err != nil {
		return false, err
	}
	if replay {
		return true, nil
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit refresh failure: %w", err)
	}
	return false, nil
}

// ReconcileSecurityEnrichmentRefresh reads only this UUID and at most 201
// observation identities, then checks at most 200 exact observations. Errors
// return unknown, never guessed success/failure; callers must retain this UUID.
func (s *Store) ReconcileSecurityEnrichmentRefresh(ctx context.Context, completion SecurityEnrichmentRefreshCompletion) (SecurityEnrichmentRefreshState, error) {
	unknown := SecurityEnrichmentRefreshState{State: "unknown"}
	c, running, success, err := normalizeRefreshCompletion(completion)
	if err != nil {
		return unknown, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return unknown, fmt.Errorf("begin refresh reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stored, exists, err := readRefreshRun(ctx, tx, running.ID)
	if err != nil {
		return unknown, err
	}
	state := SecurityEnrichmentRefreshState{State: "missing"}
	if exists {
		switch {
		case stored.Result == model.IngestResultSuccess:
			if err := checkRefreshSuccess(ctx, tx, stored, success, c); err != nil {
				return unknown, err
			}
			state = SecurityEnrichmentRefreshState{State: "success", Receipt: success.Cursor}
		case equalRefreshRun(stored, running):
			if err := checkRefreshNoEvidence(ctx, tx, running.ID); err != nil {
				return unknown, err
			}
			state.State = "running"
		case stored.Result == model.IngestResultFailed && stored.FinishedAt != nil && !stored.FinishedAt.Before(running.StartedAt) && refreshFailureCode(stored.Error):
			expected := running
			expected.Result = model.IngestResultFailed
			expected.FinishedAt = stored.FinishedAt
			expected.Error = stored.Error
			if !equalRefreshRun(stored, expected) {
				return unknown, ErrIngestConflict
			}
			if err := checkRefreshNoEvidence(ctx, tx, running.ID); err != nil {
				return unknown, err
			}
			state.State = "failed"
		default:
			return unknown, ErrIngestConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return unknown, fmt.Errorf("finish refresh reconciliation: %w", err)
	}
	return state, nil
}

func beginSecurityEnrichmentRefreshTx(ctx context.Context, tx *sql.Tx, a SecurityEnrichmentRefreshAttempt, run model.IngestRun) (bool, error) {
	stored, exists, err := readRefreshRun(ctx, tx, run.ID)
	if err != nil {
		return false, err
	}
	if exists {
		if !equalRefreshRun(stored, run) {
			return false, ErrIngestConflict
		}
		if err := checkRefreshNoEvidence(ctx, tx, run.ID); err != nil {
			return false, err
		}
		return true, nil
	}
	if err := validateCurrentRefreshTargets(ctx, tx, a.Targets); err != nil {
		return false, err
	}
	if err := insertIngestRun(ctx, tx, run); err != nil {
		return false, err
	}
	return false, nil
}

func completeSecurityEnrichmentRefreshTx(ctx context.Context, tx *sql.Tx, c SecurityEnrichmentRefreshCompletion, running, success model.IngestRun) (SecurityEnrichmentImportResult, error) {
	stored, exists, err := readRefreshRun(ctx, tx, running.ID)
	if err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	if !exists {
		return SecurityEnrichmentImportResult{}, ErrIngestConflict
	}
	result := SecurityEnrichmentImportResult{Entries: len(c.Feed.Entries)}
	if stored.Result == model.IngestResultSuccess {
		if err := checkRefreshSuccess(ctx, tx, stored, success, c); err != nil {
			return SecurityEnrichmentImportResult{}, err
		}
		result.Replay = true
		return result, nil
	}
	if !equalRefreshRun(stored, running) {
		return SecurityEnrichmentImportResult{}, ErrIngestConflict
	}
	if err := checkRefreshNoEvidence(ctx, tx, running.ID); err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	if err := validateCurrentRefreshTargets(ctx, tx, c.Attempt.Targets); err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	if err := appendSecurityEnrichment(ctx, tx, success, c.Feed, c.OriginalDigest); err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	if err := updateRefreshRun(ctx, tx, running, success); err != nil {
		return SecurityEnrichmentImportResult{}, err
	}
	return result, nil
}

func failSecurityEnrichmentRefreshTx(ctx context.Context, tx *sql.Tx, running, failed model.IngestRun) (bool, error) {
	stored, exists, err := readRefreshRun(ctx, tx, running.ID)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, ErrIngestConflict
	}
	if err := checkRefreshNoEvidence(ctx, tx, running.ID); err != nil {
		return false, err
	}
	if equalRefreshRun(stored, failed) {
		return true, nil
	}
	if !equalRefreshRun(stored, running) {
		return false, ErrIngestConflict
	}
	if err := updateRefreshRun(ctx, tx, running, failed); err != nil {
		return false, err
	}
	return false, nil
}

func equalRefreshRun(a, b model.IngestRun) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && string(x) == string(y)
}

func readRefreshRun(ctx context.Context, tx *sql.Tx, id string) (model.IngestRun, bool, error) {
	var r model.IngestRun
	var connector, scope, start, result, coverage, cursor, code, body string
	var finish sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT connector,scope,started_at,finished_at,result,coverage,cursor,error,CASE WHEN length(CAST(body_json AS BLOB))<=4096 THEN body_json ELSE '' END FROM ingest_runs WHERE id=?`, id).Scan(&connector, &scope, &start, &finish, &result, &coverage, &cursor, &code, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, fmt.Errorf("read refresh receipt: %w", err)
	}
	if decodePreviewStoredJSON(body, &r) != nil || r.ID != id || r.Connector != connector || r.Scope != scope || r.StartedAt.UTC().Format(time.RFC3339Nano) != start || r.Result != result || r.Coverage != coverage || r.Cursor != cursor || r.Error != code || (r.FinishedAt != nil) != finish.Valid || (finish.Valid && r.FinishedAt.UTC().Format(time.RFC3339Nano) != finish.String) {
		return r, false, ErrIngestConflict
	}
	return r, true, nil
}

func updateRefreshRun(ctx context.Context, tx *sql.Tx, before, after model.IngestRun) error {
	body, err := json.Marshal(after)
	if err != nil {
		return fmt.Errorf("encode refresh state: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE ingest_runs SET finished_at=?,result=?,coverage=?,cursor=?,error=?,body_json=? WHERE id=? AND result='running' AND cursor=?`, after.FinishedAt.Format(time.RFC3339Nano), after.Result, after.Coverage, after.Cursor, after.Error, string(body), before.ID, before.Cursor)
	if err != nil {
		return fmt.Errorf("write refresh state: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count refresh state write: %w", err)
	}
	if n != 1 {
		return ErrIngestConflict
	}
	return nil
}

func countRefreshEvidence(ctx context.Context, tx *sql.Tx, id string) (int, int, error) {
	var manifests, observations int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_enrichment_runs WHERE ingest_run_id=?`, id).Scan(&manifests); err != nil {
		return 0, 0, fmt.Errorf("count refresh manifest: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT id FROM security_enrichment_observations WHERE ingest_run_id=? LIMIT 201)`, id).Scan(&observations); err != nil {
		return 0, 0, fmt.Errorf("count bounded refresh evidence: %w", err)
	}
	return manifests, observations, nil
}

func checkRefreshNoEvidence(ctx context.Context, tx *sql.Tx, id string) error {
	manifests, observations, err := countRefreshEvidence(ctx, tx, id)
	if err != nil {
		return err
	}
	if manifests != 0 || observations != 0 {
		return ErrIngestConflict
	}
	return nil
}

func checkRefreshSuccess(ctx context.Context, tx *sql.Tx, stored, expected model.IngestRun, c SecurityEnrichmentRefreshCompletion) error {
	if !equalRefreshRun(stored, expected) {
		return ErrIngestConflict
	}
	manifests, observations, err := countRefreshEvidence(ctx, tx, expected.ID)
	if err != nil {
		return err
	}
	if manifests != 1 || observations != len(c.Feed.Entries) {
		return ErrIngestConflict
	}
	var source, version, pub, obs, selection, digest string
	var entries int
	if err := tx.QueryRowContext(ctx, `SELECT source,version,published_at,observed_at,CASE WHEN length(CAST(selected_cves_json AS BLOB))<=8192 THEN selected_cves_json ELSE '' END,entries,original_digest FROM security_enrichment_runs WHERE ingest_run_id=?`, expected.ID).Scan(&source, &version, &pub, &obs, &selection, &entries, &digest); err != nil {
		return fmt.Errorf("read refresh manifest: %w", err)
	}
	selected, err := json.Marshal(c.Feed.SelectedCVEs)
	if err != nil {
		return fmt.Errorf("encode expected refresh selection: %w", err)
	}
	if source != c.Feed.Source || version != c.Feed.Version || pub != c.Feed.PublishedAt.Format(time.RFC3339Nano) || obs != c.Feed.ObservedAt.Format(time.RFC3339Nano) || selection != string(selected) || entries != len(c.Feed.Entries) || digest != c.OriginalDigest {
		return ErrIngestConflict
	}
	for _, entry := range c.Feed.Entries {
		identity, body, id, err := securityEnrichmentEvidenceJSON(expected.ID, c.Feed, entry)
		if err != nil {
			return err
		}
		var gotID, gotIdentity, gotBody, gotPub, gotObs string
		if err := tx.QueryRowContext(ctx, `SELECT id,evidence_identity,CASE WHEN length(CAST(body_json AS BLOB))<=4096 THEN body_json ELSE '' END,published_at,observed_at FROM security_enrichment_observations WHERE ingest_run_id=? AND source=? AND cve_id=?`, expected.ID, c.Feed.Source, entry.CVEID).Scan(&gotID, &gotIdentity, &gotBody, &gotPub, &gotObs); err != nil {
			return fmt.Errorf("read expected refresh evidence: %w", err)
		}
		if gotID != id || gotIdentity != identity || gotBody != body || gotPub != pub || gotObs != obs {
			return ErrIngestConflict
		}
	}
	return nil
}
