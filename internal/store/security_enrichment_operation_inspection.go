package store

import (
	"context"
	"database/sql"
	"slices"
	"strings"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// SecurityEnrichmentOperationInspection separates a history-verified journal
// candidate from historical business proof. State is valid, missing or unknown;
// only valid returns a head/checkpoint. Business is never inferred from journal
// outcome or acknowledgement. Unprepared/no_run have no business UUID or receipt.
// A valid candidate may accompany Business unknown and a proof error. This is
// not run-ready restoration, ownership, liveness or a current-Finding assertion.
type SecurityEnrichmentOperationInspection struct {
	State        string
	OperationID  string
	HeadSequence int64
	HeadDigest   string
	Checkpoint   *enrichmentjournal.Checkpoint
	Business     SecurityEnrichmentRefreshState
}

// InspectSecurityEnrichmentOperation reads one canonical OperationID in a single
// read-only snapshot. It verifies at most five checkpoints and, when available,
// the exact retained completion or expected failure. It never writes, repairs,
// restores a controller, grants fetch ownership or generates UUIDs/clocks.
func (s *Store) InspectSecurityEnrichmentOperation(ctx context.Context, operationID string) (SecurityEnrichmentOperationInspection, error) {
	unknown := SecurityEnrichmentOperationInspection{State: "unknown", Business: SecurityEnrichmentRefreshState{State: "unknown"}}
	if ctx == nil || !securityUUID(operationID) || strings.Count(operationID, "-") != 4 {
		return unknown, journalError(ctx, errJournalConflict)
	}
	if ctx.Err() != nil || s == nil || s.db == nil {
		return unknown, journalError(ctx, errJournalStorage)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return unknown, journalError(ctx, errJournalStorage)
	}
	defer func() { _ = tx.Rollback() }()
	header, exists, err := readJournalHeader(ctx, tx, operationID)
	if err != nil {
		return unknown, err
	}
	rows, err := readJournalRows(ctx, tx, operationID)
	if err != nil {
		return unknown, err
	}
	if err := checkJournalHistory(header, exists, rows); err != nil {
		return unknown, journalError(ctx, err)
	}
	out := SecurityEnrichmentOperationInspection{State: "missing", OperationID: operationID, Business: unknown.Business}
	var proofErr error
	if exists {
		// Decode allocated every nested value for this call. No Store-owned
		// cache or other caller shares this candidate or the conversion below.
		checkpoint := rows[len(rows)-1].checkpoint
		out.State, out.HeadSequence, out.HeadDigest = "valid", header.Sequence, header.Digest
		out.Checkpoint = &checkpoint
		out.Business, proofErr = inspectOperationBusinessTx(ctx, tx, checkpoint)
	}
	if err := tx.Commit(); err != nil {
		return unknown, journalError(ctx, errJournalStorage)
	}
	if ctx.Err() != nil {
		return unknown, journalError(ctx, errJournalStorage)
	}
	if proofErr != nil {
		// The journal candidate remains independently valid, but SQL/body
		// details cannot escape as an error or become business success.
		return out, journalError(ctx, errJournalCorrupt)
	}
	return out, nil
}

func inspectOperationBusinessTx(ctx context.Context, tx *sql.Tx, checkpoint enrichmentjournal.Checkpoint) (SecurityEnrichmentRefreshState, error) {
	unknown := SecurityEnrichmentRefreshState{State: "unknown"}
	if checkpoint.Prepared == nil {
		state := "unprepared"
		if checkpoint.Stage == enrichmentjournal.Returned {
			state = "no_run"
		}
		return SecurityEnrichmentRefreshState{State: state}, nil
	}
	attempt, failure, completion := operationInspectionPrepared(*checkpoint.Prepared)
	_, running, _, err := normalizeRefreshAttempt(attempt)
	if err != nil {
		return unknown, err
	}
	var failed *model.IngestRun
	if failure != nil {
		if !refreshFailureCode(failure.Code) || !securityTime(failure.FinishedAt) || !securityTime(failure.FinishedAt.UTC()) || failure.FinishedAt.Before(running.StartedAt) {
			return unknown, ErrIngestConflict
		}
		finish := failure.FinishedAt.UTC()
		run := running
		run.Result, run.Error, run.FinishedAt = model.IngestResultFailed, failure.Code, &finish
		failed = &run
	}
	state, err := readSecurityEnrichmentRefreshAttemptTx(ctx, tx, running, failed)
	if err != nil || completion == nil || state.State != "unknown" {
		return state, err
	}
	// An attempt-only success remains unknown. A full completion permits
	// success only after matching its receipt, manifest and every observation.
	c, _, success, err := normalizeRefreshCompletion(*completion)
	if err != nil {
		return unknown, err
	}
	stored, exists, err := readRefreshRun(ctx, tx, running.ID)
	if err != nil {
		return unknown, err
	}
	if !exists || stored.Result != model.IngestResultSuccess {
		// No ExpectedFailure was retained: a failed row cannot be promoted
		// to a verified terminal from a Completion or journal outcome.
		return unknown, nil
	}
	if err := checkOperationInspectionEvidenceBounds(ctx, tx, running.ID); err != nil {
		return unknown, err
	}
	if err := checkRefreshSuccess(ctx, tx, stored, success, c); err != nil {
		return unknown, err
	}
	return SecurityEnrichmentRefreshState{State: "success", Receipt: success.Cursor}, nil
}

// operationInspectionPrepared copies explicitly between the leaf DTO and the
// existing Store proof types. It preserves nil/empty slices, pointer values,
// exact clocks and digests, and never consults current Finding revisions.
func operationInspectionPrepared(prepared enrichmentjournal.Prepared) (SecurityEnrichmentRefreshAttempt, *SecurityEnrichmentRefreshFailure, *SecurityEnrichmentRefreshCompletion) {
	a := prepared.Attempt
	attempt := SecurityEnrichmentRefreshAttempt{RunID: a.RunID, Connector: a.Connector, Scope: a.Scope, StartedAt: a.StartedAt}
	if a.Targets != nil {
		attempt.Targets = make([]SecurityEnrichmentRefreshTarget, len(a.Targets))
		for i, target := range a.Targets {
			attempt.Targets[i] = SecurityEnrichmentRefreshTarget{FindingID: target.FindingID, CVEID: target.CVEID, Revision: target.Revision}
		}
	}
	var failure *SecurityEnrichmentRefreshFailure
	if prepared.Failure != nil {
		failure = &SecurityEnrichmentRefreshFailure{Code: prepared.Failure.Code, FinishedAt: prepared.Failure.FinishedAt}
	}
	var completion *SecurityEnrichmentRefreshCompletion
	if prepared.Completion != nil {
		c := prepared.Completion
		f := c.Feed
		feed := model.SecurityEnrichmentFeed{Source: f.Source, Version: f.Version, PublishedAt: f.PublishedAt, ObservedAt: f.ObservedAt, SelectedCVEs: slices.Clone(f.SelectedCVEs)}
		if f.Entries != nil {
			feed.Entries = make([]model.SecurityEnrichmentEntry, len(f.Entries))
			for i, e := range f.Entries {
				entry := model.SecurityEnrichmentEntry{CVEID: e.CVEID, KEV: e.KEV}
				if e.EPSS != nil {
					value := *e.EPSS
					entry.EPSS = &value
				}
				if e.Percentile != nil {
					value := *e.Percentile
					entry.Percentile = &value
				}
				if e.KEVDateAdded != nil {
					value := *e.KEVDateAdded
					entry.KEVDateAdded = &value
				}
				feed.Entries[i] = entry
			}
		}
		// Attempt.Targets is independent even of the other converted return.
		ownedAttempt := attempt
		ownedAttempt.Targets = slices.Clone(attempt.Targets)
		completion = &SecurityEnrichmentRefreshCompletion{Attempt: ownedAttempt, Feed: feed, OriginalDigest: c.OriginalDigest, FinishedAt: c.FinishedAt}
	}
	return attempt, failure, completion
}

func checkOperationInspectionEvidenceBounds(ctx context.Context, tx *sql.Tx, id string) error {
	var invalid bool
	// Indexed finite UUID aliases are corruption, not missing evidence.
	if err := tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM security_enrichment_runs WHERE ingest_run_id=CAST(? AS BLOB)) OR
EXISTS(SELECT 1 FROM security_enrichment_observations WHERE ingest_run_id=CAST(? AS BLOB))`, id, id).Scan(&invalid); err != nil {
		return err
	}
	if invalid {
		return ErrIngestConflict
	}
	// Before the existing exact proof loads any scalar/body, enforce storage
	// types and byte caps. These guards bound materialization, not all DB work.
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM security_enrichment_runs WHERE ingest_run_id=? AND NOT (
typeof(ingest_run_id)='text' AND length(CAST(ingest_run_id AS BLOB))=36 AND
typeof(source)='text' AND length(CAST(source AS BLOB)) BETWEEN 3 AND 4 AND
typeof(version)='text' AND length(CAST(version AS BLOB)) BETWEEN 1 AND 64 AND
typeof(published_at)='text' AND length(CAST(published_at AS BLOB)) BETWEEN 1 AND 40 AND
typeof(observed_at)='text' AND length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 40 AND
typeof(selected_cves_json)='text' AND length(CAST(selected_cves_json AS BLOB)) BETWEEN 2 AND 8192 AND
typeof(entries)='integer' AND entries BETWEEN 0 AND 200 AND
typeof(original_digest)='text' AND length(CAST(original_digest AS BLOB))=71))`, id).Scan(&invalid); err != nil {
		return err
	}
	if invalid {
		return ErrIngestConflict
	}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM (
SELECT * FROM security_enrichment_observations WHERE ingest_run_id=? LIMIT 201
) WHERE NOT (
typeof(id)='text' AND length(CAST(id AS BLOB))=64 AND
typeof(ingest_run_id)='text' AND length(CAST(ingest_run_id AS BLOB))=36 AND
typeof(source)='text' AND length(CAST(source AS BLOB)) BETWEEN 3 AND 4 AND
typeof(cve_id)='text' AND length(CAST(cve_id AS BLOB)) BETWEEN 13 AND 28 AND
typeof(published_at)='text' AND length(CAST(published_at AS BLOB)) BETWEEN 1 AND 40 AND
typeof(observed_at)='text' AND length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 40 AND
typeof(evidence_identity)='text' AND length(CAST(evidence_identity AS BLOB)) BETWEEN 2 AND 4096 AND
typeof(body_json)='text' AND length(CAST(body_json AS BLOB)) BETWEEN 2 AND 4096))`, id).Scan(&invalid); err != nil {
		return err
	}
	if invalid {
		return ErrIngestConflict
	}
	return nil
}
