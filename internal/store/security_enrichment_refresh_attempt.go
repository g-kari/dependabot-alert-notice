package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// SecurityEnrichmentRefreshFailure identifies the exact failure write expected
// by a caller reconciling an uncertain Fail outcome. It contains no source data.
type SecurityEnrichmentRefreshFailure struct {
	Code       string
	FinishedAt time.Time
}

// ReadSecurityEnrichmentRefreshAttempt reads only one reservation in a read-only
// snapshot. It can confirm missing, running or an exactly expected failure, but
// never success without the full completion. Receipt is always empty.
func (s *Store) ReadSecurityEnrichmentRefreshAttempt(ctx context.Context, attempt SecurityEnrichmentRefreshAttempt, expectedFailure *SecurityEnrichmentRefreshFailure) (SecurityEnrichmentRefreshState, error) {
	unknown := SecurityEnrichmentRefreshState{State: "unknown"}
	_, running, _, err := normalizeRefreshAttempt(attempt)
	if err != nil {
		return unknown, err
	}
	var failed *model.IngestRun
	if expectedFailure != nil {
		if !refreshFailureCode(expectedFailure.Code) || !securityTime(expectedFailure.FinishedAt) || !securityTime(expectedFailure.FinishedAt.UTC()) || expectedFailure.FinishedAt.Before(running.StartedAt) {
			return unknown, fmt.Errorf("invalid expected refresh failure")
		}
		finish := expectedFailure.FinishedAt.UTC()
		run := running
		run.Result, run.Error, run.FinishedAt = model.IngestResultFailed, expectedFailure.Code, &finish
		failed = &run
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return unknown, fmt.Errorf("begin refresh attempt readback: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	body, exists, err := boundedRefreshAttemptBody(ctx, tx, running.ID)
	if err != nil {
		return unknown, err
	}
	state := unknown
	if !exists {
		// Missing is not established if a manifest or observation survives
		// without its parent run. Never hide an orphan as an unused UUID.
		if err := checkRefreshAttemptNoEvidence(ctx, tx, running.ID); err != nil {
			return unknown, err
		}
		state.State = "missing"
	} else {
		stored, found, err := readRefreshRun(ctx, tx, running.ID)
		if err != nil {
			return unknown, err
		}
		if !found {
			return unknown, ErrIngestConflict
		}
		encoded, err := json.Marshal(stored)
		if err != nil {
			return unknown, fmt.Errorf("encode refresh attempt readback: %w", err)
		}
		if body != string(encoded) || stored.ID != running.ID || stored.Connector != running.Connector || stored.Scope != running.Scope || !stored.StartedAt.Equal(running.StartedAt) {
			return unknown, ErrIngestConflict
		}
		switch stored.Result {
		case model.IngestResultRunning:
			if !equalRefreshRun(stored, running) {
				return unknown, ErrIngestConflict
			}
			if err := checkRefreshAttemptNoEvidence(ctx, tx, running.ID); err != nil {
				return unknown, err
			}
			state.State = "running"
		case model.IngestResultFailed:
			if stored.FinishedAt == nil || !securityTime(*stored.FinishedAt) || stored.FinishedAt.Before(running.StartedAt) || !refreshFailureCode(stored.Error) {
				return unknown, ErrIngestConflict
			}
			expected := running
			expected.Result, expected.Error, expected.FinishedAt = model.IngestResultFailed, stored.Error, stored.FinishedAt
			if !equalRefreshRun(stored, expected) {
				return unknown, ErrIngestConflict
			}
			if err := checkRefreshAttemptNoEvidence(ctx, tx, running.ID); err != nil {
				return unknown, err
			}
			if failed != nil {
				if !equalRefreshRun(stored, *failed) {
					return unknown, ErrIngestConflict
				}
				state.State = "failed"
			}
		case model.IngestResultSuccess:
			if stored.FinishedAt == nil || !securityTime(*stored.FinishedAt) || stored.FinishedAt.Before(running.StartedAt) || stored.Coverage != model.IngestCoveragePartial || stored.Error != "" || !strings.HasPrefix(stored.Cursor, "refresh-success-v1:sha256:") || !securityDigest(strings.TrimPrefix(stored.Cursor, "refresh-success-v1:sha256:")) {
				return unknown, ErrIngestConflict
			}
			// The success cursor commits to the full feed, not just the
			// attempt. Do not expose it or infer the completion from this row.
		default:
			return unknown, ErrIngestConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return unknown, fmt.Errorf("finish refresh attempt readback: %w", err)
	}
	return state, nil
}

func boundedRefreshAttemptBody(ctx context.Context, tx *sql.Tx, id string) (string, bool, error) {
	var alias int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM ingest_runs WHERE id=CAST(? AS BLOB))`, id).Scan(&alias); err != nil {
		return "", false, fmt.Errorf("read refresh UUID storage alias: %w", err)
	}
	if alias != 0 {
		return "", false, ErrIngestConflict
	}
	var body sql.NullString
	// Check scalar storage types and byte bounds before readRefreshRun loads
	// any scalar field. Only a capped canonical body reaches application memory.
	err := tx.QueryRowContext(ctx, `SELECT CASE WHEN
typeof(id)='text' AND length(CAST(id AS BLOB))=36 AND
typeof(connector)='text' AND length(CAST(connector AS BLOB)) BETWEEN 1 AND 64 AND
typeof(scope)='text' AND length(CAST(scope AS BLOB)) BETWEEN 1 AND 256 AND
typeof(started_at)='text' AND length(CAST(started_at AS BLOB)) BETWEEN 1 AND 40 AND
(finished_at IS NULL OR (typeof(finished_at)='text' AND length(CAST(finished_at AS BLOB)) BETWEEN 1 AND 40)) AND
typeof(result)='text' AND length(CAST(result AS BLOB)) BETWEEN 1 AND 16 AND
typeof(coverage)='text' AND length(CAST(coverage AS BLOB)) BETWEEN 1 AND 16 AND
typeof(cursor)='text' AND length(CAST(cursor AS BLOB)) BETWEEN 1 AND 128 AND
typeof(error)='text' AND length(CAST(error AS BLOB)) BETWEEN 0 AND 64 AND
typeof(body_json)='text' AND length(CAST(body_json AS BLOB)) BETWEEN 2 AND 4096
THEN body_json ELSE NULL END FROM ingest_runs WHERE id=?`, id).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read bounded refresh attempt: %w", err)
	}
	if !body.Valid {
		return "", false, ErrIngestConflict
	}
	return body.String, true, nil
}

func checkRefreshAttemptNoEvidence(ctx context.Context, tx *sql.Tx, id string) error {
	if err := checkRefreshNoEvidence(ctx, tx, id); err != nil {
		return err
	}
	var aliases int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM security_enrichment_runs WHERE ingest_run_id=CAST(? AS BLOB)) OR EXISTS(SELECT 1 FROM security_enrichment_observations WHERE ingest_run_id=CAST(? AS BLOB))`, id, id).Scan(&aliases); err != nil {
		return fmt.Errorf("read refresh evidence storage aliases: %w", err)
	}
	if aliases != 0 {
		return ErrIngestConflict
	}
	return nil
}
