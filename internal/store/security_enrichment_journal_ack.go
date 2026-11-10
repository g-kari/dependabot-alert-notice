package store

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

// SecurityEnrichmentJournalAcknowledgementState classifies exact read-only
// checkpoint matching as matched, missing, conflict or unknown. Only matched
// returns an acknowledgement and verified head. This is not business success,
// fresh reservation ownership, restoration or permission to repeat a write.
type SecurityEnrichmentJournalAcknowledgementState struct {
	State           string
	Acknowledgement enrichmentjournal.Acknowledgement
	HeadSequence    int64
	HeadDigest      string
}

// ReadSecurityEnrichmentCheckpointAcknowledgement checks the retained request in
// a read-only snapshot. It never appends, repairs, retries or rewrites receipts.
func (s *Store) ReadSecurityEnrichmentCheckpointAcknowledgement(ctx context.Context, expected enrichmentjournal.AppendRequest) (SecurityEnrichmentJournalAcknowledgementState, error) {
	unknown := SecurityEnrichmentJournalAcknowledgementState{State: "unknown"}
	if ctx == nil || expected.Sequence < 1 || expected.Sequence > journalMaxCheckpoints || (expected.Sequence == 1 && expected.PreviousDigest != "") || (expected.Sequence > 1 && !journalValidDigest(expected.PreviousDigest)) {
		return unknown, journalError(ctx, errJournalConflict)
	}
	if ctx.Err() != nil {
		return unknown, journalError(ctx, errJournalStorage)
	}
	payload, err := enrichmentjournal.Encode(expected.Checkpoint)
	if err != nil {
		return unknown, journalError(ctx, errJournalConflict)
	}
	digest := journalDigest(payload)
	id := expected.Checkpoint.OperationID
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return unknown, journalError(ctx, errJournalStorage)
	}
	defer func() { _ = tx.Rollback() }()
	header, exists, err := readJournalHeader(ctx, tx, id)
	if err != nil {
		return unknown, err
	}
	rows, err := readJournalRows(ctx, tx, id)
	if err != nil {
		return unknown, err
	}
	if err := checkJournalHistory(header, exists, rows); err != nil {
		return unknown, journalError(ctx, err)
	}
	out := SecurityEnrichmentJournalAcknowledgementState{State: "missing"}
	if !exists {
		if expected.Sequence != 1 || enrichmentjournal.ValidateTransition(nil, expected.Checkpoint) != nil {
			out.State = "conflict"
		}
	} else if expected.Sequence <= header.Sequence {
		row := rows[expected.Sequence-1]
		if row.previous != expected.PreviousDigest || row.digest != digest || !bytes.Equal(row.payload, payload) {
			out.State = "conflict"
		} else {
			out = SecurityEnrichmentJournalAcknowledgementState{State: "matched",
				Acknowledgement: enrichmentjournal.Acknowledgement{OperationID: id, Sequence: expected.Sequence, Digest: digest, Replay: true},
				HeadSequence:    header.Sequence, HeadDigest: header.Digest}
		}
	} else {
		last := rows[len(rows)-1]
		if expected.Sequence != header.Sequence+1 || expected.PreviousDigest != header.Digest || enrichmentjournal.ValidateTransition(&last.checkpoint, expected.Checkpoint) != nil {
			out.State = "conflict"
		}
	}
	if err := tx.Commit(); err != nil {
		return unknown, journalError(ctx, errJournalStorage)
	}
	if ctx.Err() != nil {
		return unknown, journalError(ctx, errJournalStorage)
	}
	return out, nil
}
