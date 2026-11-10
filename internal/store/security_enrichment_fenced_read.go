package store

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

type fencedReservationSnapshot struct {
	header journalHeader
	rows   []journalRow
}

// readFencedReservationTx verifies the original reserved payload and active
// source generation even after the head advances. It never nests the public
// still-reserved-only reader or derives execution ownership from a generic read.
func readFencedReservationTx(ctx context.Context, tx *sql.Tx, p preparedFencedRequest) (fencedReservationSnapshot, string, error) {
	var snapshot fencedReservationSnapshot
	sources, err := readReservationSources(ctx, tx)
	if err != nil {
		return snapshot, "unknown", fencedError(ctx, errFencedCorrupt)
	}
	if err := checkReservationSources(ctx, tx, sources); err != nil {
		return snapshot, "unknown", fencedError(ctx, errFencedCorrupt)
	}
	expected := p.reservation.request
	records, err := readReservationBindings(ctx, tx, expected.Reserved.Checkpoint.OperationID, expected.IntentID)
	if err != nil {
		return snapshot, "unknown", fencedError(ctx, errFencedCorrupt)
	}
	header, exists, rows, err := reservationJournalTx(ctx, tx, expected.Reserved.Checkpoint.OperationID)
	if err != nil {
		return snapshot, "unknown", fencedError(ctx, errFencedCorrupt)
	}
	if len(records) == 0 {
		state := "missing"
		if exists {
			state = "conflict"
		}
		return snapshot, state, nil
	}
	if len(records) != 1 {
		return snapshot, "conflict", nil
	}
	record := records[0]
	if record.OperationID != expected.Reserved.Checkpoint.OperationID || record.IntentID != expected.IntentID || record.Connector != expected.Reserved.Checkpoint.Request.Connector || record.ExpectedGeneration != expected.ExpectedGeneration || record.Generation != p.reservation.generation || record.Digest != expected.ReservedDigest || !bytes.Equal(record.payload, p.reservation.payload) {
		return snapshot, "conflict", nil
	}
	if !exists || len(rows) == 0 || rows[0].digest != expected.ReservedDigest || !bytes.Equal(rows[0].payload, p.reservation.payload) {
		return snapshot, "unknown", fencedError(ctx, errFencedCorrupt)
	}
	source := sources[record.Connector]
	if source.OperationID == nil || source.IntentID == nil || source.Generation != record.Generation || *source.OperationID != record.OperationID || *source.IntentID != record.IntentID {
		return snapshot, "conflict", nil
	}
	return fencedReservationSnapshot{header: header, rows: rows}, "matched", nil
}

func fencedCheckpointProofTx(ctx context.Context, tx *sql.Tx, p preparedFencedRequest) (SecurityEnrichmentFencedProof, error) {
	unknown := fencedUnknown()
	snapshot, state, err := readFencedReservationTx(ctx, tx, p)
	if err != nil {
		return unknown, err
	}
	if state != "matched" {
		unknown.State = state
		return unknown, nil
	}
	if p.checkpoint.Sequence != snapshot.header.Sequence {
		unknown.State = "conflict"
		if p.checkpoint.Sequence == snapshot.header.Sequence+1 && p.checkpoint.PreviousDigest == snapshot.header.Digest && enrichmentjournal.ValidateTransition(&snapshot.rows[len(snapshot.rows)-1].checkpoint, p.checkpoint.Checkpoint) == nil {
			unknown.State = "missing"
		}
		return unknown, nil
	}
	row := snapshot.rows[p.checkpoint.Sequence-1]
	if row.previous != p.checkpoint.PreviousDigest || row.digest != p.digest || !bytes.Equal(row.payload, p.payload) {
		unknown.State = "conflict"
		return unknown, nil
	}
	return SecurityEnrichmentFencedProof{State: "matched", Acknowledgement: fencedAck(p, true),
		Business: SecurityEnrichmentRefreshState{State: "unknown"}, HeadSequence: snapshot.header.Sequence, HeadDigest: snapshot.header.Digest}, nil
}

func fencedBusinessProofTx(ctx context.Context, tx *sql.Tx, p preparedFencedRequest) (SecurityEnrichmentFencedProof, error) {
	unknown := fencedUnknown()
	proof, err := fencedCheckpointProofTx(ctx, tx, p)
	if err != nil || proof.State != "matched" {
		return proof, err
	}
	prepared := p.checkpoint.Checkpoint.Prepared
	if prepared == nil {
		unknown.State = "conflict"
		return unknown, nil
	}
	want := "running"
	if prepared.Completion != nil {
		want = "success"
	} else if prepared.Failure != nil {
		want = "failed"
	}
	business, err := inspectOperationBusinessTx(ctx, tx, p.checkpoint.Checkpoint)
	if err != nil {
		return unknown, fencedError(ctx, errFencedCorrupt)
	}
	if business.State != want {
		// In particular a Complete CP with a running/missing run is not a
		// business acknowledgement. Never expose the matched CP Ack/head.
		unknown.Business = business
		if business.State == "missing" {
			unknown.State = "missing"
		}
		return unknown, nil
	}
	proof.Business = business
	return proof, nil
}
