package store

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrelease"
)

type preparedRelease struct {
	inspection      enrichmentrelease.Inspection
	reservation     preparedReservation
	terminalPayload []byte
}

func prepareRelease(ctx context.Context, request enrichmentrelease.ReleaseRequest) (preparedRelease, error) {
	if ctx == nil {
		return preparedRelease{}, releaseError(ctx, errReleaseConflict)
	}
	if ctx.Err() != nil {
		return preparedRelease{}, releaseError(ctx, errReleaseStorage)
	}
	// Pure leaf validation bounds strings/slices before encoding and owns
	// all nested values. No UUID, clock or duplicate business input exists.
	inspection, err := enrichmentrelease.InspectTerminal(request)
	if err != nil {
		return preparedRelease{}, releaseError(ctx, errReleaseConflict)
	}
	r := inspection.Request.Reservation
	reservation, err := prepareReservation(ctx, SecurityEnrichmentReservationRequest{
		IntentID: r.IntentID, ExpectedGeneration: r.ExpectedGeneration,
		Reserved: r.Reserved, ReservedDigest: r.ReservedDigest})
	if err != nil {
		return preparedRelease{}, releaseError(ctx, errReleaseConflict)
	}
	payload, err := enrichmentjournal.Encode(inspection.Request.Terminal.Checkpoint)
	if err != nil {
		return preparedRelease{}, releaseError(ctx, errReleaseConflict)
	}
	return preparedRelease{inspection: inspection, reservation: reservation, terminalPayload: payload}, nil
}

func releaseActiveMatches(source reservationSource, p preparedReservation) bool {
	return source.Connector == p.request.Reserved.Checkpoint.Request.Connector &&
		source.Generation == p.generation && source.OperationID != nil && source.IntentID != nil &&
		*source.OperationID == p.request.Reserved.Checkpoint.OperationID && *source.IntentID == p.request.IntentID
}

// releaseHistoryTx uses only bounded raw binding/journal readers. Unlike the
// active fenced wrapper it never calls the source checker, a public reader,
// mutex or another transaction. This lower layer is safe for idle validation.
func releaseHistoryTx(ctx context.Context, tx *sql.Tx, p preparedRelease) (journalHeader, string, error) {
	empty := journalHeader{}
	expected := p.reservation.request
	records, err := readReservationBindings(ctx, tx, expected.Reserved.Checkpoint.OperationID, expected.IntentID)
	if err != nil {
		return empty, "unknown", releaseError(ctx, errReleaseCorrupt)
	}
	header, exists, rows, err := reservationJournalTx(ctx, tx, expected.Reserved.Checkpoint.OperationID)
	if err != nil {
		return empty, "unknown", releaseError(ctx, errReleaseCorrupt)
	}
	if len(records) == 0 {
		if exists {
			return empty, "conflict", nil
		}
		return empty, "missing", nil
	}
	if len(records) != 1 {
		return empty, "conflict", nil
	}
	record := records[0]
	if record.OperationID != expected.Reserved.Checkpoint.OperationID || record.IntentID != expected.IntentID ||
		record.Connector != expected.Reserved.Checkpoint.Request.Connector || record.ExpectedGeneration != expected.ExpectedGeneration ||
		record.Generation != p.reservation.generation || record.Digest != expected.ReservedDigest || !bytes.Equal(record.payload, p.reservation.payload) {
		return empty, "conflict", nil
	}
	if !exists || len(rows) == 0 || rows[0].digest != record.Digest || !bytes.Equal(rows[0].payload, record.payload) {
		return empty, "unknown", releaseError(ctx, errReleaseCorrupt)
	}
	terminal := p.inspection.Request.Terminal
	last := rows[len(rows)-1]
	if header.Sequence != terminal.Sequence || header.Digest != p.inspection.Request.TerminalDigest ||
		last.previous != terminal.PreviousDigest || last.digest != p.inspection.Request.TerminalDigest || !bytes.Equal(last.payload, p.terminalPayload) {
		return empty, "conflict", nil
	}
	return header, "matched", nil
}

func expectedReleaseTx(ctx context.Context, tx *sql.Tx, p preparedRelease) (SecurityEnrichmentReleaseAcknowledgement, string, error) {
	empty := SecurityEnrichmentReleaseAcknowledgement{}
	header, state, err := releaseHistoryTx(ctx, tx, p)
	if err != nil || state != "matched" {
		return empty, state, err
	}
	checkpoint := p.inspection.Request.Terminal.Checkpoint
	business, err := inspectOperationBusinessTx(ctx, tx, checkpoint)
	if err != nil || business.State != p.inspection.Kind {
		return empty, "unknown", releaseError(ctx, errReleaseCorrupt)
	}
	if p.inspection.Kind == "no_run" && (header.RunID != nil || checkpoint.Prepared != nil || checkpoint.Progress.RunID != "" || business.Receipt != "") {
		return empty, "unknown", releaseError(ctx, errReleaseCorrupt)
	}
	r := p.inspection.Request
	c := enrichmentrelease.Certificate{
		Version:     enrichmentrelease.CertificateVersion,
		OperationID: r.Reservation.Reserved.Checkpoint.OperationID, IntentID: r.Reservation.IntentID,
		Connector: r.Reservation.Reserved.Checkpoint.Request.Connector, Generation: p.reservation.generation,
		ReservedDigest: r.Reservation.ReservedDigest, TerminalSequence: r.Terminal.Sequence,
		TerminalPreviousDigest: r.Terminal.PreviousDigest, TerminalDigest: r.TerminalDigest,
		Kind: p.inspection.Kind, Receipt: business.Receipt}
	if p.inspection.RunID != "" {
		id := p.inspection.RunID
		c.RunID = &id
	}
	data, err := enrichmentrelease.EncodeCertificate(c)
	if err != nil {
		return empty, "unknown", releaseError(ctx, errReleaseCorrupt)
	}
	return SecurityEnrichmentReleaseAcknowledgement{Certificate: c, CertificateDigest: journalDigest(data)}, "matched", nil
}

// storedReleasePreparedTx reconstructs only the exact already-stored root and
// terminal for historical proof. It does not acquire active/fetch ownership.
func storedReleasePreparedTx(ctx context.Context, tx *sql.Tx, c enrichmentrelease.Certificate) (preparedRelease, error) {
	records, err := readReservationBindings(ctx, tx, c.OperationID, c.IntentID)
	if err != nil || len(records) != 1 {
		return preparedRelease{}, releaseError(ctx, errReleaseCorrupt)
	}
	record := records[0]
	_, exists, rows, err := reservationJournalTx(ctx, tx, c.OperationID)
	if err != nil || !exists || len(rows) == 0 {
		return preparedRelease{}, releaseError(ctx, errReleaseCorrupt)
	}
	if record.OperationID != c.OperationID || record.IntentID != c.IntentID || record.Connector != c.Connector || record.Generation != c.Generation || record.Digest != c.ReservedDigest {
		return preparedRelease{}, releaseError(ctx, errReleaseCorrupt)
	}
	last := rows[len(rows)-1]
	return prepareRelease(ctx, enrichmentrelease.ReleaseRequest{
		Reservation: enrichmentrelease.ReservationRequest{
			IntentID: record.IntentID, ExpectedGeneration: record.ExpectedGeneration,
			Reserved: enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: rows[0].checkpoint}, ReservedDigest: record.Digest},
		Terminal: enrichmentjournal.AppendRequest{Sequence: last.sequence, PreviousDigest: last.previous, Checkpoint: last.checkpoint}, TerminalDigest: last.digest})
}

// verifyStoredReleaseTx deliberately rechecks historical receipt/manifest/all
// observations or exact failure code/finish. A certificate is not an attestation
// substitute. Current Finding/common-fact changes are not historical mutations.
func verifyStoredReleaseTx(ctx context.Context, tx *sql.Tx, record releaseCertificateRow, source reservationSource) error {
	c := record.ack.Certificate
	if source.Connector != c.Connector || source.Generation < c.Generation ||
		source.Generation == c.Generation && (source.OperationID != nil || source.IntentID != nil) {
		return releaseError(ctx, errReleaseCorrupt)
	}
	p, err := storedReleasePreparedTx(ctx, tx, c)
	if err != nil {
		return releaseError(ctx, errReleaseCorrupt)
	}
	expected, state, err := expectedReleaseTx(ctx, tx, p)
	if err != nil || state != "matched" || !releaseAckEqual(record.ack, expected) {
		return releaseError(ctx, errReleaseCorrupt)
	}
	return nil
}

func releaseAckEqual(a, b SecurityEnrichmentReleaseAcknowledgement) bool {
	left, err := enrichmentrelease.EncodeCertificate(a.Certificate)
	if err != nil {
		return false
	}
	right, err := enrichmentrelease.EncodeCertificate(b.Certificate)
	return err == nil && a.CertificateDigest == b.CertificateDigest && bytes.Equal(left, right)
}

func releaseStateTx(ctx context.Context, tx *sql.Tx, p preparedRelease) (SecurityEnrichmentReleaseProof, error) {
	unknown := SecurityEnrichmentReleaseProof{State: "unknown"}
	sources, err := readReservationSources(ctx, tx)
	if err != nil {
		return unknown, releaseError(ctx, errReleaseCorrupt)
	}
	if err := checkReservationSources(ctx, tx, sources); err != nil {
		return unknown, releaseError(ctx, errReleaseCorrupt)
	}
	r := p.reservation.request
	source := sources[r.Reserved.Checkpoint.Request.Connector]
	records, err := readReleaseCertificatesTx(ctx, tx, r.Reserved.Checkpoint.OperationID, r.IntentID, r.Reserved.Checkpoint.Request.Connector, p.reservation.generation)
	if err != nil {
		return unknown, err
	}
	expected, state, err := expectedReleaseTx(ctx, tx, p)
	if err != nil {
		return unknown, err
	}
	if state == "conflict" || len(records) > 1 {
		return SecurityEnrichmentReleaseProof{State: "conflict"}, nil
	}
	if len(records) == 1 {
		if state != "matched" {
			return unknown, releaseError(ctx, errReleaseCorrupt)
		}
		if !releaseAckEqual(records[0].ack, expected) {
			return SecurityEnrichmentReleaseProof{State: "conflict"}, nil
		}
		if err := verifyStoredReleaseTx(ctx, tx, records[0], source); err != nil {
			return unknown, err
		}
		return SecurityEnrichmentReleaseProof{State: "matched", Acknowledgement: expected}, nil
	}
	if state == "matched" {
		if !releaseActiveMatches(source, p.reservation) {
			return unknown, releaseError(ctx, errReleaseCorrupt)
		}
		return SecurityEnrichmentReleaseProof{State: "missing"}, nil
	}
	// Completely unused input is clean missing, not a new execution grant.
	// Indexed existence checks exclude old unbound receipt/journal evidence.
	if state == "missing" && source.Generation == 0 && source.OperationID == nil && source.IntentID == nil {
		legacy, err := unboundReservationSource(ctx, tx, r.Reserved.Checkpoint.Request.Connector)
		if err != nil {
			return unknown, releaseError(ctx, errReleaseStorage)
		}
		if !legacy {
			if p.inspection.Request.Terminal.Checkpoint.Prepared != nil {
				business, err := inspectOperationBusinessTx(ctx, tx, p.inspection.Request.Terminal.Checkpoint)
				if err != nil || business.State != "missing" {
					return unknown, releaseError(ctx, errReleaseCorrupt)
				}
			}
			return SecurityEnrichmentReleaseProof{State: "missing"}, nil
		}
	}
	return SecurityEnrichmentReleaseProof{State: "conflict"}, nil
}
