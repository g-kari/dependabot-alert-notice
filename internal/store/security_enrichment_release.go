package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrelease"
)

// SecurityEnrichmentReleaseAcknowledgement binds a committed release to its
// deterministic certificate and certificate JSON digest. This is storage and
// historical business proof, never authentication, fetch or restart ownership.
type SecurityEnrichmentReleaseAcknowledgement struct {
	Certificate       enrichmentrelease.Certificate
	CertificateDigest string
}

// SecurityEnrichmentReleaseProof classifies a same-retained-request read as
// matched, missing, conflict or unknown. Only matched exposes acknowledgement.
// Historical matching is not a current source fence or next-reservation grant.
type SecurityEnrichmentReleaseProof struct {
	State           string
	Acknowledgement SecurityEnrichmentReleaseAcknowledgement
}

var errReleaseConflict = errors.New("operation release conflict")
var errReleaseCorrupt = errors.New("operation release stored data invalid")
var errReleaseStorage = errors.New("operation release storage unavailable")

func releaseError(ctx context.Context, category error) error {
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("operation release: %w", ctx.Err())
	}
	return fmt.Errorf("operation release: %w", category)
}

// ReleaseSecurityEnrichmentOperation verifies the exact retained root, complete
// legal journal and historical business proof in its write transaction. Only a
// fresh active binding can INSERT a certificate and CAS-clear both active IDs.
// Generation is preserved. Errors, including Commit/cancellation, expose no Ack;
// callers retain their request and use only the read-only proof, never retry.
func (s *Store) ReleaseSecurityEnrichmentOperation(ctx context.Context, request enrichmentrelease.ReleaseRequest) (SecurityEnrichmentReleaseAcknowledgement, error) {
	empty := SecurityEnrichmentReleaseAcknowledgement{}
	p, err := prepareRelease(ctx, request)
	if err != nil {
		return empty, err
	}
	if s == nil || s.db == nil {
		return empty, releaseError(ctx, errReleaseStorage)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, releaseError(ctx, errReleaseStorage)
	}
	defer func() { _ = tx.Rollback() }()
	sources, err := readReservationSources(ctx, tx)
	if err != nil {
		return empty, releaseError(ctx, errReleaseCorrupt)
	}
	if err := checkReservationSources(ctx, tx, sources); err != nil {
		return empty, releaseError(ctx, errReleaseCorrupt)
	}
	source := sources[p.inspection.Request.Reservation.Reserved.Checkpoint.Request.Connector]
	if !releaseActiveMatches(source, p.reservation) {
		return empty, releaseError(ctx, errReleaseConflict)
	}
	ack, state, err := expectedReleaseTx(ctx, tx, p)
	if err != nil || state != "matched" {
		if err != nil {
			return empty, err
		}
		return empty, releaseError(ctx, errReleaseConflict)
	}
	stored, err := readReleaseCertificatesTx(ctx, tx, ack.Certificate.OperationID, ack.Certificate.IntentID, ack.Certificate.Connector, ack.Certificate.Generation)
	if err != nil {
		return empty, err
	}
	if len(stored) != 0 {
		return empty, releaseError(ctx, errReleaseCorrupt)
	}
	payload, err := enrichmentrelease.EncodeCertificate(ack.Certificate)
	if err != nil {
		return empty, releaseError(ctx, errReleaseCorrupt)
	}
	c := ack.Certificate
	inserted, err := tx.ExecContext(ctx, `INSERT INTO security_enrichment_release_certificates(
operation_id,intent_id,connector,generation,format_version,reserved_digest,terminal_sequence,
terminal_previous_digest,terminal_digest,kind,run_id,receipt,certificate_digest,certificate_json)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, c.OperationID, c.IntentID, c.Connector, c.Generation, c.Version, c.ReservedDigest, c.TerminalSequence,
		c.TerminalPreviousDigest, c.TerminalDigest, c.Kind, c.RunID, c.Receipt, ack.CertificateDigest, string(payload))
	if err != nil {
		return empty, releaseError(ctx, errReleaseStorage)
	}
	count, err := inserted.RowsAffected()
	if err != nil || count != 1 {
		return empty, releaseError(ctx, errReleaseStorage)
	}
	result, err := tx.ExecContext(ctx, `UPDATE security_enrichment_source_generations
SET active_operation_id=NULL,active_intent_id=NULL
WHERE connector=? AND generation=? AND active_operation_id=? AND active_intent_id=?`,
		c.Connector, c.Generation, c.OperationID, c.IntentID)
	if err != nil {
		return empty, releaseError(ctx, errReleaseStorage)
	}
	count, err = result.RowsAffected()
	if err != nil || count != 1 {
		return empty, releaseError(ctx, errReleaseConflict)
	}
	// Verify the exact post-write pair inside this same transaction before
	// exposing an Ack. Trigger suppression or mutation cannot mimic a commit.
	proved, err := releaseStateTx(ctx, tx, p)
	if err != nil || proved.State != "matched" || !releaseAckEqual(proved.Acknowledgement, ack) {
		return empty, releaseError(ctx, errReleaseCorrupt)
	}
	if err := tx.Commit(); err != nil {
		return empty, releaseError(ctx, errReleaseStorage)
	}
	if ctx.Err() != nil {
		return empty, releaseError(ctx, errReleaseStorage)
	}
	return ack, nil
}

// ReadSecurityEnrichmentRelease re-proves the complete retained request and
// historical business evidence in one read-only snapshot. Matched is historical
// release storage only, never current execution ownership or next admission.
// Missing is clean only for unused input or a fully proved still-active terminal.
func (s *Store) ReadSecurityEnrichmentRelease(ctx context.Context, request enrichmentrelease.ReleaseRequest) (SecurityEnrichmentReleaseProof, error) {
	unknown := SecurityEnrichmentReleaseProof{State: "unknown"}
	p, err := prepareRelease(ctx, request)
	if err != nil {
		return unknown, err
	}
	if s == nil || s.db == nil {
		return unknown, releaseError(ctx, errReleaseStorage)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return unknown, releaseError(ctx, errReleaseStorage)
	}
	defer func() { _ = tx.Rollback() }()
	proof, err := releaseStateTx(ctx, tx, p)
	if err != nil {
		return unknown, err
	}
	if err := tx.Commit(); err != nil {
		return unknown, releaseError(ctx, errReleaseStorage)
	}
	if ctx.Err() != nil {
		return unknown, releaseError(ctx, errReleaseStorage)
	}
	return proof, nil
}
