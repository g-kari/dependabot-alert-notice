package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

// SecurityEnrichmentReservationRequest is retained once before a reservation
// write. IntentID is a non-authentication correlation ID, not a credential or
// fetch grant. Reserved must be the full sequence-one reserved checkpoint with
// empty previous digest. ReservedDigest binds its exact canonical payload.
// ExpectedGeneration is the idle source generation; the proposed next is +1.
type SecurityEnrichmentReservationRequest struct {
	IntentID           string
	ExpectedGeneration int64
	ReservedDigest     string
	Reserved           enrichmentjournal.AppendRequest
}

// SecurityEnrichmentReservationAcknowledgement confirms atomic reservation
// storage only. Journal.Replay distinguishes an exact stored-request replay.
// Neither fresh nor replayed storage proof restores execution/fetch ownership,
// establishes business success, or enforces existing business-write APIs.
type SecurityEnrichmentReservationAcknowledgement struct {
	IntentID   string
	Connector  string
	Generation int64
	Journal    enrichmentjournal.Acknowledgement
}

// SecurityEnrichmentReservationState classifies exact read-only matching as
// matched, missing, conflict or unknown. Only matched exposes acknowledgement
// and the verified current reserved head; no repair, retry or adoption occurs.
type SecurityEnrichmentReservationState struct {
	State           string
	Acknowledgement SecurityEnrichmentReservationAcknowledgement
	HeadSequence    int64
	HeadDigest      string
}

const reservationMaxGeneration = int64(1<<63 - 1)

var errReservationConflict = errors.New("operation reservation conflict")
var errReservationCorrupt = errors.New("operation reservation stored data invalid")
var errReservationStorage = errors.New("operation reservation storage unavailable")

type preparedReservation struct {
	request    SecurityEnrichmentReservationRequest
	payload    []byte
	generation int64
}

func reservationError(ctx context.Context, category error) error {
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("operation reservation: %w", ctx.Err())
	}
	return fmt.Errorf("operation reservation: %w", category)
}

func reservationUUID(id string) bool {
	return securityUUID(id) && strings.Count(id, "-") == 4
}

func prepareReservation(ctx context.Context, request SecurityEnrichmentReservationRequest) (preparedReservation, error) {
	if ctx == nil || !reservationUUID(request.IntentID) || request.ExpectedGeneration < 0 || request.ExpectedGeneration >= reservationMaxGeneration || request.Reserved.Sequence != 1 || request.Reserved.PreviousDigest != "" || request.Reserved.Checkpoint.Stage != enrichmentjournal.Reserved || !journalValidDigest(request.ReservedDigest) {
		return preparedReservation{}, reservationError(ctx, errReservationConflict)
	}
	if ctx.Err() != nil {
		return preparedReservation{}, reservationError(ctx, errReservationStorage)
	}
	payload, err := enrichmentjournal.Encode(request.Reserved.Checkpoint)
	if err != nil || enrichmentjournal.ValidateTransition(nil, request.Reserved.Checkpoint) != nil || journalDigest(payload) != request.ReservedDigest {
		return preparedReservation{}, reservationError(ctx, errReservationConflict)
	}
	owned, err := enrichmentjournal.Decode(payload)
	if err != nil {
		return preparedReservation{}, reservationError(ctx, errReservationConflict)
	}
	request.Reserved.Checkpoint = owned
	return preparedReservation{request: request, payload: payload, generation: request.ExpectedGeneration + 1}, nil
}

func reservationAck(p preparedReservation, replay bool) SecurityEnrichmentReservationAcknowledgement {
	return SecurityEnrichmentReservationAcknowledgement{
		IntentID: p.request.IntentID, Connector: p.request.Reserved.Checkpoint.Request.Connector, Generation: p.generation,
		Journal: enrichmentjournal.Acknowledgement{OperationID: p.request.Reserved.Checkpoint.OperationID, Sequence: 1, Digest: p.request.ReservedDigest, Replay: replay},
	}
}

// ReserveSecurityEnrichmentOperation atomically stores a caller-retained intent,
// idle-generation CAS and journal reserved checkpoint. Exact replay is storage
// proof only. Errors expose zero acknowledgement, including uncertain commit.
// This unconnected API does not fence business writes, release or restore an
// operation, grant execution ownership, or generate a business UUID/clock.
func (s *Store) ReserveSecurityEnrichmentOperation(ctx context.Context, request SecurityEnrichmentReservationRequest) (SecurityEnrichmentReservationAcknowledgement, error) {
	empty := SecurityEnrichmentReservationAcknowledgement{}
	p, err := prepareReservation(ctx, request)
	if err != nil {
		return empty, err
	}
	if s == nil || s.db == nil {
		return empty, reservationError(ctx, errReservationStorage)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, reservationError(ctx, errReservationStorage)
	}
	defer func() { _ = tx.Rollback() }()
	sources, err := readReservationSources(ctx, tx)
	if err != nil {
		return empty, err
	}
	if err := checkReservationSources(ctx, tx, sources); err != nil {
		return empty, err
	}
	state, err := reservationStateTx(ctx, tx, p, sources)
	if err != nil {
		return empty, err
	}
	if state.State == "matched" {
		if err := tx.Commit(); err != nil {
			return empty, reservationError(ctx, errReservationStorage)
		}
		if ctx.Err() != nil {
			return empty, reservationError(ctx, errReservationStorage)
		}
		return state.Acknowledgement, nil
	}
	if state.State != "missing" {
		return empty, reservationError(ctx, errReservationConflict)
	}
	connector := p.request.Reserved.Checkpoint.Request.Connector
	if len(sources) == 0 {
		// Admission and both initially idle source rows are part of this
		// reservation transaction, never side effects of a read or migration.
		if err := initialReservationAdmission(ctx, tx); err != nil {
			return empty, err
		}
		for _, source := range []string{"epss_feed", "kev_feed"} {
			if _, err := tx.ExecContext(ctx, "INSERT INTO security_enrichment_source_generations(connector,generation,active_operation_id,active_intent_id) VALUES(?,0,NULL,NULL)", source); err != nil {
				return empty, reservationError(ctx, errReservationStorage)
			}
		}
	}
	if err := insertJournalOperationTx(ctx, tx, p.request.Reserved, p.request.ReservedDigest); err != nil {
		return empty, reservationError(ctx, errReservationStorage)
	}
	if err := insertJournalCheckpointTx(ctx, tx, p.request.Reserved, p.payload, p.request.ReservedDigest); err != nil {
		return empty, reservationError(ctx, errReservationStorage)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_enrichment_reservations(operation_id,intent_id,connector,expected_generation,generation,reserved_digest,reserved_payload_json) VALUES(?,?,?,?,?,?,?)`,
		p.request.Reserved.Checkpoint.OperationID, p.request.IntentID, connector, p.request.ExpectedGeneration, p.generation, p.request.ReservedDigest, string(p.payload)); err != nil {
		return empty, reservationError(ctx, errReservationStorage)
	}
	result, err := tx.ExecContext(ctx, `UPDATE security_enrichment_source_generations SET generation=?,active_operation_id=?,active_intent_id=? WHERE connector=? AND generation=? AND active_operation_id IS NULL AND active_intent_id IS NULL`,
		p.generation, p.request.Reserved.Checkpoint.OperationID, p.request.IntentID, connector, p.request.ExpectedGeneration)
	if err != nil {
		return empty, reservationError(ctx, errReservationStorage)
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return empty, reservationError(ctx, errReservationConflict)
	}
	if err := tx.Commit(); err != nil {
		return empty, reservationError(ctx, errReservationStorage)
	}
	if ctx.Err() != nil {
		return empty, reservationError(ctx, errReservationStorage)
	}
	return reservationAck(p, false), nil
}

// ReadSecurityEnrichmentReservation checks the complete retained request in one
// read-only snapshot. Only an exact active binding with a still-reserved head
// matches. It never initializes storage, retries Reserve, repairs, releases,
// adopts old work or grants restart/different-caller execution ownership.
func (s *Store) ReadSecurityEnrichmentReservation(ctx context.Context, expected SecurityEnrichmentReservationRequest) (SecurityEnrichmentReservationState, error) {
	unknown := SecurityEnrichmentReservationState{State: "unknown"}
	p, err := prepareReservation(ctx, expected)
	if err != nil {
		return unknown, err
	}
	if s == nil || s.db == nil {
		return unknown, reservationError(ctx, errReservationStorage)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return unknown, reservationError(ctx, errReservationStorage)
	}
	defer func() { _ = tx.Rollback() }()
	sources, err := readReservationSources(ctx, tx)
	if err != nil {
		return unknown, err
	}
	if err := checkReservationSources(ctx, tx, sources); err != nil {
		return unknown, err
	}
	state, err := reservationStateTx(ctx, tx, p, sources)
	if err != nil {
		return unknown, err
	}
	if err := tx.Commit(); err != nil {
		return unknown, reservationError(ctx, errReservationStorage)
	}
	if ctx.Err() != nil {
		return unknown, reservationError(ctx, errReservationStorage)
	}
	return state, nil
}

func reservationStateTx(ctx context.Context, tx *sql.Tx, p preparedReservation, sources map[string]reservationSource) (SecurityEnrichmentReservationState, error) {
	unknown := SecurityEnrichmentReservationState{State: "unknown"}
	conflict := SecurityEnrichmentReservationState{State: "conflict"}
	records, err := readReservationBindings(ctx, tx, p.request.Reserved.Checkpoint.OperationID, p.request.IntentID)
	if err != nil {
		return unknown, err
	}
	header, exists, rows, err := reservationJournalTx(ctx, tx, p.request.Reserved.Checkpoint.OperationID)
	if err != nil {
		return unknown, err
	}
	source := sources[p.request.Reserved.Checkpoint.Request.Connector]
	if len(records) > 0 {
		if len(records) != 1 {
			return conflict, nil
		}
		record := records[0]
		if record.OperationID != p.request.Reserved.Checkpoint.OperationID || record.IntentID != p.request.IntentID || record.Connector != p.request.Reserved.Checkpoint.Request.Connector || record.ExpectedGeneration != p.request.ExpectedGeneration || record.Generation != p.generation || record.Digest != p.request.ReservedDigest || !bytes.Equal(record.payload, p.payload) {
			return conflict, nil
		}
		if !exists {
			return unknown, reservationError(ctx, errReservationCorrupt)
		}
		if source.Generation != p.generation || source.OperationID == nil || *source.OperationID != record.OperationID || source.IntentID == nil || *source.IntentID != record.IntentID {
			closed, err := certifiedReservationClosureTx(ctx, tx, p, source)
			if err != nil {
				return unknown, reservationError(ctx, errReservationCorrupt)
			}
			if closed {
				return conflict, nil
			}
			return unknown, reservationError(ctx, errReservationCorrupt)
		}
		if header.Sequence != 1 || header.Digest != record.Digest || len(rows) != 1 || !bytes.Equal(rows[0].payload, record.payload) {
			return conflict, nil
		}
		return SecurityEnrichmentReservationState{State: "matched", Acknowledgement: reservationAck(p, true), HeadSequence: header.Sequence, HeadDigest: header.Digest}, nil
	}
	// Certified idle is readable, but next-generation admission is a separate
	// bounded-history slice. Reads must not classify this as clean missing.
	if source.Generation > 0 && source.OperationID == nil {
		return conflict, nil
	}
	if exists || source.OperationID != nil || source.Generation != p.request.ExpectedGeneration {
		return conflict, nil
	}
	if legacy, err := unboundReservationSource(ctx, tx, p.request.Reserved.Checkpoint.Request.Connector); err != nil {
		return unknown, err
	} else if legacy {
		return conflict, nil
	}
	return SecurityEnrichmentReservationState{State: "missing"}, nil
}
