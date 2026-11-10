package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// SecurityEnrichmentFencedRequest retains one reservation and full current
// checkpoint/digest before I/O. Prepared Attempt/Failure/Completion come only
// from Checkpoint, never a second independent input. This is not authentication,
// executable ownership or permission to adopt an old/restarted operation.
type SecurityEnrichmentFencedRequest struct {
	Reservation      SecurityEnrichmentReservationRequest
	Checkpoint       enrichmentjournal.AppendRequest
	CheckpointDigest string
}

// SecurityEnrichmentFencedAcknowledgement binds one exact action to the retained
// operation/intent/source/generation/checkpoint. Replay describes this API action
// (or a read), not fresh fetch ownership. It contains no business success claim.
type SecurityEnrichmentFencedAcknowledgement struct {
	OperationID string
	IntentID    string
	Connector   string
	Generation  int64
	Sequence    int64
	Digest      string
	Replay      bool
}

// SecurityEnrichmentFencedProof separates exact checkpoint/fence acknowledgement
// from business evidence. Only matched exposes Ack/head. A checkpoint-only read
// leaves Business unknown. A refresh proof matches only the exact retained
// running attempt, expected failure or full successful completion; unresolved
// business state exposes no Ack/head. No result grants execution/restoration.
type SecurityEnrichmentFencedProof struct {
	State           string
	Acknowledgement SecurityEnrichmentFencedAcknowledgement
	Business        SecurityEnrichmentRefreshState
	HeadSequence    int64
	HeadDigest      string
}

var errFencedConflict = errors.New("fenced enrichment conflict")
var errFencedCorrupt = errors.New("fenced enrichment stored data invalid")
var errFencedStorage = errors.New("fenced enrichment storage unavailable")

type preparedFencedRequest struct {
	reservation preparedReservation
	checkpoint  enrichmentjournal.AppendRequest
	payload     []byte
	digest      string
}

func fencedUnknown() SecurityEnrichmentFencedProof {
	return SecurityEnrichmentFencedProof{State: "unknown", Business: SecurityEnrichmentRefreshState{State: "unknown"}}
}

func fencedError(ctx context.Context, category error) error {
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("fenced enrichment: %w", ctx.Err())
	}
	return fmt.Errorf("fenced enrichment: %w", category)
}

func prepareFencedRequest(ctx context.Context, request SecurityEnrichmentFencedRequest) (preparedFencedRequest, error) {
	reservation, err := prepareReservation(ctx, request.Reservation)
	if err != nil {
		return preparedFencedRequest{}, fencedError(ctx, errFencedConflict)
	}
	if request.Checkpoint.Sequence < 2 || request.Checkpoint.Sequence > journalMaxCheckpoints || !journalValidDigest(request.Checkpoint.PreviousDigest) || !journalValidDigest(request.CheckpointDigest) || request.Checkpoint.Checkpoint.Stage == enrichmentjournal.Reserved {
		return preparedFencedRequest{}, fencedError(ctx, errFencedConflict)
	}
	payload, err := enrichmentjournal.Encode(request.Checkpoint.Checkpoint)
	if err != nil || journalDigest(payload) != request.CheckpointDigest {
		return preparedFencedRequest{}, fencedError(ctx, errFencedConflict)
	}
	checkpoint, err := enrichmentjournal.Decode(payload)
	if err != nil || checkpoint.OperationID != reservation.request.Reserved.Checkpoint.OperationID || checkpoint.Version != reservation.request.Reserved.Checkpoint.Version || checkpoint.Request != reservation.request.Reserved.Checkpoint.Request {
		return preparedFencedRequest{}, fencedError(ctx, errFencedConflict)
	}
	request.Checkpoint.Checkpoint = checkpoint
	return preparedFencedRequest{reservation: reservation, checkpoint: request.Checkpoint, payload: payload, digest: request.CheckpointDigest}, nil
}

func fencedAck(p preparedFencedRequest, replay bool) SecurityEnrichmentFencedAcknowledgement {
	return SecurityEnrichmentFencedAcknowledgement{OperationID: p.checkpoint.Checkpoint.OperationID,
		IntentID: p.reservation.request.IntentID, Connector: p.checkpoint.Checkpoint.Request.Connector,
		Generation: p.reservation.generation, Sequence: p.checkpoint.Sequence, Digest: p.digest, Replay: replay}
}

// AppendSecurityEnrichmentFencedCheckpoint appends only an exact current replay
// or legal next checkpoint while the full retained reservation/generation agrees
// in its writeTx. Old phases are refused even if stored historically. No business
// write, execution grant, release, retry or repair is performed.
func (s *Store) AppendSecurityEnrichmentFencedCheckpoint(ctx context.Context, request SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedAcknowledgement, error) {
	empty := SecurityEnrichmentFencedAcknowledgement{}
	p, err := prepareFencedRequest(ctx, request)
	if err != nil {
		return empty, err
	}
	if s == nil || s.db == nil {
		return empty, fencedError(ctx, errFencedStorage)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, fencedError(ctx, errFencedStorage)
	}
	defer func() { _ = tx.Rollback() }()
	snapshot, state, err := readFencedReservationTx(ctx, tx, p)
	if err != nil {
		return empty, err
	}
	if state != "matched" || (p.checkpoint.Sequence != snapshot.header.Sequence && p.checkpoint.Sequence != snapshot.header.Sequence+1) {
		return empty, fencedError(ctx, errFencedConflict)
	}
	ack, err := appendJournalCheckpointTx(ctx, tx, p.checkpoint, p.payload, p.digest)
	if err != nil {
		return empty, fencedError(ctx, errFencedConflict)
	}
	proof, err := fencedCheckpointProofTx(ctx, tx, p)
	if err != nil {
		return empty, err
	}
	if proof.State != "matched" {
		return empty, fencedError(ctx, errFencedCorrupt)
	}
	if err := tx.Commit(); err != nil {
		return empty, fencedError(ctx, errFencedStorage)
	}
	if ctx.Err() != nil {
		return empty, fencedError(ctx, errFencedStorage)
	}
	return fencedAck(p, ack.Replay), nil
}

type preparedFencedBusiness struct {
	attempt    SecurityEnrichmentRefreshAttempt
	running    model.IngestRun
	failed     model.IngestRun
	completion SecurityEnrichmentRefreshCompletion
	success    model.IngestRun
}

func prepareFencedBusiness(p preparedFencedRequest) (preparedFencedBusiness, error) {
	var out preparedFencedBusiness
	if p.checkpoint.Checkpoint.Prepared == nil {
		return out, errFencedConflict
	}
	attempt, failure, completion := operationInspectionPrepared(*p.checkpoint.Checkpoint.Prepared)
	var err error
	switch p.checkpoint.Checkpoint.Stage {
	case enrichmentjournal.Begin:
		out.attempt, out.running, _, err = normalizeRefreshAttempt(attempt)
	case enrichmentjournal.Fail:
		out.attempt, out.running, _, err = normalizeRefreshAttempt(attempt)
		if err == nil {
			if failure == nil || !refreshFailureCode(failure.Code) || !securityTime(failure.FinishedAt) || !securityTime(failure.FinishedAt.UTC()) || failure.FinishedAt.Before(out.running.StartedAt) {
				return out, errFencedConflict
			}
			finish := failure.FinishedAt.UTC()
			out.failed = out.running
			out.failed.Result, out.failed.Error, out.failed.FinishedAt = model.IngestResultFailed, failure.Code, &finish
		}
	case enrichmentjournal.Complete:
		if completion == nil {
			return out, errFencedConflict
		}
		out.completion, out.running, out.success, err = normalizeRefreshCompletion(*completion)
	default:
		return out, errFencedConflict
	}
	return out, err
}

// ApplySecurityEnrichmentFencedRefresh derives Begin/Fail/Complete only from the
// owned full current checkpoint. Fence checking, the business write and exact
// post-write proof share one transaction. Legacy business replay remains
// rollback-only. Errors expose zero Ack and never start another write/UUID/clock.
func (s *Store) ApplySecurityEnrichmentFencedRefresh(ctx context.Context, request SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedProof, error) {
	unknown := fencedUnknown()
	p, err := prepareFencedRequest(ctx, request)
	if err != nil {
		return unknown, err
	}
	business, err := prepareFencedBusiness(p)
	if err != nil {
		return unknown, fencedError(ctx, errFencedConflict)
	}
	if s == nil || s.db == nil {
		return unknown, fencedError(ctx, errFencedStorage)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return unknown, fencedError(ctx, errFencedStorage)
	}
	defer func() { _ = tx.Rollback() }()
	proof, err := fencedCheckpointProofTx(ctx, tx, p)
	if err != nil {
		return unknown, err
	}
	if proof.State != "matched" {
		return unknown, fencedError(ctx, errFencedConflict)
	}
	// Share the strict bounded existing receipt/evidence guards before the
	// legacy write helper can materialize any corrupt stored scalar.
	if _, err := inspectOperationBusinessTx(ctx, tx, p.checkpoint.Checkpoint); err != nil {
		return unknown, fencedError(ctx, errFencedCorrupt)
	}
	var replay bool
	switch p.checkpoint.Checkpoint.Stage {
	case enrichmentjournal.Begin:
		replay, err = beginSecurityEnrichmentRefreshTx(ctx, tx, business.attempt, business.running)
	case enrichmentjournal.Fail:
		replay, err = failSecurityEnrichmentRefreshTx(ctx, tx, business.running, business.failed)
	case enrichmentjournal.Complete:
		var result SecurityEnrichmentImportResult
		result, err = completeSecurityEnrichmentRefreshTx(ctx, tx, business.completion, business.running, business.success)
		replay = result.Replay
	}
	if err != nil {
		return unknown, fencedError(ctx, errFencedStorage)
	}
	// Recheck the current fence/head and actual business proof in this same
	// transaction. A prepared CP or expected receipt is not a commit proof.
	proof, err = fencedBusinessProofTx(ctx, tx, p)
	if err != nil {
		return unknown, err
	}
	if proof.State != "matched" {
		return unknown, fencedError(ctx, errFencedCorrupt)
	}
	if !replay {
		if err := tx.Commit(); err != nil {
			return unknown, fencedError(ctx, errFencedStorage)
		}
	}
	if ctx.Err() != nil {
		return unknown, fencedError(ctx, errFencedStorage)
	}
	proof.Acknowledgement.Replay = replay
	return proof, nil
}

// ReadSecurityEnrichmentFencedCheckpoint proves only exact current CP/fence
// storage in one read-only snapshot. Business remains unknown; storage is not
// business completion, fresh fetch ownership or permission to adopt old work.
func (s *Store) ReadSecurityEnrichmentFencedCheckpoint(ctx context.Context, expected SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedProof, error) {
	return s.readFencedEnrichment(ctx, expected, false)
}

// ReadSecurityEnrichmentFencedRefresh matches only exact current CP/fence and the
// retained running attempt, expected failure or full successful completion.
// Missing/running/unknown where a different phase is expected exposes no Ack/head.
// This read never writes, retries, releases, restores or grants ownership.
func (s *Store) ReadSecurityEnrichmentFencedRefresh(ctx context.Context, expected SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedProof, error) {
	return s.readFencedEnrichment(ctx, expected, true)
}

func (s *Store) readFencedEnrichment(ctx context.Context, expected SecurityEnrichmentFencedRequest, business bool) (SecurityEnrichmentFencedProof, error) {
	unknown := fencedUnknown()
	p, err := prepareFencedRequest(ctx, expected)
	if err != nil {
		return unknown, err
	}
	if s == nil || s.db == nil {
		return unknown, fencedError(ctx, errFencedStorage)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return unknown, fencedError(ctx, errFencedStorage)
	}
	defer func() { _ = tx.Rollback() }()
	var proof SecurityEnrichmentFencedProof
	if business {
		proof, err = fencedBusinessProofTx(ctx, tx, p)
	} else {
		proof, err = fencedCheckpointProofTx(ctx, tx, p)
	}
	if err != nil {
		return unknown, err
	}
	if err := tx.Commit(); err != nil {
		return unknown, fencedError(ctx, errFencedStorage)
	}
	if ctx.Err() != nil {
		return unknown, fencedError(ctx, errFencedStorage)
	}
	return proof, nil
}
