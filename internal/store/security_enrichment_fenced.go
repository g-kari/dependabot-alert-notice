package store

import (
	"context"
	"errors"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
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

var errFencedEnrichmentUnavailable = errors.New("fenced enrichment unavailable")

// AppendSecurityEnrichmentFencedCheckpoint will append an exact post-reserved
// checkpoint only while its retained reservation/generation and current head
// match inside the write transaction. It does not apply a business write.
func (s *Store) AppendSecurityEnrichmentFencedCheckpoint(ctx context.Context, request SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedAcknowledgement, error) {
	return SecurityEnrichmentFencedAcknowledgement{}, errFencedEnrichmentUnavailable
}

// ApplySecurityEnrichmentFencedRefresh will apply Begin/Fail/Complete derived
// solely from the already stored exact current checkpoint in the same writeTx
// as the fence check. Errors return zero Ack, never retry or repair.
func (s *Store) ApplySecurityEnrichmentFencedRefresh(ctx context.Context, request SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedProof, error) {
	return SecurityEnrichmentFencedProof{State: "unknown", Business: SecurityEnrichmentRefreshState{State: "unknown"}}, errFencedEnrichmentUnavailable
}

// ReadSecurityEnrichmentFencedCheckpoint will prove only checkpoint/fence
// storage in a read-only snapshot, without business success or execution rights.
func (s *Store) ReadSecurityEnrichmentFencedCheckpoint(ctx context.Context, expected SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedProof, error) {
	return SecurityEnrichmentFencedProof{State: "unknown", Business: SecurityEnrichmentRefreshState{State: "unknown"}}, errFencedEnrichmentUnavailable
}

// ReadSecurityEnrichmentFencedRefresh will check exact retained business proof
// plus the current checkpoint/fence in one read-only snapshot. Missing/running/
// unknown outcomes never cause writes, new UUIDs/clocks or ownership transfer.
func (s *Store) ReadSecurityEnrichmentFencedRefresh(ctx context.Context, expected SecurityEnrichmentFencedRequest) (SecurityEnrichmentFencedProof, error) {
	return SecurityEnrichmentFencedProof{State: "unknown", Business: SecurityEnrichmentRefreshState{State: "unknown"}}, errFencedEnrichmentUnavailable
}
