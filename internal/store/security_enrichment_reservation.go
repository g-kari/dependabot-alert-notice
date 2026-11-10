package store

import (
	"context"
	"errors"

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

var errOperationReservationUnavailable = errors.New("operation reservation unavailable")

// ReserveSecurityEnrichmentOperation will atomically bind the caller-retained
// intent/request, one source generation and journal reserved checkpoint. This
// unconnected experimental storage API does not create a business UUID/clock,
// fence business writes, release a source, restore a controller or enable live work.
func (s *Store) ReserveSecurityEnrichmentOperation(ctx context.Context, request SecurityEnrichmentReservationRequest) (SecurityEnrichmentReservationAcknowledgement, error) {
	return SecurityEnrichmentReservationAcknowledgement{}, errOperationReservationUnavailable
}

// ReadSecurityEnrichmentReservation will check only this complete retained
// request in a read-only snapshot. Missing/conflict/unknown never grant rights;
// matching a DB record is not restart or different-caller execution ownership.
func (s *Store) ReadSecurityEnrichmentReservation(ctx context.Context, expected SecurityEnrichmentReservationRequest) (SecurityEnrichmentReservationState, error) {
	return SecurityEnrichmentReservationState{State: "unknown"}, errOperationReservationUnavailable
}
