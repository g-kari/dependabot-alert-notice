package store

import (
	"context"
	"errors"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

// SecurityEnrichmentOperationInspection separates validated journal state from
// historical business proof. State is valid, missing or unknown. Only valid
// returns a head/checkpoint candidate. Business is never inferred from journal
// outcome/ack alone. Unprepared/no_run have no bound business UUID or receipt.
// It is not a run-ready controller, ownership grant, liveness or current facts.
type SecurityEnrichmentOperationInspection struct {
	State        string
	OperationID  string
	HeadSequence int64
	HeadDigest   string
	Checkpoint   *enrichmentjournal.Checkpoint
	Business     SecurityEnrichmentRefreshState
}

var errOperationInspectionUnavailable = errors.New("operation inspection unavailable")

// InspectSecurityEnrichmentOperation reads one canonical operation and verifies
// bounded journal history and any available exact business proof in one
// read-only snapshot. It creates no clock, UUID, metadata, write or restoration.
// A valid journal candidate may accompany Business=unknown plus a proof error.
func (s *Store) InspectSecurityEnrichmentOperation(ctx context.Context, operationID string) (SecurityEnrichmentOperationInspection, error) {
	return SecurityEnrichmentOperationInspection{State: "unknown", Business: SecurityEnrichmentRefreshState{State: "unknown"}}, errOperationInspectionUnavailable
}
