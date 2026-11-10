package enrichmentrefresh

import (
	"context"
	"errors"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// JournalRepository is the explicit checkpoint append and read-only matching
// boundary. Its acknowledgements never confer business/fetch ownership.
type JournalRepository interface {
	AppendSecurityEnrichmentCheckpoint(context.Context, enrichmentjournal.AppendRequest) (enrichmentjournal.Acknowledgement, error)
	ReadSecurityEnrichmentCheckpointAcknowledgement(context.Context, enrichmentjournal.AppendRequest) (store.SecurityEnrichmentJournalAcknowledgementState, error)
}

var errJournalAdapterUnavailable = errors.New("journal adapter unavailable")

// NewJournalManualController binds one private adapter to one controller lifetime.
// It requires explicit Service and journal dependencies, creates no defaults,
// and does not return a reusable Sink. Existing constructors remain unchanged.
// Repeated reserved callbacks, fresh journal replay and uncertain reservations
// must not authorize another Service execution or restoration.
func NewJournalManualController(service Service, journal JournalRepository) (*ManualController, error) {
	return nil, errJournalAdapterUnavailable
}

// convertJournalCheckpoint checks duplicated source values before aggregation.
// It must not hide unequal Completion.Attempt or Result.Pending values through
// canonicalization, nil/empty changes or dropping a duplicate representation.
func convertJournalCheckpoint(checkpoint PreservationCheckpoint) (enrichmentjournal.Checkpoint, error) {
	return enrichmentjournal.Checkpoint{}, errJournalAdapterUnavailable
}
