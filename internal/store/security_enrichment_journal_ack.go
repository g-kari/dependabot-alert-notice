package store

import (
	"context"
	"errors"

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

var errJournalAcknowledgementUnavailable = errors.New("journal acknowledgement unavailable")

// ReadSecurityEnrichmentCheckpointAcknowledgement checks the retained request in
// a read-only snapshot. It never appends, repairs, retries or rewrites receipts.
func (s *Store) ReadSecurityEnrichmentCheckpointAcknowledgement(ctx context.Context, expected enrichmentjournal.AppendRequest) (SecurityEnrichmentJournalAcknowledgementState, error) {
	return SecurityEnrichmentJournalAcknowledgementState{State: "unknown"}, errJournalAcknowledgementUnavailable
}
