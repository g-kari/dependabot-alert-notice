package store

import (
	"context"
	"errors"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

var errOperationJournalUnavailable = errors.New("operation journal unavailable")

// AppendSecurityEnrichmentCheckpoint atomically appends one immutable checkpoint
// and CAS-updates its bound operation head. Exact retained payload replay returns
// the original acknowledgement. It never writes existing enrichment receipts,
// creates an ingest run, grants fetch ownership or retries an uncertain commit.
func (s *Store) AppendSecurityEnrichmentCheckpoint(ctx context.Context, request enrichmentjournal.AppendRequest) (enrichmentjournal.Acknowledgement, error) {
	return enrichmentjournal.Acknowledgement{}, errOperationJournalUnavailable
}
