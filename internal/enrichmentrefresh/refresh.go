// Package enrichmentrefresh coordinates one unconnected synthetic enrichment
// refresh page. It has no application wiring, live fetcher or background worker.
package enrichmentrefresh

import (
	"context"
	"fmt"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// Repository is the caller-owned store boundary used by one refresh operation.
type Repository interface {
	QuerySecurityEnrichmentRefreshTargets(context.Context, string, int) (store.SecurityEnrichmentRefreshTargetPage, error)
	BeginSecurityEnrichmentRefresh(context.Context, store.SecurityEnrichmentRefreshAttempt) (bool, error)
	CompleteSecurityEnrichmentRefresh(context.Context, store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentImportResult, error)
	FailSecurityEnrichmentRefresh(context.Context, store.SecurityEnrichmentRefreshAttempt, string, time.Time) (bool, error)
	ReadSecurityEnrichmentRefreshAttempt(context.Context, store.SecurityEnrichmentRefreshAttempt, *store.SecurityEnrichmentRefreshFailure) (store.SecurityEnrichmentRefreshState, error)
	ReconcileSecurityEnrichmentRefresh(context.Context, store.SecurityEnrichmentRefreshCompletion) (store.SecurityEnrichmentRefreshState, error)
}

// Fetcher supplies owned, complete, uncompressed synthetic strict-offline-envelope
// bytes for epss or kev. No real wire/HTTP/compression adapter is supplied here.
type Fetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

// Service requires explicitly injected storage, clock, UUID and fixture fetcher.
type Service struct {
	Store   Repository
	Clock   func() time.Time
	NewUUID func() (string, error)
	Fetcher Fetcher
}

// Request selects one connector and at most 200 scan rows by exact ID keyset.
type Request struct {
	Connector string
	After     string
	Limit     int
}

// Pending is an in-process envelope prepared before each Begin/Fail/Complete
// write. It retains the same UUID and exact expected write for returned-error
// readback only. It is neither durable restart retention nor an ownership grant
// or permission to refetch an existing reservation.
type Pending struct {
	Attempt         store.SecurityEnrichmentRefreshAttempt
	ExpectedFailure *store.SecurityEnrichmentRefreshFailure
	Completion      *store.SecurityEnrichmentRefreshCompletion
}

// Result separates scan progress from permission to advance the input cursor.
// Pending outcomes never claim success or authorize a replacement UUID.
type Result struct {
	Outcome   string
	Code      string
	RunID     string
	Scanned   int
	Targets   int
	ScanAfter string
	NextAfter string
	Advance   bool
	Exhausted bool
	Pending   *Pending
}

// RefreshOnce coordinates only one source/page without holding a SQL transaction
// across fetch/parse. A replay or uncertain Begin must never establish ownership.
// The store caller retains its attempt/completion in memory before each write;
// process crashes, unreturned calls and restart recovery are outside this slice.
func (s Service) RefreshOnce(ctx context.Context, request Request) (Result, error) {
	return Result{}, fmt.Errorf("refresh orchestration unavailable")
}
