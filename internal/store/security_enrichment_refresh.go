package store

import (
	"context"
	"fmt"
	"time"
)

// BeginSecurityEnrichmentRefresh reserves the same UUID before future I/O.
func (s *Store) BeginSecurityEnrichmentRefresh(ctx context.Context, attempt SecurityEnrichmentRefreshAttempt) (bool, error) {
	return false, fmt.Errorf("refresh lifecycle unavailable")
}

// CompleteSecurityEnrichmentRefresh atomically commits manifest, evidence and receipt.
func (s *Store) CompleteSecurityEnrichmentRefresh(ctx context.Context, completion SecurityEnrichmentRefreshCompletion) (SecurityEnrichmentImportResult, error) {
	return SecurityEnrichmentImportResult{}, fmt.Errorf("refresh lifecycle unavailable")
}

// FailSecurityEnrichmentRefresh records a fixed failure code without deleting evidence.
func (s *Store) FailSecurityEnrichmentRefresh(ctx context.Context, attempt SecurityEnrichmentRefreshAttempt, code string, finishedAt time.Time) (bool, error) {
	return false, fmt.Errorf("refresh lifecycle unavailable")
}

// ReconcileSecurityEnrichmentRefresh checks the same UUID and expected manifest.
func (s *Store) ReconcileSecurityEnrichmentRefresh(ctx context.Context, completion SecurityEnrichmentRefreshCompletion) (SecurityEnrichmentRefreshState, error) {
	return SecurityEnrichmentRefreshState{State: "unknown"}, fmt.Errorf("refresh lifecycle unavailable")
}
