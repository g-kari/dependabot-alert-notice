package store

import (
	"context"
	"fmt"
	"time"
)

// SecurityEnrichmentRefreshFailure identifies the exact failure write expected
// by a caller reconciling an uncertain Fail outcome. It contains no source data.
type SecurityEnrichmentRefreshFailure struct {
	Code       string
	FinishedAt time.Time
}

// ReadSecurityEnrichmentRefreshAttempt reads a reservation without a completed
// feed. It never establishes success; only full-completion reconciliation can.
func (s *Store) ReadSecurityEnrichmentRefreshAttempt(ctx context.Context, attempt SecurityEnrichmentRefreshAttempt, expectedFailure *SecurityEnrichmentRefreshFailure) (SecurityEnrichmentRefreshState, error) {
	return SecurityEnrichmentRefreshState{State: "unknown"}, fmt.Errorf("attempt readback unavailable")
}
