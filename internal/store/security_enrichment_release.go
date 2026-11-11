package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrelease"
)

// SecurityEnrichmentReleaseAcknowledgement binds a committed release to its
// deterministic certificate and certificate JSON digest. This is storage and
// historical business proof, never authentication, fetch or restart ownership.
type SecurityEnrichmentReleaseAcknowledgement struct {
	Certificate       enrichmentrelease.Certificate
	CertificateDigest string
}

// SecurityEnrichmentReleaseProof classifies a same-retained-request read as
// matched, missing, conflict or unknown. Only matched exposes acknowledgement.
// Historical matching is not a current source fence or next-reservation grant.
type SecurityEnrichmentReleaseProof struct {
	State           string
	Acknowledgement SecurityEnrichmentReleaseAcknowledgement
}

var errReleaseUnavailable = errors.New("operation release unavailable")

// ReleaseSecurityEnrichmentOperation is the explicit fresh-active-only release
// boundary. The retained request supplies the root and complete terminal CP;
// no second Attempt/Completion, replacement UUID or clock is accepted. Until
// implemented, it refuses without changing existing runtime or storage.
func (s *Store) ReleaseSecurityEnrichmentOperation(ctx context.Context, request enrichmentrelease.ReleaseRequest) (SecurityEnrichmentReleaseAcknowledgement, error) {
	return SecurityEnrichmentReleaseAcknowledgement{}, fmt.Errorf("release operation: %w", errReleaseUnavailable)
}

// ReadSecurityEnrichmentRelease is a read-only same-full-request proof boundary,
// not a release retry, repair, restore or execution grant. Until implemented,
// it exposes no acknowledgement and makes no schema or storage changes.
func (s *Store) ReadSecurityEnrichmentRelease(ctx context.Context, request enrichmentrelease.ReleaseRequest) (SecurityEnrichmentReleaseProof, error) {
	return SecurityEnrichmentReleaseProof{State: "unknown"}, fmt.Errorf("read operation release: %w", errReleaseUnavailable)
}
