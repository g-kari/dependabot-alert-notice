// Package enrichmentrelease defines pure retained-request inspection and an
// independent release-certificate data format. It imports no Store or runtime.
// Neither inspection nor encoding obtains business proof, releases a source,
// permits Reserve, restores an owner, or changes journal checkpoint version 1.
package enrichmentrelease

import (
	"errors"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

// CertificateVersion identifies this independent internal certificate format.
const CertificateVersion = 1

// MaxCertificateBytes bounds certificate JSON, not a retained checkpoint/feed.
const MaxCertificateBytes = 4 << 10

// ReservationRequest preserves the exact already-retained reservation input.
// IntentID is a non-authentication correlation value, never an execution grant.
type ReservationRequest struct {
	IntentID           string
	ExpectedGeneration int64
	Reserved           enrichmentjournal.AppendRequest
	ReservedDigest     string
}

// ReleaseRequest retains only the original reservation and the complete terminal
// checkpoint/previous head/digest. It accepts no duplicate Attempt or Completion.
type ReleaseRequest struct {
	Reservation    ReservationRequest
	Terminal       enrichmentjournal.AppendRequest
	TerminalDigest string
}

// Inspection is a syntactically eligible, independently owned candidate.
// Kind is the required future proof class: success, failed, or no_run.
// Empty RunID means no run was prepared; no UUID/clock is synthesized.
type Inspection struct {
	Request ReleaseRequest
	Kind    string
	RunID   string
}

// Certificate is bounded data, not proof that a Store verified or committed it.
// A future issuer must match the complete retained request and historical
// business proof in the release transaction. RunID is null exactly for no_run;
// Receipt is a bounded nonempty business receipt only for success.
type Certificate struct {
	Version                int     `json:"version"`
	OperationID            string  `json:"operation_id"`
	IntentID               string  `json:"intent_id"`
	Connector              string  `json:"connector"`
	Generation             int64   `json:"generation"`
	ReservedDigest         string  `json:"reserved_digest"`
	TerminalSequence       int64   `json:"terminal_sequence"`
	TerminalPreviousDigest string  `json:"terminal_previous_digest"`
	TerminalDigest         string  `json:"terminal_digest"`
	Kind                   string  `json:"kind"`
	RunID                  *string `json:"run_id"`
	Receipt                string  `json:"receipt"`
}

// InspectTerminal validates only the retained binding and legal nonpending
// returned checkpoint shape, using the existing journal contract. It is pure.
func InspectTerminal(request ReleaseRequest) (Inspection, error) {
	return Inspection{}, errors.New("release inspection unavailable")
}

// EncodeCertificate validates bounded shape before canonical JSON marshaling.
// Its syntactic success cannot replace SQL proof or an atomic release.
func EncodeCertificate(certificate Certificate) ([]byte, error) {
	return nil, errors.New("release certificate codec unavailable")
}

// DecodeCertificate rejects non-closed/oversized certificate JSON and owns its
// decoded values. It never reads a journal or attests that a release occurred.
func DecodeCertificate(data []byte) (Certificate, error) {
	return Certificate{}, errors.New("release certificate codec unavailable")
}
