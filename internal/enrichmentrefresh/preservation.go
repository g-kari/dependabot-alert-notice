package enrichmentrefresh

import (
	"context"
	"errors"
)

// PreservationStage identifies a bounded checkpoint, not a recovery grant.
type PreservationStage string

const (
	PreserveReserved PreservationStage = "reserved"
	PreserveBegin    PreservationStage = "begin"
	PreserveFail     PreservationStage = "fail"
	PreserveComplete PreservationStage = "complete"
	PreserveReturned PreservationStage = "returned"
)

// PreservationCheckpoint binds a versioned operation and its exact scan result
// to zero or one prepared run UUID. Prepared retains the full original envelope
// even when a candidate terminal Result has cleared Result.Pending. This is an
// internal library contract, not an HTTP DTO or a durable/restart guarantee.
type PreservationCheckpoint struct {
	Version     int
	OperationID string
	Request     Request
	Stage       PreservationStage
	Result      Result
	Prepared    *Pending
}

// PreservationSink must acknowledge preservation before a dependent write or
// result publication. Nil error is the only acknowledgement. Any error is an
// unknown outcome: no retry, replacement UUID, fetch grant or cursor advancement.
// The sink receives an independent deep copy and may not mutate private state.
// Persistence, readback, storage capacity and durability are not implemented here.
type PreservationSink interface {
	Preserve(context.Context, PreservationCheckpoint) error
}

var errPreservationUnavailable = errors.New("owned preservation unavailable")

// NewPreservingManualController requires an explicit sink in addition to the
// existing Service dependencies. The existing constructor remains unchanged.
// This optional mode retains the same 16-record, exact-binding/source gates.
func NewPreservingManualController(service Service, sink PreservationSink) (*ManualController, error) {
	return nil, errPreservationUnavailable
}
