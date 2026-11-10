package enrichmentrefresh

import (
	"context"
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
// The explicitly trusted sink must honor its context; panic or a call that never
// returns keeps the controller's reservation. This boundary cannot force it to stop.
type PreservationSink interface {
	Preserve(context.Context, PreservationCheckpoint) error
}

// NewPreservingManualController requires an explicit sink in addition to the
// existing Service dependencies. The existing constructor remains unchanged.
// This optional mode retains the same 16-record, exact-binding/source gates.
func NewPreservingManualController(service Service, sink PreservationSink) (*ManualController, error) {
	if missing(sink) {
		return nil, ErrManualInvalid
	}
	c, err := NewManualController(service)
	if err != nil {
		return nil, err
	}
	c.preservation = sink
	return c, nil
}

type preservationBeforeWrite func(context.Context, PreservationStage, Result) error

func clonePreservationCheckpoint(checkpoint PreservationCheckpoint) PreservationCheckpoint {
	checkpoint.Result = cloneManualResult(checkpoint.Result)
	checkpoint.Prepared = cloneManualPending(checkpoint.Prepared)
	return checkpoint
}

func preservationUnknown(out Result, after string) (Result, error) {
	out.Outcome, out.Code, out.Advance, out.NextAfter = "pending", "preservation_unknown", false, after
	return out, ErrPending
}

// preserve checkpoints an owned original before calling the sink with another
// copy. The private flag is distinct from Pending: even a zero-UUID reservation
// with no Store write can have an unknown preservation acknowledgement.
func (c *ManualController) preserve(ctx context.Context, record *manualRecord, stage PreservationStage, result Result) error {
	checkpoint := PreservationCheckpoint{
		Version: 1, OperationID: record.operation.OperationID,
		Request: record.operation.Request, Stage: stage,
		Result: cloneManualResult(result),
	}
	c.mu.Lock()
	checkpoint.Prepared = cloneManualPending(record.retained)
	if result.Pending != nil {
		checkpoint.Prepared = cloneManualPending(result.Pending)
	}
	owned := clonePreservationCheckpoint(checkpoint)
	record.checkpoint = &owned
	record.retained = cloneManualPending(owned.Prepared)
	c.mu.Unlock()

	argument := clonePreservationCheckpoint(owned)
	var err error
	if ctx.Err() != nil {
		err = ctx.Err()
	} else {
		err = c.preservation.Preserve(ctx, argument)
	}
	if err == nil && ctx.Err() == nil {
		return nil
	}
	c.mu.Lock()
	record.preservationUnknown = true
	c.mu.Unlock()
	// Never retain or expose sink errors, which can contain arbitrary data.
	return ErrPending
}

func (c *ManualController) callPreserving(ctx context.Context, record *manualRecord) (ManualOperation, bool, error) {
	request := record.operation.Request
	result := Result{NextAfter: request.After}
	callErr := c.preserve(ctx, record, PreserveReserved, result)
	if callErr == nil {
		result, callErr = c.service.runPrepared(ctx, request, func(checkpointCtx context.Context, stage PreservationStage, candidate Result) error {
			return c.preserve(checkpointCtx, record, stage, candidate)
		})
	} else {
		result, callErr = preservationUnknown(result, request.After)
	}
	owned := cloneManualResult(result)
	safeErr := manualCallError(callErr, owned)
	c.mu.Lock()
	if record.preservationUnknown {
		owned, safeErr = preservationUnknown(owned, request.After)
		owned.Pending = cloneManualPending(record.retained)
	}
	record.operation.Result, record.err = owned, safeErr
	record.operation.State = "resolved"
	if owned.Pending != nil || record.preservationUnknown {
		record.operation.State = "pending"
	}
	c.busy = false
	snapshot := cloneManualOperation(record.operation)
	c.mu.Unlock()
	return snapshot, false, safeErr
}

// reconcilePreserving publishes a newly verified terminal result only after
// acknowledgement. The Store remains read-only; the injected sink is a separate
// preservation capability. No sink error is retried or resolved by Store reads.
func (c *ManualController) reconcilePreserving(ctx, readCtx context.Context, record *manualRecord, work *Pending, success, failed bool) (ManualOperation, error) {
	c.mu.Lock()
	candidate := cloneManualResult(record.operation.Result)
	c.mu.Unlock()
	resolved := false
	if ctx.Err() == nil && readCtx.Err() == nil {
		if success {
			var err error
			candidate, err = succeeded(candidate)
			resolved = err == nil
		} else if failed {
			candidate.Outcome, candidate.Code, candidate.Pending = "failed", work.ExpectedFailure.Code, nil
			candidate.Advance, candidate.NextAfter = false, record.operation.Request.After
			resolved = true
		}
	}
	if resolved {
		if err := c.preserve(readCtx, record, PreserveReturned, candidate); err != nil {
			resolved = false
		}
	}
	c.mu.Lock()
	if record.preservationUnknown {
		pendingResult, _ := preservationUnknown(record.operation.Result, record.operation.Request.After)
		pendingResult.Pending = cloneManualPending(record.retained)
		record.operation.Result, record.operation.State, record.err = pendingResult, "pending", ErrPending
	} else if resolved && ctx.Err() == nil && readCtx.Err() == nil {
		record.operation.Result, record.operation.State, record.err = cloneManualResult(candidate), "resolved", nil
	}
	c.busy = false
	snapshot, err := cloneManualOperation(record.operation), record.err
	if record.operation.State == "pending" {
		err = ErrPending
	}
	if ctx.Err() != nil {
		err = manualContextError(ctx)
	}
	c.mu.Unlock()
	return snapshot, err
}
