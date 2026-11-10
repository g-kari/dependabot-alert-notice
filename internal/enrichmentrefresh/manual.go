package enrichmentrefresh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
)

const manualMaxRecords = 16

// ErrManualInvalid reports invalid explicit dependencies, context or binding.
var ErrManualInvalid = errors.New("manual refresh: invalid input")

// ErrManualConflict reports reuse of an operation ID with different content.
var ErrManualConflict = errors.New("manual refresh: operation conflict")

// ErrManualBusy reports one already reserved service or readback call.
var ErrManualBusy = errors.New("manual refresh: call in progress")

// ErrManualCapacity reports full non-evicting in-process retention.
var ErrManualCapacity = errors.New("manual refresh: retention full")

// ErrManualPendingSource blocks fresh operations on an unresolved source.
var ErrManualPendingSource = errors.New("manual refresh: source has pending operation")

// ErrManualNotFound reports an operation not retained by this controller.
var ErrManualNotFound = errors.New("manual refresh: operation not found")

// ErrManualExecution reports a failed service call without retaining raw errors.
var ErrManualExecution = errors.New("manual refresh: service call failed")

// ManualOperation describes one in-process, exactly bound manual call. State is
// calling, pending or resolved. Result may retain the complete Pending envelope;
// it is not a public HTTP response schema or a durable recovery record.
type ManualOperation struct {
	OperationID string
	Request     Request
	State       string
	Result      Result
}

type manualRecord struct {
	operation ManualOperation
	err       error
	// Keep the original envelope even after a verified resolution. Neither
	// repository readback arguments nor outer snapshots alias this evidence.
	retained *Pending
}

// ManualController owns at most 16 non-evicting in-process operation records.
// It copies the explicitly injected Service, but does not own or close its Store.
// It has no route, default dependencies, background retry or crash durability.
// A call that never returns (including panic) cannot release its reserved slot.
type ManualController struct {
	service    Service
	mu         sync.Mutex
	operations map[string]*manualRecord
	busy       bool
}

// NewManualController requires explicit Service dependencies without any I/O.
func NewManualController(service Service) (*ManualController, error) {
	if missing(service.Store) || missing(service.Fetcher) || service.Clock == nil || service.NewUUID == nil {
		return nil, ErrManualInvalid
	}
	return &ManualController{service: service, operations: make(map[string]*manualRecord)}, nil
}

func manualRequestValid(operationID string, request Request) bool {
	return uuid(operationID) && (request.Connector == "epss_feed" || request.Connector == "kev_feed") && request.Limit >= 1 && request.Limit <= 200 && cursor(request.After)
}

func manualContextError(ctx context.Context) error {
	return fmt.Errorf("manual refresh: %w", ctx.Err())
}

func manualCallError(err error, result Result) error {
	if result.Pending != nil {
		return ErrPending
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("manual refresh: %w", context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("manual refresh: %w", context.DeadlineExceeded)
	}
	return ErrManualExecution
}

// Call binds a distinct operation ID to the exact connector/after/limit.
// The bool identifies cached state replay, never ownership or permission to fetch.
// An existing matching operation can replay even when retention is full or a
// different call is busy. A calling slot reports busy without another service
// call. Every refusal happens before service/Store/clock/UUID/fetcher I/O.
func (c *ManualController) Call(ctx context.Context, operationID string, request Request) (ManualOperation, bool, error) {
	if c == nil || c.operations == nil || ctx == nil || !manualRequestValid(operationID, request) {
		return ManualOperation{}, false, ErrManualInvalid
	}
	if ctx.Err() != nil {
		return ManualOperation{}, false, manualContextError(ctx)
	}
	c.mu.Lock()
	if record, ok := c.operations[operationID]; ok {
		if record.operation.Request != request {
			c.mu.Unlock()
			return ManualOperation{}, false, ErrManualConflict
		}
		snapshot := cloneManualOperation(record.operation)
		err := record.err
		if record.operation.State == "calling" {
			err = ErrManualBusy
		}
		c.mu.Unlock()
		return snapshot, true, err
	}
	if c.busy {
		c.mu.Unlock()
		return ManualOperation{}, false, ErrManualBusy
	}
	for _, record := range c.operations {
		if record.operation.State == "pending" && record.operation.Request.Connector == request.Connector {
			c.mu.Unlock()
			return ManualOperation{}, false, ErrManualPendingSource
		}
	}
	if len(c.operations) >= manualMaxRecords {
		c.mu.Unlock()
		return ManualOperation{}, false, ErrManualCapacity
	}
	if ctx.Err() != nil {
		c.mu.Unlock()
		return ManualOperation{}, false, manualContextError(ctx)
	}
	record := &manualRecord{operation: ManualOperation{
		OperationID: operationID, Request: request, State: "calling",
		Result: Result{NextAfter: request.After},
	}}
	c.operations[operationID], c.busy = record, true
	c.mu.Unlock()

	// Service owns its prepared envelope before each write. On return take an
	// immediate deep copy before making the result available to any outer caller.
	result, callErr := c.service.RefreshOnce(ctx, request)
	owned := cloneManualResult(result)
	kept := cloneManualPending(owned.Pending)
	safeErr := manualCallError(callErr, owned)

	c.mu.Lock()
	record.operation.Result, record.err, record.retained = owned, safeErr, kept
	record.operation.State = "resolved"
	if owned.Pending != nil {
		record.operation.State = "pending"
	}
	c.busy = false
	snapshot := cloneManualOperation(record.operation)
	c.mu.Unlock()
	return snapshot, false, safeErr
}

// Snapshot returns a separate deep copy without any dependency I/O. A calling
// record proves slot reservation only; it does not imply a run ID or ownership.
func (c *ManualController) Snapshot(operationID string) (ManualOperation, bool) {
	if c == nil || !uuid(operationID) {
		return ManualOperation{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.operations[operationID]
	if !ok {
		return ManualOperation{}, false
	}
	return cloneManualOperation(record.operation), true
}

// Reconcile performs at most one existing read-only Store recovery call, using
// the exact privately retained envelope and the caller's context with a two-second
// maximum. It never writes, fetches or reads a business clock/UUID factory.
// Begin-only running/missing/readback does not grant fetch ownership.
func (c *ManualController) Reconcile(ctx context.Context, operationID string) (ManualOperation, error) {
	if c == nil || c.operations == nil || ctx == nil || !uuid(operationID) {
		return ManualOperation{}, ErrManualInvalid
	}
	if ctx.Err() != nil {
		return ManualOperation{}, manualContextError(ctx)
	}
	c.mu.Lock()
	record, ok := c.operations[operationID]
	if !ok {
		c.mu.Unlock()
		return ManualOperation{}, ErrManualNotFound
	}
	if record.operation.State == "resolved" {
		snapshot, err := cloneManualOperation(record.operation), record.err
		c.mu.Unlock()
		return snapshot, err
	}
	if c.busy {
		snapshot := cloneManualOperation(record.operation)
		c.mu.Unlock()
		return snapshot, ErrManualBusy
	}
	work := cloneManualPending(record.retained)
	if work == nil {
		snapshot := cloneManualOperation(record.operation)
		c.mu.Unlock()
		return snapshot, ErrPending
	}
	c.busy = true
	c.mu.Unlock()

	readCtx, stop := context.WithTimeout(ctx, cleanupBudget)
	defer stop()
	success, failed := false, false
	if work.Completion != nil {
		state, err := c.service.Store.ReconcileSecurityEnrichmentRefresh(readCtx, *work.Completion)
		success = err == nil && state.State == "success" && state.Receipt != ""
	} else {
		state, err := c.service.Store.ReadSecurityEnrichmentRefreshAttempt(readCtx, work.Attempt, work.ExpectedFailure)
		failed = err == nil && work.ExpectedFailure != nil && state.State == "failed" && state.Receipt == ""
	}

	c.mu.Lock()
	// Cancellation/read errors/unknown states retain every original value.
	if ctx.Err() == nil && readCtx.Err() == nil {
		if success {
			resolved, err := succeeded(record.operation.Result)
			if err == nil {
				record.operation.Result, record.operation.State, record.err = resolved, "resolved", nil
			}
		} else if failed {
			record.operation.Result.Outcome = "failed"
			record.operation.Result.Code = work.ExpectedFailure.Code
			record.operation.Result.Pending = nil
			record.operation.Result.Advance = false
			record.operation.Result.NextAfter = record.operation.Request.After
			record.operation.State, record.err = "resolved", nil
		}
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

func cloneManualOperation(operation ManualOperation) ManualOperation {
	operation.Result = cloneManualResult(operation.Result)
	return operation
}

func cloneManualResult(result Result) Result {
	result.Pending = cloneManualPending(result.Pending)
	return result
}

func cloneManualPending(pending *Pending) *Pending {
	if pending == nil {
		return nil
	}
	owned := *pending
	owned.Attempt.Targets = slices.Clone(pending.Attempt.Targets)
	if pending.ExpectedFailure != nil {
		failure := *pending.ExpectedFailure
		owned.ExpectedFailure = &failure
	}
	if pending.Completion != nil {
		completion := *pending.Completion
		completion.Attempt.Targets = slices.Clone(pending.Completion.Attempt.Targets)
		completion.Feed.SelectedCVEs = slices.Clone(pending.Completion.Feed.SelectedCVEs)
		completion.Feed.Entries = slices.Clone(pending.Completion.Feed.Entries)
		for i := range completion.Feed.Entries {
			entry := &completion.Feed.Entries[i]
			if entry.EPSS != nil {
				value := *entry.EPSS
				entry.EPSS = &value
			}
			if entry.Percentile != nil {
				value := *entry.Percentile
				entry.Percentile = &value
			}
			if entry.KEVDateAdded != nil {
				value := *entry.KEVDateAdded
				entry.KEVDateAdded = &value
			}
		}
		owned.Completion = &completion
	}
	return &owned
}
