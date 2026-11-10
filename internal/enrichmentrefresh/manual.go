package enrichmentrefresh

import (
	"context"
	"errors"
)

const manualMaxRecords = 16

// ManualOperation describes one in-process, exactly bound manual call. State is
// calling, pending or resolved. Result may retain the complete Pending envelope;
// it is not a public HTTP response schema or a durable recovery record.
type ManualOperation struct {
	OperationID string
	Request     Request
	State       string
	Result      Result
}

// ManualController owns bounded, non-evicting operation retention around one
// explicitly injected Service. This Red checkpoint is an unavailable API stub;
// it provides no route, default dependencies, background work or durability.
type ManualController struct{}

// NewManualController declares the required Service-injection boundary.
// Validation and execution are unavailable in this Red checkpoint.
func NewManualController(service Service) (*ManualController, error) {
	return &ManualController{}, nil
}

// Call declares exact operation/request binding and cached replay. The bool
// identifies a replay, not fetch ownership or permission to mint another UUID.
func (c *ManualController) Call(ctx context.Context, operationID string, request Request) (ManualOperation, bool, error) {
	return ManualOperation{}, false, errors.New("manual controller unavailable")
}

// Snapshot declares an owned in-process copy without executing any service I/O.
func (c *ManualController) Snapshot(operationID string) (ManualOperation, bool) {
	return ManualOperation{}, false
}

// Reconcile declares explicit read-only recovery of the exact retained envelope.
// It must never fetch, write, regenerate clocks or acquire Begin replay ownership.
func (c *ManualController) Reconcile(ctx context.Context, operationID string) (ManualOperation, error) {
	return ManualOperation{}, errors.New("manual controller unavailable")
}
