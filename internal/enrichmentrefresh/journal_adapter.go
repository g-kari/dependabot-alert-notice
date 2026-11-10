package enrichmentrefresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

// JournalRepository is the explicit checkpoint append and read-only matching
// boundary. Its acknowledgements never confer business/fetch ownership.
type JournalRepository interface {
	AppendSecurityEnrichmentCheckpoint(context.Context, enrichmentjournal.AppendRequest) (enrichmentjournal.Acknowledgement, error)
	ReadSecurityEnrichmentCheckpointAcknowledgement(context.Context, enrichmentjournal.AppendRequest) (store.SecurityEnrichmentJournalAcknowledgementState, error)
}

var errJournalAdapterUnknown = errors.New("journal preservation unknown")

// NewJournalManualController binds one private adapter to one controller lifetime.
// It requires explicit Service and journal dependencies, creates no defaults,
// and does not return a reusable Sink. Existing constructors remain unchanged.
// Repeated reserved callbacks, fresh journal replay and uncertain reservations
// must not authorize another Service execution or restoration.
func NewJournalManualController(service Service, journal JournalRepository) (*ManualController, error) {
	if missing(journal) {
		return nil, ErrManualInvalid
	}
	adapter := &journalAdapter{repository: journal, records: make(map[string]*journalAdapterRecord)}
	return NewPreservingManualController(service, adapter)
}

type journalAdapterRecord struct {
	request           Request
	current           enrichmentjournal.AppendRequest
	payload           []byte
	digest            string
	acknowledged      bool
	reservedConfirmed bool
	unknown           bool
}

type journalAdapter struct {
	repository JournalRepository
	mu         sync.Mutex
	busy       bool
	records    map[string]*journalAdapterRecord
}

func adapterUnknown(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("journal preservation: %w", ctx.Err())
	}
	return errJournalAdapterUnknown
}

func adapterDigest(payload []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}

func copyJournalAppend(request enrichmentjournal.AppendRequest, payload []byte) (enrichmentjournal.AppendRequest, error) {
	checkpoint, err := enrichmentjournal.Decode(payload)
	if err != nil {
		return enrichmentjournal.AppendRequest{}, ErrManualInvalid
	}
	return enrichmentjournal.AppendRequest{Sequence: request.Sequence, PreviousDigest: request.PreviousDigest, Checkpoint: checkpoint}, nil
}

func exactJournalAck(ack enrichmentjournal.Acknowledgement, expected enrichmentjournal.AppendRequest, digest string) bool {
	return ack.OperationID == expected.Checkpoint.OperationID && ack.Sequence == expected.Sequence && ack.Digest == digest
}

// Preserve is intentionally available only on the private adapter created by
// the factory. All I/O uses the supplied context with no replacement budget.
func (a *journalAdapter) Preserve(ctx context.Context, checkpoint PreservationCheckpoint) error {
	if a == nil || a.records == nil || ctx == nil {
		return ErrManualInvalid
	}
	if ctx.Err() != nil {
		return adapterUnknown(ctx)
	}
	converted, err := convertJournalCheckpoint(checkpoint)
	if err != nil {
		return ErrManualInvalid
	}
	payload, err := enrichmentjournal.Encode(converted)
	if err != nil {
		return ErrManualInvalid
	}
	digest := adapterDigest(payload)
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return ErrManualBusy
	}
	record, exists := a.records[checkpoint.OperationID]
	sequence, previous := int64(1), ""
	if exists {
		if record.request != checkpoint.Request || checkpoint.Stage == PreserveReserved {
			a.mu.Unlock()
			return ErrManualConflict
		}
		if record.unknown {
			a.mu.Unlock()
			return adapterUnknown(ctx)
		}
		if bytes.Equal(record.payload, payload) {
			acknowledged := record.acknowledged
			a.mu.Unlock()
			if acknowledged && ctx.Err() == nil {
				return nil
			}
			return adapterUnknown(ctx)
		}
		if !record.acknowledged || !record.reservedConfirmed || enrichmentjournal.ValidateTransition(&record.current.Checkpoint, converted) != nil {
			a.mu.Unlock()
			return ErrManualConflict
		}
		sequence, previous = record.current.Sequence+1, record.digest
	} else {
		if checkpoint.Stage != PreserveReserved || enrichmentjournal.ValidateTransition(nil, converted) != nil {
			a.mu.Unlock()
			return ErrManualConflict
		}
		for _, pending := range a.records {
			if pending.unknown && pending.request.Connector == checkpoint.Request.Connector {
				a.mu.Unlock()
				return ErrManualPendingSource
			}
		}
		if len(a.records) >= manualMaxRecords {
			a.mu.Unlock()
			return ErrManualCapacity
		}
		record = &journalAdapterRecord{request: checkpoint.Request}
	}
	// Retain the exact private payload/request before any dependency call.
	expected := enrichmentjournal.AppendRequest{Sequence: sequence, PreviousDigest: previous, Checkpoint: converted}
	record.current, record.payload, record.digest = expected, bytes.Clone(payload), digest
	record.acknowledged = false
	a.records[checkpoint.OperationID], a.busy = record, true
	knownOwner := record.reservedConfirmed
	a.mu.Unlock()

	argument, copyErr := copyJournalAppend(expected, payload)
	confirmed := false
	if copyErr == nil && ctx.Err() == nil {
		ack, appendErr := a.repository.AppendSecurityEnrichmentCheckpoint(ctx, argument)
		if ctx.Err() == nil {
			if appendErr == nil {
				confirmed = exactJournalAck(ack, expected, digest) && !ack.Replay
			} else if checkpoint.Stage != PreserveReserved && knownOwner {
				// This is a read, never an Append retry. Readback gets a fresh
				// copy; dependency argument mutation cannot supply expected data.
				readArgument, err := copyJournalAppend(expected, payload)
				if err == nil {
					state, readErr := a.repository.ReadSecurityEnrichmentCheckpointAcknowledgement(ctx, readArgument)
					confirmed = readErr == nil && ctx.Err() == nil && state.State == "matched" &&
						exactJournalAck(state.Acknowledgement, expected, digest) && state.Acknowledgement.Replay &&
						state.HeadSequence == expected.Sequence && state.HeadDigest == digest
				}
			}
		}
	}
	a.mu.Lock()
	if ctx.Err() != nil {
		confirmed = false
	}
	record.acknowledged, record.unknown = confirmed, !confirmed
	if checkpoint.Stage == PreserveReserved && confirmed {
		record.reservedConfirmed = true
	}
	a.busy = false
	a.mu.Unlock()
	if !confirmed {
		return adapterUnknown(ctx)
	}
	return nil
}
