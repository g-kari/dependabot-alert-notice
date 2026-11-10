package enrichmentrefresh

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type faultJournalRepository struct {
	JournalRepository
	appendCalls, readCalls       int
	appendHook                   func(context.Context, *enrichmentjournal.AppendRequest, *enrichmentjournal.Acknowledgement, *error)
	readHook                     func(context.Context, *enrichmentjournal.AppendRequest, *store.SecurityEnrichmentJournalAcknowledgementState, *error)
	arguments                    []*enrichmentjournal.AppendRequest
	appendContexts, readContexts []context.Context
}

func (r *faultJournalRepository) AppendSecurityEnrichmentCheckpoint(ctx context.Context, request enrichmentjournal.AppendRequest) (enrichmentjournal.Acknowledgement, error) {
	r.appendCalls++
	r.appendContexts = append(r.appendContexts, ctx)
	r.arguments = append(r.arguments, &request)
	ack, err := r.JournalRepository.AppendSecurityEnrichmentCheckpoint(ctx, request)
	if r.appendHook != nil {
		r.appendHook(ctx, &request, &ack, &err)
	}
	return ack, err
}
func (r *faultJournalRepository) ReadSecurityEnrichmentCheckpointAcknowledgement(ctx context.Context, request enrichmentjournal.AppendRequest) (store.SecurityEnrichmentJournalAcknowledgementState, error) {
	r.readCalls++
	r.readContexts = append(r.readContexts, ctx)
	r.arguments = append(r.arguments, &request)
	state, err := r.JournalRepository.ReadSecurityEnrichmentCheckpointAcknowledgement(ctx, request)
	if r.readHook != nil {
		r.readHook(ctx, &request, &state, &err)
	}
	return state, err
}
func mutateJournalArgument(request *enrichmentjournal.AppendRequest) {
	request.Sequence = 99
	request.PreviousDigest = "PRIVATE-argument"
	request.Checkpoint.OperationID = "PRIVATE-operation"
	if p := request.Checkpoint.Prepared; p != nil {
		if len(p.Attempt.Targets) > 0 {
			p.Attempt.Targets[0].FindingID = "PRIVATE-target"
		}
		if p.Failure != nil {
			p.Failure.Code = "PRIVATE-failure"
		}
		if p.Completion != nil {
			p.Completion.OriginalDigest = "PRIVATE-digest"
			if len(p.Completion.Feed.Entries) > 0 && p.Completion.Feed.Entries[0].EPSS != nil {
				*p.Completion.Feed.Entries[0].EPSS = 1
			}
		}
	}
}
func adapterPrivateJSON(t *testing.T, c *ManualController, id string) string {
	t.Helper()
	a, ok := c.preservation.(*journalAdapter)
	if !ok {
		t.Fatal("private adapter not bound")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.records[id]
	if r == nil {
		t.Fatal("retained adapter record missing")
	}
	return jsonValue(t, r.current) + "/" + string(r.payload) + "/" + r.digest
}
func TestJournalAdapterConstructorAndInvalidConversionHaveNoIO(t *testing.T) {
	db := contractStore(t, false)
	h := harness(t, db)
	repo := &faultJournalRepository{JournalRepository: db}
	var nilRepo *faultJournalRepository
	for _, dependency := range []JournalRepository{nil, nilRepo} {
		if _, err := NewJournalManualController(h.service, dependency); !errors.Is(err, ErrManualInvalid) {
			t.Fatal("nil journal accepted")
		}
	}
	bad := h.service
	bad.Clock = nil
	if _, err := NewJournalManualController(bad, repo); !errors.Is(err, ErrManualInvalid) {
		t.Fatal("missing Service dependency accepted")
	}
	c, err := NewJournalManualController(h.service, repo)
	if err != nil {
		t.Fatal(err)
	}
	source := adapterContractCheckpoint(t)
	source.Result.Pending.Completion.Feed.Entries[0].EPSS = new(float64)
	*source.Result.Pending.Completion.Feed.Entries[0].EPSS = math.Copysign(0, -1)
	if err := c.preservation.Preserve(context.Background(), source); !errors.Is(err, ErrManualInvalid) {
		t.Fatal("signed-zero duplicate mismatch accepted")
	}
	if repo.appendCalls != 0 || repo.readCalls != 0 || len(h.repo.calls) != 0 || h.clockCalls != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 {
		t.Fatal("constructor/converter rejection acquired I/O")
	}
}
func TestJournalAdapterDependencyAndLateArgumentMutationCannotSupplyExpectedValues(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	repo := &faultJournalRepository{JournalRepository: db}
	repo.appendHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, _ *enrichmentjournal.Acknowledgement, err *error) {
		stage := request.Checkpoint.Stage
		mutateJournalArgument(request)
		if stage == enrichmentjournal.Complete {
			*err = errors.New("PRIVATE-postcommit")
		}
	}
	repo.readHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, _ *store.SecurityEnrichmentJournalAcknowledgementState, _ *error) {
		mutateJournalArgument(request)
	}
	c, err := NewJournalManualController(h.service, repo)
	if err != nil {
		t.Fatal(err)
	}
	h.fetchHook = func(context.Context) {
		for _, argument := range repo.arguments {
			mutateJournalArgument(argument)
		}
	}
	id := manualOperationID(620)
	request := Request{Connector: "epss_feed", Limit: 200}
	op, _, err := c.Call(context.Background(), id, request)
	if err != nil || op.Result.Outcome != "success" || repo.appendCalls != 4 || repo.readCalls != 1 || h.uuidCalls != 1 || h.fetchCalls != 1 || h.clockCalls != 3 {
		t.Fatalf("mutable arguments supplied expected identity: %+v %v", op, err)
	}
	private := adapterPrivateJSON(t, c, id)
	for _, argument := range repo.arguments {
		mutateJournalArgument(argument)
	}
	if adapterPrivateJSON(t, c, id) != private {
		t.Fatal("late dependency mutation damaged retained request/payload")
	}
	counts, appends, reads := manualCounts(t, h), repo.appendCalls, repo.readCalls
	again, cached, err := c.Call(context.Background(), id, request)
	if err != nil || !cached || !reflect.DeepEqual(op, again) || manualCounts(t, h) != counts || repo.appendCalls != appends || repo.readCalls != reads {
		t.Fatal("cached replay acquired I/O after mutation")
	}
	c.mu.Lock()
	checkpoint := clonePreservationCheckpoint(*c.operations[id].checkpoint)
	c.mu.Unlock()
	if err := c.preservation.Preserve(context.Background(), checkpoint); err != nil || repo.appendCalls != appends || repo.readCalls != reads {
		t.Fatal("same current CP created a sequence or write")
	}
}
func TestJournalAdapterReadbackMismatchErrorAndCancellationRemainUnknown(t *testing.T) {
	for _, kind := range []string{"missing", "conflict", "unknown", "read-error", "wrong-op", "wrong-sequence", "wrong-digest", "wrong-replay", "wrong-head-sequence", "wrong-head-digest", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			repo := &faultJournalRepository{JournalRepository: db}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			repo.appendHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, _ *enrichmentjournal.Acknowledgement, err *error) {
				if request.Checkpoint.Stage == enrichmentjournal.Complete {
					*err = errors.New("PRIVATE-postcommit")
				}
			}
			repo.readHook = func(_ context.Context, _ *enrichmentjournal.AppendRequest, state *store.SecurityEnrichmentJournalAcknowledgementState, err *error) {
				switch kind {
				case "missing", "conflict", "unknown":
					*state = store.SecurityEnrichmentJournalAcknowledgementState{State: kind}
				case "read-error":
					*err = errors.New("PRIVATE-read-error")
				case "wrong-op":
					state.Acknowledgement.OperationID = manualOperationID(999)
				case "wrong-sequence":
					state.Acknowledgement.Sequence++
				case "wrong-digest":
					state.Acknowledgement.Digest = "sha256:" + strings.Repeat("f", 64)
				case "wrong-replay":
					state.Acknowledgement.Replay = false
				case "wrong-head-sequence":
					state.HeadSequence++
				case "wrong-head-digest":
					state.HeadDigest = "sha256:" + strings.Repeat("f", 64)
				case "cancel":
					cancel()
				}
			}
			c, err := NewJournalManualController(h.service, repo)
			if err != nil {
				t.Fatal(err)
			}
			id := manualOperationID(630)
			request := Request{Connector: "epss_feed", Limit: 200}
			op, _, err := c.Call(ctx, id, request)
			if !errors.Is(err, ErrPending) || op.State != "pending" || op.Result.Code != "preservation_unknown" || op.Result.Advance || op.Result.Pending == nil || op.Result.Pending.Completion == nil || h.repo.calls["complete"] != 0 || repo.appendCalls != 3 || repo.readCalls != 1 {
				t.Fatalf("unverified ack continued: %+v %v", op, err)
			}
			counts, appends, reads := manualCounts(t, h), repo.appendCalls, repo.readCalls
			_, _, err = c.Call(context.Background(), id, request)
			if !errors.Is(err, ErrPending) {
				t.Fatal("unknown same-ID replay resolved")
			}
			if _, _, err := c.Call(context.Background(), manualOperationID(631), request); !errors.Is(err, ErrManualPendingSource) {
				t.Fatal("unknown source gate lost")
			}
			if _, err := c.Reconcile(context.Background(), id); !errors.Is(err, ErrPending) {
				t.Fatal("business readback cleared preservation unknown")
			}
			if manualCounts(t, h) != counts || repo.appendCalls != appends || repo.readCalls != reads {
				t.Fatal("unknown was retried or advanced")
			}
		})
	}
}
func TestJournalAdapterWrongAppendAckNeverTriggersReadOrService(t *testing.T) {
	for _, kind := range []string{"operation", "sequence", "digest", "replay", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			repo := &faultJournalRepository{JournalRepository: db}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			repo.appendHook = func(_ context.Context, _ *enrichmentjournal.AppendRequest, ack *enrichmentjournal.Acknowledgement, _ *error) {
				switch kind {
				case "operation":
					ack.OperationID = manualOperationID(999)
				case "sequence":
					ack.Sequence++
				case "digest":
					ack.Digest = "bad"
				case "replay":
					ack.Replay = true
				case "cancel":
					cancel()
				}
			}
			c, err := NewJournalManualController(h.service, repo)
			if err != nil {
				t.Fatal(err)
			}
			op, _, err := c.Call(ctx, manualOperationID(640), Request{Connector: "epss_feed", Limit: 200})
			if !errors.Is(err, ErrPending) || op.Result.RunID != "" || op.Result.Pending != nil || op.Result.Advance || repo.appendCalls != 1 || repo.readCalls != 0 || len(h.repo.calls) != 0 || h.clockCalls != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 {
				t.Fatal("wrong reserved acknowledgement acquired fresh Service")
			}
		})
	}
}
func TestJournalAdapterReentryAndCapacityUseOnlyMetadataReservation(t *testing.T) {
	db := contractStore(t, false)
	h := harness(t, db)
	repo := &faultJournalRepository{JournalRepository: db}
	var c *ManualController
	ctx := context.Background()
	request := Request{Connector: "epss_feed", Limit: 1}
	repo.appendHook = func(_ context.Context, argument *enrichmentjournal.AppendRequest, _ *enrichmentjournal.Acknowledgement, _ *error) {
		done := make(chan error, 1)
		go func() {
			if snapshot, ok := c.Snapshot(argument.Checkpoint.OperationID); !ok || snapshot.State != "calling" {
				done <- errors.New("snapshot not available during journal I/O")
				return
			}
			if _, _, err := c.Call(ctx, manualOperationID(799), Request{Connector: "kev_feed", Limit: 1}); !errors.Is(err, ErrManualBusy) {
				done <- errors.New("reentrant Service not rejected")
				return
			}
			cp := PreservationCheckpoint{Version: 1, OperationID: argument.Checkpoint.OperationID, Request: request, Stage: PreserveReserved}
			if err := c.preservation.Preserve(ctx, cp); !errors.Is(err, ErrManualBusy) {
				done <- errors.New("adapter mutex held or reentrant I/O permitted")
				return
			}
			done <- nil
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("metadata mutex held over repository I/O")
		}
	}
	var err error
	c, err = NewJournalManualController(h.service, repo)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		op, _, err := c.Call(ctx, manualOperationID(700+i), request)
		if err != nil || !op.Result.Exhausted {
			t.Fatalf("zero-run retained slot failed: %+v %v", op, err)
		}
	}
	appends, reads, counts := repo.appendCalls, repo.readCalls, manualCounts(t, h)
	if _, _, err := c.Call(ctx, manualOperationID(716), request); !errors.Is(err, ErrManualCapacity) {
		t.Fatal("controller evicted operation")
	}
	cp := PreservationCheckpoint{Version: 1, OperationID: manualOperationID(716), Request: request, Stage: PreserveReserved}
	if err := c.preservation.Preserve(ctx, cp); !errors.Is(err, ErrManualCapacity) {
		t.Fatal("adapter evicted retained payload")
	}
	if _, cached, err := c.Call(ctx, manualOperationID(700), request); err != nil || !cached {
		t.Fatal("full capacity blocked cached operation")
	}
	if appends != 32 || repo.appendCalls != appends || repo.readCalls != reads || manualCounts(t, h) != counts || h.clockCalls != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 {
		t.Fatal("capacity/replay/reentry acquired dependencies")
	}
}
func TestJournalAdapterFailReadAndReturnedUseOriginalSharedCleanupContext(t *testing.T) {
	type valueKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), valueKey{}, "owned-cleanup"))
	defer cancel()
	db := contractStore(t, true)
	h := harness(t, db)
	h.repo.onBegin = cancel
	repo := &faultJournalRepository{JournalRepository: db}
	repo.appendHook = func(_ context.Context, request *enrichmentjournal.AppendRequest, _ *enrichmentjournal.Acknowledgement, err *error) {
		if request.Checkpoint.Stage == enrichmentjournal.Fail {
			*err = errors.New("PRIVATE-fail-postcommit")
		}
	}
	c, err := NewJournalManualController(h.service, repo)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := c.Call(ctx, manualOperationID(650), Request{Connector: "epss_feed", Limit: 200})
	if err != nil || op.Result.Outcome != "failed" || op.Result.Code != "canceled" || h.fetchCalls != 0 || h.clockCalls != 2 || h.uuidCalls != 1 || repo.appendCalls != 4 || repo.readCalls != 1 {
		t.Fatalf("cleanup acknowledgement failed: %+v %v", op, err)
	}
	if len(h.repo.cleanupContexts) != 1 || repo.appendContexts[2] != repo.readContexts[0] || repo.appendContexts[2] != repo.appendContexts[3] || repo.appendContexts[2] != h.repo.cleanupContexts[0] {
		t.Fatal("adapter renewed or replaced cleanup context")
	}
	cleanup := repo.readContexts[0]
	deadline, ok := cleanup.Deadline()
	if !ok || cleanup.Value(valueKey{}) != "owned-cleanup" || time.Until(deadline) > cleanupBudget {
		t.Fatal("shared cleanup has no original bounded deadline")
	}
	select {
	case <-cleanup.Done():
	default:
		t.Fatal("cleanup not released")
	}
}
