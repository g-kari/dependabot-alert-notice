package enrichmentrefresh

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPreservationRejectsNilSinkAndInvalidDependenciesWithoutIO(t *testing.T) {
	h := harness(t, contractStore(t, false))
	var typedNil preservationSinkFunc
	for _, sink := range []PreservationSink{nil, typedNil} {
		if _, err := NewPreservingManualController(h.service, sink); !errors.Is(err, ErrManualInvalid) {
			t.Fatalf("nil sink accepted: %v", err)
		}
	}
	sinkCalls := 0
	sink := preservationSinkFunc(func(context.Context, PreservationCheckpoint) error {
		sinkCalls++
		return nil
	})
	bad := h.service
	bad.Clock = nil
	if _, err := NewPreservingManualController(bad, sink); !errors.Is(err, ErrManualInvalid) {
		t.Fatalf("missing explicit Service dependency accepted: %v", err)
	}
	if h.clockCalls != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 || len(h.repo.calls) != 0 || sinkCalls != 0 {
		t.Fatal("constructor performed dependency I/O")
	}
}

func privatePreservationJSON(t *testing.T, controller *ManualController, id string) string {
	t.Helper()
	controller.mu.Lock()
	defer controller.mu.Unlock()
	record := controller.operations[id]
	if record == nil {
		t.Fatal("private reservation missing")
	}
	return jsonValue(t, record.checkpoint) + "/" + jsonValue(t, record.retained)
}

func mutatePreservationPending(pending *Pending) {
	if pending == nil {
		return
	}
	if len(pending.Attempt.Targets) != 0 {
		pending.Attempt.Targets[0].FindingID = "PRIVATE-late-target"
	}
	if pending.ExpectedFailure != nil {
		pending.ExpectedFailure.Code = "PRIVATE-late-failure"
		pending.ExpectedFailure.FinishedAt = pending.ExpectedFailure.FinishedAt.Add(time.Hour)
	}
	if pending.Completion != nil {
		completion := pending.Completion
		if len(completion.Attempt.Targets) != 0 {
			completion.Attempt.Targets[0].Revision = strings.Repeat("f", 64)
		}
		if len(completion.Feed.SelectedCVEs) != 0 {
			completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
		}
		if len(completion.Feed.Entries) != 0 {
			entry := &completion.Feed.Entries[0]
			if entry.EPSS != nil {
				*entry.EPSS = 1
			}
			if entry.Percentile != nil {
				*entry.Percentile = 1
			}
			if entry.KEVDateAdded != nil {
				*entry.KEVDateAdded = entry.KEVDateAdded.Add(time.Hour)
			}
		}
	}
}

func TestPreservationSinkArgumentsRemainDetachedAfterReturnAndRecovery(t *testing.T) {
	for _, kind := range []string{"failure", "epss-completion", "kev-completion"} {
		t.Run(kind, func(t *testing.T) {
			h := harness(t, contractStore(t, true))
			request := Request{Connector: "epss_feed", Limit: 200}
			if kind == "failure" {
				h.fetchError = errors.New("PRIVATE-synthetic-fetch-error")
				h.repo.failAfter, h.repo.readError = true, true
			} else {
				h.repo.completeAfter, h.repo.reconcileError = true, true
				if kind == "kev-completion" {
					request.Connector = "kev_feed"
					h.service.Fetcher = fetchFunc(func(_ context.Context, source string) ([]byte, error) {
						h.fetchCalls++
						if source != "kev" {
							t.Fatal("incorrect domain source")
						}
						return []byte("{\"catalogVersion\":\"synthetic-preservation\",\"dateReleased\":\"2026-11-10T00:00:00Z\",\"count\":1,\"vulnerabilities\":[{\"cveID\":\"CVE-2026-1234\",\"dateAdded\":\"2026-11-09\"}]}"), nil
					})
				}
			}
			var arguments []PreservationCheckpoint
			c, err := NewPreservingManualController(h.service, preservationSinkFunc(func(_ context.Context, checkpoint PreservationCheckpoint) error {
				arguments = append(arguments, checkpoint)
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			id := manualOperationID(230)
			op, _, err := c.Call(context.Background(), id, request)
			if !errors.Is(err, ErrPending) || op.Result.Pending == nil {
				t.Fatalf("ambiguous real Store write not retained: %+v %v", op, err)
			}
			private, public := privatePreservationJSON(t, c, id), jsonValue(t, op)
			for i := range arguments {
				mutatePreservationPending(arguments[i].Prepared)
				mutatePreservationPending(arguments[i].Result.Pending)
				arguments[i].Request.Connector = "PRIVATE-source"
				arguments[i].Result.NextAfter = "PRIVATE-cursor"
			}
			mutatePreservationPending(op.Result.Pending)
			snapshot, ok := c.Snapshot(id)
			if !ok || jsonValue(t, snapshot) != public || privatePreservationJSON(t, c, id) != private {
				t.Fatal("late hook/caller mutation changed owned original")
			}
			clock, uuid, fetch := h.clockCalls, h.uuidCalls, h.fetchCalls
			begin, fail, complete := h.repo.calls["begin"], h.repo.calls["fail"], h.repo.calls["complete"]
			checkpoints := len(arguments)
			h.repo.readError, h.repo.reconcileError = false, false
			resolved, err := c.Reconcile(context.Background(), id)
			if err != nil || resolved.State != "resolved" || resolved.Result.Pending != nil || len(arguments) != checkpoints+1 || arguments[len(arguments)-1].Stage != PreserveReturned {
				t.Fatalf("exact real Store readback was not preserved before resolution: %+v %v", resolved, err)
			}
			if kind == "failure" {
				if resolved.Result.Outcome != "failed" || resolved.Result.Code != "fetch_failed" || resolved.Result.Advance {
					t.Fatal("late failure pointer mutation supplied resolved values")
				}
			} else if resolved.Result.Outcome != "success" || !resolved.Result.Advance || resolved.Result.NextAfter != snapshot.Result.ScanAfter {
				t.Fatal("late completion pointer mutation supplied resolved values")
			}
			if h.clockCalls != clock || h.uuidCalls != uuid || h.fetchCalls != fetch || h.repo.calls["begin"] != begin || h.repo.calls["fail"] != fail || h.repo.calls["complete"] != complete {
				t.Fatal("readback regenerated or rewrote prepared values")
			}
			private = privatePreservationJSON(t, c, id)
			mutatePreservationPending(arguments[len(arguments)-1].Prepared)
			counts := manualCounts(t, h)
			again, cached, err := c.Call(context.Background(), id, request)
			if err != nil || !cached || !reflect.DeepEqual(again, resolved) || manualCounts(t, h) != counts || privatePreservationJSON(t, c, id) != private || strings.Contains(jsonValue(t, again), "PRIVATE") {
				t.Fatal("resolved checkpoint alias affected cached replay")
			}
		})
	}
}

func TestPreservationCanceledOrExpiredAcknowledgementNeverGrantsWrite(t *testing.T) {
	for _, stage := range []PreservationStage{PreserveReserved, PreserveBegin, PreserveComplete, PreserveReturned} {
		t.Run(string(stage), func(t *testing.T) {
			h := harness(t, contractStore(t, true))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, err := NewPreservingManualController(h.service, preservationSinkFunc(func(_ context.Context, checkpoint PreservationCheckpoint) error {
				if checkpoint.Stage == stage {
					cancel()
				}
				return nil // Losing the context before acknowledgement is unknown.
			}))
			if err != nil {
				t.Fatal(err)
			}
			id := manualOperationID(240)
			request := Request{Connector: "epss_feed", Limit: 200}
			op, _, err := c.Call(ctx, id, request)
			if !errors.Is(err, ErrPending) || op.State != "pending" || op.Result.Code != "preservation_unknown" || op.Result.Advance || op.Result.NextAfter != request.After {
				t.Fatalf("canceled acknowledgement published progress: %+v %v", op, err)
			}
			wantBegin, wantComplete := 0, 0
			if stage == PreserveComplete || stage == PreserveReturned {
				wantBegin = 1
			}
			if stage == PreserveReturned {
				wantComplete = 1 // This preceding write was acknowledged.
			}
			if h.repo.calls["begin"] != wantBegin || h.repo.calls["complete"] != wantComplete || h.repo.calls["fail"] != 0 {
				t.Fatal("cancelled acknowledgement authorized another Store write")
			}
			counts := manualCounts(t, h)
			if _, err := c.Reconcile(context.Background(), id); !errors.Is(err, ErrPending) || manualCounts(t, h) != counts {
				t.Fatal("fresh read context cleared preservation uncertainty")
			}
		})
	}
	t.Run("already-expired-deadline", func(t *testing.T) {
		h := harness(t, contractStore(t, true))
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		sinkCalls := 0
		c, err := NewPreservingManualController(h.service, preservationSinkFunc(func(context.Context, PreservationCheckpoint) error {
			sinkCalls++
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		op, _, err := c.Call(ctx, manualOperationID(241), Request{Connector: "epss_feed", Limit: 200})
		if !errors.Is(err, context.DeadlineExceeded) || op.Result.Advance || len(h.repo.calls) != 0 || sinkCalls != 0 || h.clockCalls != 0 || h.fetchCalls != 0 || h.uuidCalls != 0 {
			t.Fatalf("expired context entered preservation or Service: %+v %v", op, err)
		}
	})

}

func TestPreservationFailureAndReturnShareOneExistingCleanupBudget(t *testing.T) {
	type valueKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), valueKey{}, "owned"))
	defer cancel()
	h := harness(t, contractStore(t, true))
	h.repo.onBegin = cancel
	var cleanupContexts []context.Context
	c, err := NewPreservingManualController(h.service, preservationSinkFunc(func(checkpointCtx context.Context, checkpoint PreservationCheckpoint) error {
		if checkpoint.Stage == PreserveFail || checkpoint.Stage == PreserveReturned {
			cleanupContexts = append(cleanupContexts, checkpointCtx)
			deadline, ok := checkpointCtx.Deadline()
			if !ok || checkpointCtx.Err() != nil || checkpointCtx.Value(valueKey{}) != "owned" || time.Until(deadline) > cleanupBudget || checkpointCtx == ctx {
				t.Fatal("preservation failed to reuse bounded uncancelled cleanup")
			}
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := c.Call(ctx, manualOperationID(250), Request{Connector: "epss_feed", Limit: 200})
	if err != nil || op.Result.Outcome != "failed" || op.Result.Code != "canceled" || op.Result.Advance || h.fetchCalls != 0 || h.clockCalls != 2 || h.uuidCalls != 1 || h.repo.calls["fail"] != 1 {
		t.Fatalf("cancel cleanup did not preserve exact existing failure: %+v %v", op, err)
	}
	if len(cleanupContexts) != 2 || len(h.repo.cleanupContexts) != 1 || cleanupContexts[0] != cleanupContexts[1] || cleanupContexts[0] != h.repo.cleanupContexts[0] {
		t.Fatal("Fail/returned preservation renewed the cleanup context/deadline")
	}
	select {
	case <-cleanupContexts[0].Done():
	default:
		t.Fatal("shared cleanup context was not canceled on exit")
	}
}

func TestPreservationReadonlyResolutionCannotBypassUnknownTerminalAck(t *testing.T) {
	h := harness(t, contractStore(t, true))
	h.repo.completeAfter, h.repo.reconcileError = true, true
	sinkCalls, denyTerminal := 0, false
	c, err := NewPreservingManualController(h.service, preservationSinkFunc(func(_ context.Context, checkpoint PreservationCheckpoint) error {
		sinkCalls++
		if denyTerminal && checkpoint.Stage == PreserveReturned && checkpoint.Result.Outcome == "success" {
			return errors.New("PRIVATE-terminal-acknowledgement-unknown")
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := manualOperationID(260)
	request := Request{Connector: "epss_feed", Limit: 200}
	first, _, err := c.Call(context.Background(), id, request)
	if !errors.Is(err, ErrPending) || first.Result.Pending == nil || first.Result.Pending.Completion == nil {
		t.Fatal("expected pending completion")
	}
	h.repo.reconcileError, denyTerminal = false, true
	op, err := c.Reconcile(context.Background(), id)
	if !errors.Is(err, ErrPending) || op.State != "pending" || op.Result.Code != "preservation_unknown" || op.Result.Advance || !reflect.DeepEqual(op.Result.Pending, first.Result.Pending) {
		t.Fatalf("Store success bypassed terminal preservation: %+v %v", op, err)
	}
	counts, checkpoints := manualCounts(t, h), sinkCalls
	if _, err := c.Reconcile(context.Background(), id); !errors.Is(err, ErrPending) {
		t.Fatal("unknown terminal preservation was silently retried")
	}
	again, cached, err := c.Call(context.Background(), id, request)
	if !errors.Is(err, ErrPending) || !cached || !reflect.DeepEqual(again, op) || manualCounts(t, h) != counts || sinkCalls != checkpoints || h.repo.calls["complete"] != 1 || h.repo.calls["fail"] != 0 {
		t.Fatal("unknown terminal recovery refetched/rewrote/retried")
	}
}

func TestPreservationKeepsSixteenRecordNonEvictionAndCachedReplay(t *testing.T) {
	h := harness(t, contractStore(t, false))
	sinkCalls := 0
	c, err := NewPreservingManualController(h.service, preservationSinkFunc(func(context.Context, PreservationCheckpoint) error {
		sinkCalls++
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := Request{Connector: "epss_feed", Limit: 1}
	var first ManualOperation
	for i := 0; i < 16; i++ {
		op, replay, err := c.Call(context.Background(), manualOperationID(300+i), request)
		if err != nil || replay || op.Result.RunID != "" || !op.Result.Exhausted {
			t.Fatalf("zero-run operation did not retain its bounded slot: %+v %v", op, err)
		}
		if i == 0 {
			first = op
		}
	}
	counts, checkpoints := manualCounts(t, h), sinkCalls
	replay, cached, err := c.Call(context.Background(), manualOperationID(300), request)
	if err != nil || !cached || !reflect.DeepEqual(replay, first) {
		t.Fatal("full capacity blocked existing cached replay")
	}
	if _, _, err := c.Call(context.Background(), manualOperationID(300), Request{Connector: "epss_feed", Limit: 2}); !errors.Is(err, ErrManualConflict) {
		t.Fatal("full capacity bypassed exact operation binding")
	}
	if _, _, err := c.Call(context.Background(), manualOperationID(316), request); !errors.Is(err, ErrManualCapacity) {
		t.Fatal("preserving controller evicted a retained operation")
	}
	if manualCounts(t, h) != counts || sinkCalls != checkpoints || sinkCalls != 32 || h.clockCalls != 0 || h.uuidCalls != 0 || h.fetchCalls != 0 {
		t.Fatal("capacity/replay rejection performed dependency or sink I/O")
	}
}

func TestPreservationLateBeginArgumentMutationCannotChangeLaterStoreWrite(t *testing.T) {
	h := harness(t, contractStore(t, true))
	var beginArgument PreservationCheckpoint
	var preservedCompletion *Pending
	c, err := NewPreservingManualController(h.service, preservationSinkFunc(func(_ context.Context, checkpoint PreservationCheckpoint) error {
		if checkpoint.Stage == PreserveBegin {
			beginArgument = checkpoint // Keep the actual sink argument after return.
		}
		if checkpoint.Stage == PreserveComplete {
			preservedCompletion = cloneManualPending(checkpoint.Prepared)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	h.fetchHook = func(context.Context) {
		// Begin's Preserve has returned and the real reservation already exists.
		// Mutation must not reach the still-running Service or later Complete.
		mutatePreservationPending(beginArgument.Prepared)
		mutatePreservationPending(beginArgument.Result.Pending)
	}
	op, _, err := c.Call(context.Background(), manualOperationID(330), Request{Connector: "epss_feed", Limit: 200})
	if err != nil || op.Result.Outcome != "success" || preservedCompletion == nil || preservedCompletion.Completion == nil {
		t.Fatalf("late hook mutation affected real subsequent completion: %+v %v", op, err)
	}
	if jsonValue(t, preservedCompletion.Attempt) != h.repo.beginJSON || jsonValue(t, preservedCompletion.Completion.Attempt) != h.repo.beginJSON || jsonValue(t, *preservedCompletion.Completion) != h.repo.completeJSON {
		t.Fatal("prepared attempt/Completion changed after earlier sink returned")
	}
}
