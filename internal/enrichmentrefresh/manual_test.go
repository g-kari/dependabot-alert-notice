package enrichmentrefresh

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestManualControllerContractResponseLossReplaysWithoutServiceIO(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	controller, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := "40000000-0000-4000-8000-000000000001"
	request := Request{Connector: "epss_feed", Limit: 200}
	first, replay, err := controller.Call(context.Background(), id, request)
	if err != nil {
		t.Fatalf("manual controller call failed: %v", err)
	}
	if replay || first.OperationID != id || first.Request != request || first.State != "resolved" || first.Result.Outcome != "success" || first.Result.RunID == id || !first.Result.Advance {
		t.Fatalf("first manual operation=%+v replay=%v", first, replay)
	}
	// Simulate a lost outer response: retry the same operation/request instead
	// of inventing a service UUID, source clock or replacement operation.
	again, replay, err := controller.Call(context.Background(), id, request)
	if err != nil || !replay || !reflect.DeepEqual(again, first) {
		t.Fatalf("response-loss replay=%+v replay=%v err=%v", again, replay, err)
	}
	if h.uuidCalls != 1 || h.fetchCalls != 1 || h.clockCalls != 3 || h.repo.calls["begin"] != 1 || h.repo.calls["complete"] != 1 {
		t.Fatalf("cached replay repeated service work: uuid=%d fetch=%d clock=%d calls=%v", h.uuidCalls, h.fetchCalls, h.clockCalls, h.repo.calls)
	}
}

func TestManualControllerContractPendingAndSnapshotKeepOwnedFullCompletion(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	h.repo.completeAfter, h.repo.reconcileError = true, true
	controller, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := "40000000-0000-4000-8000-000000000002"
	request := Request{Connector: "epss_feed", Limit: 200}
	first, replay, err := controller.Call(context.Background(), id, request)
	if !errors.Is(err, ErrPending) || replay || first.State != "pending" || first.Result.Pending == nil || first.Result.Pending.Completion == nil {
		t.Fatalf("manual controller pending failed: %+v replay=%v err=%v", first, replay, err)
	}
	want := h.repo.completeJSON
	wantPending := jsonValue(t, first.Result.Pending)
	if jsonValue(t, first.Result.Pending.Completion) != want {
		t.Fatal("returned pending lost full prepared completion")
	}
	first.Result.Pending.Completion.OriginalDigest = "caller-mutated"
	first.Result.Pending.Attempt.Targets[0].CVEID = "CVE-2026-9999"
	snapshot, ok := controller.Snapshot(id)
	if !ok || snapshot.Result.Pending == nil || jsonValue(t, snapshot.Result.Pending) != wantPending || jsonValue(t, snapshot.Result.Pending.Completion) != want {
		t.Fatal("caller mutation damaged retained full completion")
	}
	snapshot.Result.Pending.Completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
	*snapshot.Result.Pending.Completion.Feed.Entries[0].EPSS = 1
	again, replay, err := controller.Call(context.Background(), id, request)
	if !errors.Is(err, ErrPending) || !replay || again.Result.Pending == nil || jsonValue(t, again.Result.Pending) != wantPending || jsonValue(t, again.Result.Pending.Completion) != want {
		t.Fatalf("owned snapshot/replay lost pending: %+v replay=%v err=%v", again, replay, err)
	}
	if h.uuidCalls != 1 || h.fetchCalls != 1 || h.clockCalls != 3 || h.repo.calls["complete"] != 1 || h.repo.calls["reconcile"] != 1 {
		t.Fatalf("pending replay performed service/readback I/O: %v", h.repo.calls)
	}
}

func TestManualControllerContractBeginReadbackNeverAcquiresFetchOwnership(t *testing.T) {
	db := contractStore(t, true)
	h := harness(t, db)
	h.repo.beginAfter = true
	controller, err := NewManualController(h.service)
	if err != nil {
		t.Fatal(err)
	}
	id := "40000000-0000-4000-8000-000000000003"
	first, _, err := controller.Call(context.Background(), id, Request{Connector: "epss_feed", Limit: 200})
	if !errors.Is(err, ErrPending) || first.Result.Pending == nil || first.Result.Pending.Completion != nil {
		t.Fatalf("manual controller Begin pending failed: %+v err=%v", first, err)
	}
	kept := jsonValue(t, first.Result.Pending)
	again, err := controller.Reconcile(context.Background(), id)
	if !errors.Is(err, ErrPending) || again.State != "pending" || jsonValue(t, again.Result.Pending) != kept || again.Result.Advance {
		t.Fatalf("running readback changed ownership: %+v err=%v", again, err)
	}
	if h.uuidCalls != 1 || h.fetchCalls != 0 || h.clockCalls != 1 || h.repo.calls["begin"] != 1 || h.repo.calls["read"] != 2 || h.repo.calls["fail"] != 0 || h.repo.calls["complete"] != 0 {
		t.Fatalf("manual Begin readback started replacement work: %v", h.repo.calls)
	}
}
