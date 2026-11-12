package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRefreshAttemptReadbackContractMissingAndSameUUIDRunningRecovery(t *testing.T) {
	s, completion := refreshContractFixture(t, "epss", 1001)
	ctx := context.Background()
	state, err := s.ReadSecurityEnrichmentRefreshAttempt(ctx, completion.Attempt, nil)
	if err != nil || state.State != "missing" || state.Receipt != "" {
		t.Fatalf("missing attempt readback=%+v err=%v", state, err)
	}
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, completion.Attempt); err != nil {
		t.Fatal(err)
	}
	state, err = s.ReadSecurityEnrichmentRefreshAttempt(ctx, completion.Attempt, nil)
	if err != nil || state.State != "running" || state.Receipt != "" {
		t.Fatalf("same-UUID reservation readback=%+v err=%v", state, err)
	}
	failure := &SecurityEnrichmentRefreshFailure{Code: "fetch_failed", FinishedAt: completion.FinishedAt}
	state, err = s.ReadSecurityEnrichmentRefreshAttempt(ctx, completion.Attempt, failure)
	if err != nil || state.State != "running" || state.Receipt != "" {
		t.Fatalf("uncommitted expected failure readback=%+v err=%v", state, err)
	}
}

func TestRefreshAttemptReadbackContractConfirmsOnlyExactFailure(t *testing.T) {
	s, completion := refreshContractFixture(t, "kev", 1002)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, completion.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FailSecurityEnrichmentRefresh(ctx, completion.Attempt, "parse_failed", completion.FinishedAt); err != nil {
		t.Fatal(err)
	}
	failure := &SecurityEnrichmentRefreshFailure{Code: "parse_failed", FinishedAt: completion.FinishedAt}
	state, err := s.ReadSecurityEnrichmentRefreshAttempt(ctx, completion.Attempt, failure)
	if err != nil || state.State != "failed" || state.Receipt != "" {
		t.Fatalf("exact failure readback=%+v err=%v", state, err)
	}
	zone := time.FixedZone("same instant", 9*60*60)
	failure.FinishedAt = failure.FinishedAt.In(zone)
	state, err = s.ReadSecurityEnrichmentRefreshAttempt(ctx, completion.Attempt, failure)
	if err != nil || state.State != "failed" {
		t.Fatalf("equivalent UTC failure readback=%+v err=%v", state, err)
	}
	for _, expected := range []*SecurityEnrichmentRefreshFailure{
		nil,
		{Code: "fetch_failed", FinishedAt: completion.FinishedAt},
		{Code: "parse_failed", FinishedAt: completion.FinishedAt.Add(time.Nanosecond)},
	} {
		state, err := s.ReadSecurityEnrichmentRefreshAttempt(ctx, completion.Attempt, expected)
		if err != nil && !errors.Is(err, ErrIngestConflict) {
			t.Fatalf("unexpected collision readback error=%v", err)
		}
		if state.State != "unknown" || state.Receipt != "" {
			t.Fatalf("mismatched/unprovided failure established outcome=%+v", state)
		}
	}
}

func TestRefreshAttemptReadbackContractCannotEstablishCompletedSuccess(t *testing.T) {
	s, completion := refreshContractFixture(t, "epss", 1003)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, completion.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, completion); err != nil {
		t.Fatal(err)
	}
	state, err := s.ReadSecurityEnrichmentRefreshAttempt(ctx, completion.Attempt, nil)
	if err != nil || state.State != "unknown" || state.Receipt != "" {
		t.Fatalf("attempt-only reader must not establish success=%+v err=%v", state, err)
	}
	full, err := s.ReconcileSecurityEnrichmentRefresh(ctx, completion)
	if err != nil || full.State != "success" || full.Receipt == "" {
		t.Fatalf("existing full-completion verification changed=%+v err=%v", full, err)
	}
}
