package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

func refreshContractFixture(t *testing.T, source string, id int) (*Store, SecurityEnrichmentRefreshCompletion) {
	t.Helper()
	s := newConnectorStatusStore(t)
	run, item := importFixture()
	if _, err := s.ImportSecurityFindings(context.Background(), run, []model.SecurityFinding{item}); err != nil {
		t.Fatal(err)
	}
	page, err := s.QuerySecurityEnrichmentRefreshTargets(context.Background(), "", 200)
	if err != nil || len(page.Targets) != 1 {
		t.Fatalf("refresh fixture page=%+v err=%v", page, err)
	}
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	_, feed := enrichmentFixture(t, id, source, at.Add(-time.Hour), at)
	scope, err := threat.OfflineSelectionScope(feed.SelectedCVEs)
	if err != nil {
		t.Fatal(err)
	}
	return s, SecurityEnrichmentRefreshCompletion{Attempt: SecurityEnrichmentRefreshAttempt{RunID: fmt.Sprintf("10000000-0000-4000-8000-%012d", id), Connector: source + "_feed", Scope: scope, StartedAt: at.Add(-time.Minute), Targets: page.Targets}, Feed: feed, OriginalDigest: "sha256:" + strings.Repeat("a", 64), FinishedAt: at.Add(time.Minute)}
}

func TestSecurityEnrichmentRefreshContractSameUUIDAtomicSuccessAndReplay(t *testing.T) {
	s, completion := refreshContractFixture(t, "epss", 901)
	ctx := context.Background()
	if replay, err := s.BeginSecurityEnrichmentRefresh(ctx, completion.Attempt); err != nil || replay {
		t.Fatalf("begin replay=%v err=%v", replay, err)
	}
	result, err := s.CompleteSecurityEnrichmentRefresh(ctx, completion)
	if err != nil || result.Replay || result.Entries != 1 {
		t.Fatalf("complete=%+v err=%v", result, err)
	}
	result, err = s.CompleteSecurityEnrichmentRefresh(ctx, completion)
	if err != nil || !result.Replay || result.Entries != 1 {
		t.Fatalf("same-ID replay=%+v err=%v", result, err)
	}
	state, err := s.ReconcileSecurityEnrichmentRefresh(ctx, completion)
	if err != nil || state.State != "success" || state.Receipt == "" {
		t.Fatalf("same-ID readback=%+v err=%v", state, err)
	}
	var observations, manifests int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM security_enrichment_observations WHERE ingest_run_id=?`, completion.Attempt.RunID).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM security_enrichment_runs WHERE ingest_run_id=?`, completion.Attempt.RunID).Scan(&manifests); err != nil || observations != 1 || manifests != 1 {
		t.Fatalf("atomic writes observations=%d manifests=%d err=%v", observations, manifests, err)
	}
}

func TestSecurityEnrichmentRefreshContractFailureDoesNotBecomeSuccess(t *testing.T) {
	s, completion := refreshContractFixture(t, "kev", 902)
	ctx := context.Background()
	if _, err := s.BeginSecurityEnrichmentRefresh(ctx, completion.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FailSecurityEnrichmentRefresh(ctx, completion.Attempt, "fetch_failed", completion.FinishedAt); err != nil {
		t.Fatal(err)
	}
	state, err := s.ReconcileSecurityEnrichmentRefresh(ctx, completion)
	if err != nil || state.State != "failed" || state.Receipt != "" {
		t.Fatalf("failure readback=%+v err=%v", state, err)
	}
	if _, err := s.CompleteSecurityEnrichmentRefresh(ctx, completion); err == nil {
		t.Fatal("failed attempt accepted completion")
	}
}
