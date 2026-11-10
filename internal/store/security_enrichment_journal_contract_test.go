package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func TestOperationJournalContractAtomicBindingCASAndExactPersistentReplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned-operation-journal.sqlite")
	db, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			if err := db.Close(); err != nil {
				t.Errorf("close owned SQLite: %v", err)
			}
		}
	})
	at := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	legacy, err := db.StartIngestRun(ctx, "dependabot", "synthetic/journal-preserved", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.FinishIngestRun(ctx, legacy.ID, "success", "partial", "", at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	before, err := db.QueryIngestRuns(ctx)
	if err != nil || len(before) == 0 {
		t.Fatal("non-empty old receipt fixture missing")
	}
	reserved := enrichmentjournal.Checkpoint{
		Version: enrichmentjournal.Version, OperationID: "82000000-0000-4000-8000-000000000001",
		Request: enrichmentjournal.Request{Connector: "epss_feed", Limit: 200}, Stage: enrichmentjournal.Reserved,
	}
	first := enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: reserved}
	ack, err := db.AppendSecurityEnrichmentCheckpoint(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if ack.OperationID != reserved.OperationID || ack.Sequence != 1 || ack.Replay || !strings.HasPrefix(ack.Digest, "sha256:") || len(ack.Digest) != 71 {
		t.Fatalf("journal acknowledgement lost binding: %+v", ack)
	}
	replay, err := db.AppendSecurityEnrichmentCheckpoint(ctx, first)
	if err != nil || !replay.Replay || replay.Digest != ack.Digest || replay.Sequence != ack.Sequence {
		t.Fatalf("exact append replay changed receipt: %+v %v", replay, err)
	}
	mismatch := first
	mismatch.Checkpoint.Request.Limit = 1
	if _, err := db.AppendSecurityEnrichmentCheckpoint(ctx, mismatch); err == nil {
		t.Fatal("same operation/sequence accepted different content")
	}
	cves, err := json.Marshal([]string{"CVE-2026-1234"})
	if err != nil {
		t.Fatal(err)
	}
	begin := reserved
	begin.Stage = enrichmentjournal.Begin
	begin.Progress = enrichmentjournal.Progress{
		RunID: "83000000-0000-4000-8000-000000000001", Scanned: 1, Targets: 1, ScanAfter: "finding-001", Pending: true,
	}
	begin.Prepared = &enrichmentjournal.Prepared{Attempt: enrichmentjournal.Attempt{
		RunID: begin.Progress.RunID, Connector: reserved.Request.Connector, StartedAt: at.Add(24 * time.Hour),
		Scope:   fmt.Sprintf("cves-sha256:%x", sha256.Sum256(cves)),
		Targets: []enrichmentjournal.Target{{FindingID: "finding-001", CVEID: "CVE-2026-1234", Revision: strings.Repeat("a", 64)}},
	}}
	second := enrichmentjournal.AppendRequest{Sequence: 2, PreviousDigest: "sha256:" + strings.Repeat("f", 64), Checkpoint: begin}
	if _, err := db.AppendSecurityEnrichmentCheckpoint(ctx, second); err == nil {
		t.Fatal("wrong previous head bypassed CAS")
	}
	second.PreviousDigest = ack.Digest
	next, err := db.AppendSecurityEnrichmentCheckpoint(ctx, second)
	if err != nil || next.Sequence != 2 || next.Replay || next.Digest == ack.Digest {
		t.Fatalf("valid CAS append failed: %+v %v", next, err)
	}
	collision := second
	prepared := *begin.Prepared
	prepared.Attempt.RunID = "83000000-0000-4000-8000-000000000002"
	collision.Checkpoint.Prepared = &prepared
	collision.Checkpoint.Progress.RunID = prepared.Attempt.RunID
	if _, err := db.AppendSecurityEnrichmentCheckpoint(ctx, collision); err == nil {
		t.Fatal("operation UUID binding changed")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := db.AppendSecurityEnrichmentCheckpoint(ctx, second)
	if err != nil || !persisted.Replay || persisted.Sequence != next.Sequence || persisted.Digest != next.Digest {
		t.Fatalf("reopen did not preserve exact checkpoint identity: %+v %v", persisted, err)
	}
	oldReplay, err := db.AppendSecurityEnrichmentCheckpoint(ctx, first)
	if err != nil || !oldReplay.Replay || oldReplay.Digest != ack.Digest {
		t.Fatal("historical exact replay lost immutable acknowledgement")
	}
	fail := begin
	p := *begin.Prepared
	p.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: begin.Prepared.Attempt.StartedAt.Add(time.Minute)}
	fail.Stage, fail.Prepared = enrichmentjournal.Fail, &p
	third, err := db.AppendSecurityEnrichmentCheckpoint(ctx, enrichmentjournal.AppendRequest{Sequence: 3, PreviousDigest: next.Digest, Checkpoint: fail})
	if err != nil || third.Sequence != 3 || third.Replay {
		t.Fatalf("historical replay rewound operation head: %+v %v", third, err)
	}
	after, err := db.QueryIngestRuns(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("journal append mutated existing receipt or created a common attempt")
	}
}
