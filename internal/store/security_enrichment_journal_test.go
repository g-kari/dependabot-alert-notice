package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func journalStoreFrames(t *testing.T) []enrichmentjournal.Checkpoint {
	t.Helper()
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	r := enrichmentjournal.Checkpoint{Version: 1, OperationID: "84000000-0000-4000-8000-000000000001",
		Request: enrichmentjournal.Request{Connector: "epss_feed", Limit: 200}, Stage: enrichmentjournal.Reserved}
	begin := r
	begin.Stage = enrichmentjournal.Begin
	begin.Progress = enrichmentjournal.Progress{RunID: "85000000-0000-4000-8000-000000000001", Scanned: 1, Targets: 1, ScanAfter: "finding-001", Pending: true}
	selected := []string{"CVE-2026-1234"}
	data, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	begin.Prepared = &enrichmentjournal.Prepared{Attempt: enrichmentjournal.Attempt{RunID: begin.Progress.RunID, Connector: r.Request.Connector, Scope: fmt.Sprintf("cves-sha256:%x", sha256.Sum256(data)), StartedAt: at,
		Targets: []enrichmentjournal.Target{{FindingID: "finding-001", CVEID: selected[0], Revision: strings.Repeat("a", 64)}}}}
	complete := begin
	p := *begin.Prepared
	zero := 0.0
	p.Completion = &enrichmentjournal.Completion{Feed: enrichmentjournal.Feed{Source: "epss", Version: "synthetic-store-journal", PublishedAt: at.Add(-12 * time.Hour), ObservedAt: at.Add(time.Minute), SelectedCVEs: selected, Entries: []enrichmentjournal.Entry{{CVEID: selected[0], EPSS: &zero, Percentile: &zero}}}, OriginalDigest: "sha256:" + strings.Repeat("b", 64), FinishedAt: at.Add(2 * time.Minute)}
	complete.Stage, complete.Prepared = enrichmentjournal.Complete, &p
	pending := complete
	pending.Stage, pending.Progress.Outcome, pending.Progress.Code = enrichmentjournal.Returned, "pending", "completion_unknown"
	success := pending
	success.Progress.Outcome, success.Progress.Code, success.Progress.Pending = "success", "", false
	success.Progress.Advance, success.Progress.NextAfter = true, success.Progress.ScanAfter
	return []enrichmentjournal.Checkpoint{r, begin, complete, pending, success}
}

func journalOwnedStore(t *testing.T) *Store {
	t.Helper()
	db, err := NewWithPath(filepath.Join(t.TempDir(), "owned-journal.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close journal fixture: %v", err)
		}
	})
	return db
}

func journalSnapshot(t *testing.T, db *Store, oldOnly bool) string {
	t.Helper()
	rows, err := db.db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	values := map[string][][]any{}
	for _, name := range names {
		if oldOnly && (name == "security_enrichment_operations" || name == "security_enrichment_checkpoints") {
			continue
		}
		query := `SELECT * FROM "` + strings.ReplaceAll(name, `"`, `""`) + `"`
		if oldOnly && name == "app_migrations" {
			query += " WHERE version<>4"
		}
		if name == "security_enrichment_release_certificates" {
			query += " ORDER BY operation_id"
		} else {
			query += " ORDER BY rowid"
		}
		r, err := db.db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		columns, err := r.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for r.Next() {
			if len(values[name]) >= 1000 {
				t.Fatal("unexpectedly large synthetic fixture")
			}
			row := make([]any, len(columns))
			args := make([]any, len(columns))
			for i := range row {
				args[i] = &row[i]
			}
			if err := r.Scan(args...); err != nil {
				t.Fatal(err)
			}
			values[name] = append(values[name], row)
		}
		if err := r.Err(); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func appendJournalFrame(t *testing.T, db *Store, frame enrichmentjournal.Checkpoint, seq int64, previous string) enrichmentjournal.Acknowledgement {
	t.Helper()
	ack, err := db.AppendSecurityEnrichmentCheckpoint(context.Background(), enrichmentjournal.AppendRequest{Sequence: seq, PreviousDigest: previous, Checkpoint: frame})
	if err != nil {
		t.Fatal(err)
	}
	return ack
}

func TestOperationJournalUpgradeReconstructedOldSchemaPreservesRows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "owned-upgrade.sqlite")
	db, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			if err := db.Close(); err != nil {
				t.Errorf("close upgrade: %v", err)
			}
		}
	})
	at := time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	_, err = db.SaveObservedWithError(ctx, &model.AlertRecord{Alert: model.Alert{Owner: "example", Repo: "journal-upgrade", Number: 1, State: "open", CVEID: "CVE-2026-1234", PackageName: "synthetic", PackageEcosystem: "npm", Summary: "Owned migration fixture", Severity: model.SeverityHigh, CreatedAt: at, UpdatedAt: at, HTMLURL: "https://example.invalid/synthetic"}, NotifiedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	value := 0.25
	if err := db.UpsertThreat(ctx, "epss", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-9999", EPSS: &value, FetchedAt: at}}); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the exact pre-journal schema by removing only this additive
	// migration from an owned fixture. No old binary or operational DB is used.
	for _, query := range []string{"DROP TABLE security_enrichment_checkpoints", "DROP TABLE security_enrichment_operations", "DELETE FROM app_migrations WHERE version=4"} {
		if _, err := db.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	before := journalSnapshot(t, db, true)
	runs, err := db.QueryIngestRuns(ctx)
	if err != nil || len(runs) == 0 {
		t.Fatal("non-empty old receipt fixture missing")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if journalSnapshot(t, db, true) != before {
		t.Fatal("additive upgrade changed old schema rows")
	}
	var tables, version int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('security_enrichment_operations','security_enrichment_checkpoints')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow("SELECT COUNT(*) FROM app_migrations WHERE version=4").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if tables != 2 || version != 1 {
		t.Fatal("journal migration not installed exactly once")
	}
	frames := journalStoreFrames(t)
	previous := ""
	for i, frame := range frames {
		ack := appendJournalFrame(t, db, frame, int64(i+1), previous)
		previous = ack.Digest
	}
	if journalSnapshot(t, db, true) != before {
		t.Fatal("journal changed old finding/legacy/receipt data")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if journalSnapshot(t, db, true) != before {
		t.Fatal("idempotent migration changed old rows")
	}
}

func TestOperationJournalTriggerFailureRollsBackAppendAndHead(t *testing.T) {
	for _, stage := range []string{"initial", "head-update"} {
		t.Run(stage, func(t *testing.T) {
			db := journalOwnedStore(t)
			frames := journalStoreFrames(t)
			request := enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: frames[0]}
			trigger := `CREATE TRIGGER journal_synthetic_failure BEFORE INSERT ON security_enrichment_checkpoints BEGIN SELECT RAISE(ABORT,'PRIVATE-trigger-error'); END`
			if stage == "head-update" {
				ack := appendJournalFrame(t, db, frames[0], 1, "")
				request = enrichmentjournal.AppendRequest{Sequence: 2, PreviousDigest: ack.Digest, Checkpoint: frames[1]}
				trigger = `CREATE TRIGGER journal_synthetic_failure BEFORE UPDATE ON security_enrichment_operations BEGIN SELECT RAISE(ABORT,'PRIVATE-trigger-error'); END`
			}
			if _, err := db.db.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, db, false)
			ack, err := db.AppendSecurityEnrichmentCheckpoint(context.Background(), request)
			if err == nil || ack.Digest != "" || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, db, false) != before {
				t.Fatalf("trigger failure left partial journal or leaked error: %+v %v", ack, err)
			}
			if _, err := db.db.Exec("DROP TRIGGER journal_synthetic_failure"); err != nil {
				t.Fatal(err)
			}
			ack, err = db.AppendSecurityEnrichmentCheckpoint(context.Background(), request)
			if err != nil || ack.Replay {
				t.Fatalf("rollback did not leave retryable exact request: %+v %v", ack, err)
			}
		})
	}
}

func TestOperationJournalCorruptionAndStorageAliasesNeverReplayAsSuccess(t *testing.T) {
	for _, kind := range []string{"header-blob-alias", "payload-blob", "oversize-payload", "sequence-blob", "orphan", "header-source", "payload-digest"} {
		t.Run(kind, func(t *testing.T) {
			db := journalOwnedStore(t)
			frame := journalStoreFrames(t)[0]
			request := enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: frame}
			appendJournalFrame(t, db, frame, 1, "")
			if _, err := db.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "header-blob-alias":
				_, err = db.db.Exec(`INSERT INTO security_enrichment_operations SELECT CAST(operation_id AS BLOB),format_version,connector,request_after,request_limit,run_id,head_sequence,head_digest FROM security_enrichment_operations WHERE operation_id=?`, frame.OperationID)
			case "payload-blob":
				_, err = db.db.Exec("UPDATE security_enrichment_checkpoints SET payload_json=CAST(payload_json AS BLOB)")
			case "oversize-payload":
				_, err = db.db.Exec("UPDATE security_enrichment_checkpoints SET payload_json=?", strings.Repeat(" ", enrichmentjournal.MaxCheckpointBytes+1))
			case "sequence-blob":
				_, err = db.db.Exec("UPDATE security_enrichment_checkpoints SET sequence=CAST(sequence AS BLOB)")
			case "orphan":
				if _, err = db.db.Exec("PRAGMA foreign_keys=OFF"); err == nil {
					_, err = db.db.Exec("DELETE FROM security_enrichment_operations")
				}
			case "header-source":
				_, err = db.db.Exec("UPDATE security_enrichment_operations SET connector='kev_feed'")
			case "payload-digest":
				_, err = db.db.Exec("UPDATE security_enrichment_checkpoints SET payload_digest=?", "sha256:"+strings.Repeat("f", 64))
			}
			if err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, db, false)
			ack, err := db.AppendSecurityEnrichmentCheckpoint(context.Background(), request)
			if err == nil || ack.Digest != "" || journalSnapshot(t, db, false) != before {
				t.Fatalf("corrupt journal replayed or was repaired: %+v %v", ack, err)
			}
		})
	}
}

func TestOperationJournalConcurrentCASHasOneImmutableWinner(t *testing.T) {
	db := journalOwnedStore(t)
	frames := journalStoreFrames(t)
	ack := appendJournalFrame(t, db, frames[0], 1, "")
	a, b := frames[1], frames[1]
	prepared := *b.Prepared
	prepared.Attempt.Targets = append([]enrichmentjournal.Target(nil), prepared.Attempt.Targets...)
	prepared.Attempt.Targets[0].Revision = strings.Repeat("c", 64)
	b.Prepared = &prepared
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, frame := range []enrichmentjournal.Checkpoint{a, b} {
		wg.Add(1)
		go func(frame enrichmentjournal.Checkpoint) {
			defer wg.Done()
			_, err := db.AppendSecurityEnrichmentCheckpoint(context.Background(), enrichmentjournal.AppendRequest{Sequence: 2, PreviousDigest: ack.Digest, Checkpoint: frame})
			results <- err
		}(frame)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	var rows, head int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_checkpoints").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow("SELECT head_sequence FROM security_enrichment_operations").Scan(&head); err != nil {
		t.Fatal(err)
	}
	if success != 1 || rows != 2 || head != 2 {
		t.Fatal("CAS collision created a partial/forked journal")
	}
}

func TestOperationJournalDigestCancellationAndClosedDBAreDistinctFromBusinessSuccess(t *testing.T) {
	db := journalOwnedStore(t)
	frames := journalStoreFrames(t)
	previous := ""
	for i, frame := range frames {
		ack := appendJournalFrame(t, db, frame, int64(i+1), previous)
		data, err := enrichmentjournal.Encode(frame)
		if err != nil {
			t.Fatal(err)
		}
		if ack.Digest != journalDigest(data) {
			t.Fatal("ack is not exact canonical payload SHA")
		}
		if frame.Prepared != nil && frame.Prepared.Completion != nil && ack.Digest == frame.Prepared.Completion.OriginalDigest {
			t.Fatal("journal SHA confused with input digest")
		}
		previous = ack.Digest
	}
	runs, err := db.QueryIngestRuns(context.Background())
	if err != nil || len(runs) != 0 {
		t.Fatal("journal success fabricated an enrichment receipt")
	}
	before := journalSnapshot(t, db, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ack, err := db.AppendSecurityEnrichmentCheckpoint(ctx, enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: frames[0]})
	if err == nil || ack.Digest != "" || journalSnapshot(t, db, false) != before {
		t.Fatal("cancelled append performed writes")
	}
	// Exact retained request replay models recovery after an outer caller loses
	// a successful return; this is Store idempotence, not an ack-recovery adapter.
	replayed, err := db.AppendSecurityEnrichmentCheckpoint(context.Background(), enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: frames[0]})
	if err != nil || !replayed.Replay || journalSnapshot(t, db, false) != before {
		t.Fatal("response-loss replay changed journal")
	}
	stored, err := db.QueryIngestRuns(context.Background())
	if err != nil || !reflect.DeepEqual(runs, stored) {
		t.Fatal("read/replay touched business receipts")
	}
}

func TestOperationJournalUUIDUniquenessAndBoundRunBlobAlias(t *testing.T) {
	db := journalOwnedStore(t)
	frames := journalStoreFrames(t)
	first := appendJournalFrame(t, db, frames[0], 1, "")
	bound := appendJournalFrame(t, db, frames[1], 2, first.Digest)
	other := frames[0]
	other.OperationID = "84000000-0000-4000-8000-000000000002"
	reserved := appendJournalFrame(t, db, other, 1, "")
	collision := frames[1]
	collision.OperationID = other.OperationID
	before := journalSnapshot(t, db, false)
	ack, err := db.AppendSecurityEnrichmentCheckpoint(context.Background(), enrichmentjournal.AppendRequest{Sequence: 2, PreviousDigest: reserved.Digest, Checkpoint: collision})
	if err == nil || ack.Digest != "" || journalSnapshot(t, db, false) != before {
		t.Fatal("same run UUID acquired another operation or left partial state")
	}
	if _, err := db.db.Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec("UPDATE security_enrichment_operations SET run_id=CAST(? AS BLOB) WHERE operation_id=?", frames[1].Progress.RunID, other.OperationID); err != nil {
		t.Fatal(err)
	}
	before = journalSnapshot(t, db, false)
	ack, err = db.AppendSecurityEnrichmentCheckpoint(context.Background(), enrichmentjournal.AppendRequest{Sequence: 2, PreviousDigest: first.Digest, Checkpoint: frames[1]})
	if err == nil || ack.Digest != "" || journalSnapshot(t, db, false) != before {
		t.Fatal("TEXT/BLOB run UUID alias was accepted or repaired during replay")
	}
	if bound.Digest == "" {
		t.Fatal("fixture lacks a bound checkpoint")
	}
}

func TestOperationJournalClosedDatabaseReturnsNoAck(t *testing.T) {
	db, err := NewWithPath(filepath.Join(t.TempDir(), "closed-journal.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ack, err := db.AppendSecurityEnrichmentCheckpoint(context.Background(), enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: journalStoreFrames(t)[0]})
	if err == nil || ack.Digest != "" || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("closed database returned an acknowledgement or raw error")
	}
}
