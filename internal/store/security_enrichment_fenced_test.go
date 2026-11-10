package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func fencedAssertNoAck(t *testing.T, proof SecurityEnrichmentFencedProof) {
	t.Helper()
	if proof.State == "matched" || !reflect.DeepEqual(proof.Acknowledgement, SecurityEnrichmentFencedAcknowledgement{}) || proof.HeadSequence != 0 || proof.HeadDigest != "" || proof.Business.Receipt != "" {
		t.Fatalf("unverified proof exposed acknowledgement/head/receipt: %+v", proof)
	}
}

func TestFencedSameCompletionAcrossConnectionsHasAtMostOneFreshCommit(t *testing.T) {
	db, completion, reservation, frames := fencedContractFixture(t, "epss", 2490)
	begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	fencedContractAppend(t, db, begin)
	fencedContractApply(t, db, begin, "running")
	request := fencedContractRequest(t, reservation, frames[2], 3, begin.CheckpointDigest)
	fencedContractAppend(t, db, request)
	var path string
	if err := db.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
		t.Fatal("owned database path unavailable")
	}
	second, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	type result struct {
		proof SecurityEnrichmentFencedProof
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, store := range []*Store{db, second} {
		go func(store *Store) {
			<-start
			proof, err := store.ApplySecurityEnrichmentFencedRefresh(context.Background(), request)
			results <- result{proof, err}
		}(store)
	}
	close(start)
	fresh := 0
	for i := 0; i < 2; i++ {
		out := <-results
		if out.err != nil {
			fencedAssertNoAck(t, out.proof)
		} else {
			if out.proof.State != "matched" || out.proof.Business.State != "success" || out.proof.Business.Receipt == "" || !fencedContractAckMatches(out.proof.Acknowledgement, request, out.proof.Acknowledgement.Replay) {
				t.Fatal("successful concurrent completion acknowledgement mismatched")
			}
			if !out.proof.Acknowledgement.Replay {
				fresh++
			}
		}
	}
	if fresh > 1 {
		t.Fatal("two connections acknowledged fresh writes for one UUID")
	}
	before := journalSnapshot(t, db, false)
	proof, err := db.ReadSecurityEnrichmentFencedRefresh(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	var manifests, observations, runs int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_runs WHERE ingest_run_id=?", completion.Attempt.RunID).Scan(&manifests); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_observations WHERE ingest_run_id=?", completion.Attempt.RunID).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow("SELECT COUNT(*) FROM ingest_runs WHERE id=?", completion.Attempt.RunID).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if proof.State == "matched" {
		if proof.Business.State != "success" || manifests != 1 || observations != len(completion.Feed.Entries) {
			t.Fatal("concurrent completion did not retain exact atomic evidence")
		}
	} else {
		// Lock/commit errors need not guarantee progress. They cannot leave
		// partial evidence, create a replacement UUID or expose an Ack.
		fencedAssertNoAck(t, proof)
		if fresh != 0 || manifests != 0 || observations != 0 {
			t.Fatal("uncertain/uncommitted concurrent write left partial evidence")
		}
	}
	if runs != 1 || journalSnapshot(t, db, false) != before {
		t.Fatal("readonly reconciliation wrote or created another business run")
	}
}

func TestFencedFailureRequiresExactStoredCodeAndFinish(t *testing.T) {
	for _, kind := range []string{"code", "finish"} {
		t.Run(kind, func(t *testing.T) {
			db, completion, reservation, frames := fencedContractFixture(t, "epss", 2470)
			begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
			fencedContractAppend(t, db, begin)
			fencedContractApply(t, db, begin, "running")
			fail := frames[1]
			p := *fail.Prepared
			p.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: completion.FinishedAt}
			fail.Stage, fail.Prepared = enrichmentjournal.Fail, &p
			request := fencedContractRequest(t, reservation, fail, 3, begin.CheckpointDigest)
			fencedContractAppend(t, db, request)
			fencedContractApply(t, db, request, "failed")
			var body string
			if err := db.db.QueryRow("SELECT body_json FROM ingest_runs WHERE id=?", completion.Attempt.RunID).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var run model.IngestRun
			if err := json.Unmarshal([]byte(body), &run); err != nil {
				t.Fatal(err)
			}
			if run.FinishedAt == nil {
				t.Fatal("fixture lacks a finished failure")
			}
			if kind == "code" {
				run.Error = "parse_failed"
			} else {
				finish := run.FinishedAt.Add(time.Nanosecond)
				run.FinishedAt = &finish
			}
			encoded, err := json.Marshal(run)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.db.Exec("UPDATE ingest_runs SET error=?,finished_at=?,body_json=? WHERE id=?", run.Error, run.FinishedAt.Format(time.RFC3339Nano), string(encoded), run.ID); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, db, false)
			fencedContractRead(t, db, request, false, "unknown")
			read, err := db.ReadSecurityEnrichmentFencedRefresh(context.Background(), request)
			if err == nil {
				t.Fatal("different stored failure was accepted")
			}
			fencedAssertNoAck(t, read)
			applied, err := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), request)
			if err == nil {
				t.Fatal("different stored failure was rewritten")
			}
			fencedAssertNoAck(t, applied)
			if journalSnapshot(t, db, false) != before {
				t.Fatal("failure mismatch changed data")
			}
		})
	}
}

func TestFencedNilClosedAndReadErrorExposeNoAcknowledgement(t *testing.T) {
	_, _, reservation, frames := fencedContractFixture(t, "epss", 2480)
	request := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	closed := journalOwnedStore(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	for _, db := range []*Store{nil, closed} {
		ack, appendErr := db.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), request)
		applied, applyErr := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), request)
		cp, cpErr := db.ReadSecurityEnrichmentFencedCheckpoint(context.Background(), request)
		business, readErr := db.ReadSecurityEnrichmentFencedRefresh(context.Background(), request)
		if appendErr == nil || applyErr == nil || cpErr == nil || readErr == nil || !reflect.DeepEqual(ack, SecurityEnrichmentFencedAcknowledgement{}) {
			t.Fatal("nil/closed dependency exposed acknowledgement")
		}
		fencedAssertNoAck(t, applied)
		fencedAssertNoAck(t, cp)
		fencedAssertNoAck(t, business)
	}
	db, _, reservation, frames := fencedContractFixture(t, "epss", 2481)
	request = fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	fencedContractAppend(t, db, request)
	if _, err := db.db.Exec("ALTER TABLE security_enrichment_operations RENAME TO PRIVATE_unavailable_operations"); err != nil {
		t.Fatal(err)
	}
	fencedContractRejectWithoutWrites(t, db, request)
}

func TestFencedBeginAndFailReplaysPreserveHistoricalBindingAndAllRows(t *testing.T) {
	db, completion, reservation, frames := fencedContractFixture(t, "epss", 2400)
	begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	fencedContractAppend(t, db, begin)
	fencedContractApply(t, db, begin, "running")
	if _, err := db.db.Exec("UPDATE findings SET body_json=json_set(body_json,'$.title','later synthetic revision')"); err != nil {
		t.Fatal(err)
	}
	before := journalSnapshot(t, db, false)
	replay, err := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), begin)
	if err != nil || !fencedContractAckMatches(replay.Acknowledgement, begin, true) || replay.Business.State != "running" {
		t.Fatal("Begin replay became fresh or revalidated current Finding")
	}
	if legacy, err := db.BeginSecurityEnrichmentRefresh(context.Background(), completion.Attempt); !errors.Is(err, ErrIngestConflict) || legacy {
		t.Fatal("adopted source escaped through generic Begin replay")
	}
	if journalSnapshot(t, db, false) != before {
		t.Fatal("Begin replays changed a table")
	}
	fail := frames[1]
	prepared := *fail.Prepared
	prepared.Failure = &enrichmentjournal.Failure{Code: "target_changed", FinishedAt: completion.FinishedAt}
	fail.Stage, fail.Prepared = enrichmentjournal.Fail, &prepared
	request := fencedContractRequest(t, reservation, fail, 3, begin.CheckpointDigest)
	fencedContractAppend(t, db, request)
	fencedContractApply(t, db, request, "failed")
	before = journalSnapshot(t, db, false)
	replay, err = db.ApplySecurityEnrichmentFencedRefresh(context.Background(), request)
	if err != nil || !fencedContractAckMatches(replay.Acknowledgement, request, true) || replay.Business.State != "failed" || replay.Business.Receipt != "" {
		t.Fatal("exact Fail replay changed its fixed-code proof")
	}
	if legacy, err := db.FailSecurityEnrichmentRefresh(context.Background(), completion.Attempt, "target_changed", completion.FinishedAt); !errors.Is(err, ErrIngestConflict) || legacy {
		t.Fatal("adopted source escaped through generic Fail replay")
	}
	fencedContractRead(t, db, request, true, "failed")
	if journalSnapshot(t, db, false) != before {
		t.Fatal("Fail replays changed a table")
	}
}

func TestFencedBusinessCorruptionNeverBorrowsCheckpointOnlyProof(t *testing.T) {
	for _, kind := range []string{"run-body-oversize", "run-connector-oversize", "run-scope-oversize", "run-start-oversize", "run-cursor-blob", "run-alias", "manifest-version-oversize", "manifest-digest", "observation-identity-blob", "observation-body-oversize", "observation-missing", "manifest-reference-alias"} {
		t.Run(kind, func(t *testing.T) {
			db, completion, reservation, frames := fencedContractFixture(t, "epss", 2410)
			begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
			fencedContractAppend(t, db, begin)
			fencedContractApply(t, db, begin, "running")
			complete := fencedContractRequest(t, reservation, frames[2], 3, begin.CheckpointDigest)
			fencedContractAppend(t, db, complete)
			fencedContractApply(t, db, complete, "success")
			if _, err := db.db.Exec("PRAGMA foreign_keys=OFF"); err != nil {
				t.Fatal(err)
			}
			query := ""
			args := []any{completion.Attempt.RunID}
			switch kind {
			case "run-body-oversize":
				body, err := json.Marshal(map[string]string{"oversize": strings.Repeat("PRIVATE", 1000)})
				if err != nil || !json.Valid(body) || len(body) <= 4096 {
					t.Fatal("fixture must be valid JSON above the stored body byte cap")
				}
				query, args = "UPDATE ingest_runs SET body_json=? WHERE id=?", []any{string(body), completion.Attempt.RunID}
			case "run-connector-oversize":
				query, args = "UPDATE ingest_runs SET connector=? WHERE id=?", []any{strings.Repeat("PRIVATE", 1000), completion.Attempt.RunID}
			case "run-scope-oversize":
				query, args = "UPDATE ingest_runs SET scope=? WHERE id=?", []any{strings.Repeat("PRIVATE", 1000), completion.Attempt.RunID}
			case "run-start-oversize":
				query, args = "UPDATE ingest_runs SET started_at=? WHERE id=?", []any{strings.Repeat("PRIVATE", 1000), completion.Attempt.RunID}
			case "run-cursor-blob":
				query = "UPDATE ingest_runs SET cursor=CAST(cursor AS BLOB) WHERE id=?"
			case "run-alias":
				query = "INSERT INTO ingest_runs(id,connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json) SELECT CAST(id AS BLOB),connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json FROM ingest_runs WHERE id=?"
			case "manifest-version-oversize":
				query, args = "UPDATE security_enrichment_runs SET version=? WHERE ingest_run_id=?", []any{strings.Repeat("PRIVATE", 1000), completion.Attempt.RunID}
			case "manifest-digest":
				query, args = "UPDATE security_enrichment_runs SET original_digest=? WHERE ingest_run_id=?", []any{"sha256:" + strings.Repeat("f", 64), completion.Attempt.RunID}
			case "observation-identity-blob":
				query = "UPDATE security_enrichment_observations SET evidence_identity=CAST(evidence_identity AS BLOB) WHERE ingest_run_id=?"
			case "observation-body-oversize":
				query, args = "UPDATE security_enrichment_observations SET body_json=? WHERE ingest_run_id=?", []any{strings.Repeat("PRIVATE", 1000), completion.Attempt.RunID}
			case "observation-missing":
				query = "DELETE FROM security_enrichment_observations WHERE ingest_run_id=?"
			case "manifest-reference-alias":
				query = "INSERT INTO security_enrichment_runs SELECT CAST(ingest_run_id AS BLOB),source,version,published_at,observed_at,selected_cves_json,entries,original_digest FROM security_enrichment_runs WHERE ingest_run_id=?"
			}
			if _, err := db.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			if kind == "run-body-oversize" {
				var valid, size int
				if err := db.db.QueryRow("SELECT json_valid(body_json),length(CAST(body_json AS BLOB)) FROM ingest_runs WHERE id=?", completion.Attempt.RunID).Scan(&valid, &size); err != nil || valid != 1 || size <= 4096 {
					t.Fatal("oversize fixture did not reach the DB as valid JSON above the byte cap")
				}
			}
			before := journalSnapshot(t, db, false)
			fencedContractRead(t, db, complete, false, "unknown")
			proof, readErr := db.ReadSecurityEnrichmentFencedRefresh(context.Background(), complete)
			if !errors.Is(readErr, errFencedCorrupt) || strings.Contains(readErr.Error(), "PRIVATE") {
				t.Fatal("corrupt business evidence was misclassified, accepted or leaked raw content")
			}
			fencedAssertNoAck(t, proof)
			proof, writeErr := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), complete)
			if !errors.Is(writeErr, errFencedCorrupt) || strings.Contains(writeErr.Error(), "PRIVATE") {
				t.Fatal("corrupt replay was misclassified, accepted or leaked raw content")
			}
			fencedAssertNoAck(t, proof)
			if journalSnapshot(t, db, false) != before {
				t.Fatal("business proof/rejected replay repaired or changed a table")
			}
		})
	}
}

func TestFencedSourceJournalAndReservationAliasesExposeNoProofOrWrites(t *testing.T) {
	for _, kind := range []string{"source-blob", "source-incomplete", "reservation-payload-blob", "reservation-oversize", "operation-alias", "journal-payload-blob", "journal-oversize", "journal-orphan"} {
		t.Run(kind, func(t *testing.T) {
			db, _, reservation, frames := fencedContractFixture(t, "epss", 2420)
			begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
			fencedContractAppend(t, db, begin)
			for _, query := range []string{"PRAGMA foreign_keys=OFF", "PRAGMA ignore_check_constraints=ON"} {
				if _, err := db.db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			query := ""
			var args []any
			switch kind {
			case "source-blob":
				query = "UPDATE security_enrichment_source_generations SET connector=CAST(connector AS BLOB) WHERE connector='epss_feed'"
			case "source-incomplete":
				query = "DELETE FROM security_enrichment_source_generations WHERE connector='kev_feed'"
			case "reservation-payload-blob":
				query = "UPDATE security_enrichment_reservations SET reserved_payload_json=CAST(reserved_payload_json AS BLOB)"
			case "reservation-oversize":
				query, args = "UPDATE security_enrichment_reservations SET reserved_payload_json=?", []any{strings.Repeat(" ", enrichmentjournal.MaxCheckpointBytes+1)}
			case "operation-alias":
				query = "INSERT INTO security_enrichment_operations SELECT CAST(operation_id AS BLOB),format_version,connector,request_after,request_limit,NULL,head_sequence,head_digest FROM security_enrichment_operations"
			case "journal-payload-blob":
				query = "UPDATE security_enrichment_checkpoints SET payload_json=CAST(payload_json AS BLOB)"
			case "journal-oversize":
				query, args = "UPDATE security_enrichment_checkpoints SET payload_json=?", []any{strings.Repeat(" ", enrichmentjournal.MaxCheckpointBytes+1)}
			case "journal-orphan":
				query = "DELETE FROM security_enrichment_operations"
			}
			if _, err := db.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			fencedContractRejectWithoutWrites(t, db, begin)
		})
	}
}

func TestFencedRequestBoundsContextAndNilStoreRejectBeforeDependencyIO(t *testing.T) {
	db, _, reservation, frames := fencedContractFixture(t, "epss", 2430)
	good := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	for _, kind := range []string{"intent", "generation", "sequence", "previous", "digest", "reserved", "cursor", "targets", "finding-id"} {
		t.Run(kind, func(t *testing.T) {
			request := fencedContractClone(t, good)
			switch kind {
			case "intent":
				request.Reservation.IntentID = strings.Repeat("PRIVATE", 10000)
			case "generation":
				request.Reservation.ExpectedGeneration = reservationMaxGeneration
			case "sequence":
				request.Checkpoint.Sequence = 6
			case "previous":
				request.Checkpoint.PreviousDigest = ""
			case "digest":
				request.CheckpointDigest = strings.Repeat("PRIVATE", 10000)
			case "reserved":
				request.Checkpoint.Checkpoint = request.Reservation.Reserved.Checkpoint
			case "cursor":
				request.Checkpoint.Checkpoint.Request.After = strings.Repeat("x", 129)
			case "targets":
				request.Checkpoint.Checkpoint.Prepared.Attempt.Targets = make([]enrichmentjournal.Target, 201)
			case "finding-id":
				request.Checkpoint.Checkpoint.Prepared.Attempt.Targets[0].FindingID = strings.Repeat("x", 129)
			}
			if kind != "digest" {
				// Keep syntax/digest sound: malformed closed shape must not be
				// rejected only because its earlier digest became stale. Unlike
				// the strict leaf encoder, json.Marshal permits invalid shapes.
				raw, err := json.Marshal(request.Checkpoint.Checkpoint)
				if err != nil {
					t.Fatal(err)
				}
				request.CheckpointDigest = journalDigest(raw)
			}
			before := journalSnapshot(t, db, false)
			for _, store := range []*Store{nil, db} {
				ack, appendErr := store.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), request)
				applied, applyErr := store.ApplySecurityEnrichmentFencedRefresh(context.Background(), request)
				cp, cpErr := store.ReadSecurityEnrichmentFencedCheckpoint(context.Background(), request)
				business, readErr := store.ReadSecurityEnrichmentFencedRefresh(context.Background(), request)
				for _, err := range []error{appendErr, applyErr, cpErr, readErr} {
					if !errors.Is(err, errFencedConflict) || strings.Contains(err.Error(), "PRIVATE") {
						t.Fatal("invalid shape did not return conflict before dependency I/O, or leaked input")
					}
				}
				if !reflect.DeepEqual(ack, SecurityEnrichmentFencedAcknowledgement{}) {
					t.Fatal("invalid shape exposed acknowledgement")
				}
				fencedAssertNoAck(t, applied)
				fencedAssertNoAck(t, cp)
				fencedAssertNoAck(t, business)
			}
			if journalSnapshot(t, db, false) != before {
				t.Fatal("invalid shape changed an owned database table")
			}
		})
	}
	before := journalSnapshot(t, db, false)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer expire()
	for _, ctx := range []context.Context{nil, cancelled, expired} {
		ack, appendErr := db.AppendSecurityEnrichmentFencedCheckpoint(ctx, good)
		applied, applyErr := db.ApplySecurityEnrichmentFencedRefresh(ctx, good)
		cp, cpErr := db.ReadSecurityEnrichmentFencedCheckpoint(ctx, good)
		business, readErr := db.ReadSecurityEnrichmentFencedRefresh(ctx, good)
		if appendErr == nil || applyErr == nil || cpErr == nil || readErr == nil || !reflect.DeepEqual(ack, SecurityEnrichmentFencedAcknowledgement{}) || journalSnapshot(t, db, false) != before {
			t.Fatal("invalid/cancelled context changed a table")
		}
		fencedAssertNoAck(t, applied)
		fencedAssertNoAck(t, cp)
		fencedAssertNoAck(t, business)
		if ctx != nil && (!errors.Is(appendErr, ctx.Err()) || !errors.Is(applyErr, ctx.Err()) || !errors.Is(cpErr, ctx.Err()) || !errors.Is(readErr, ctx.Err())) {
			t.Fatal("context identity changed")
		}
	}
}

func TestFencedPreparedCopiesDoNotAliasCallerOrTypedBusinessValues(t *testing.T) {
	for _, source := range []string{"epss", "kev"} {
		t.Run(source, func(t *testing.T) {
			_, _, reservation, frames := fencedContractFixture(t, source, 2440)
			request := fencedContractRequest(t, reservation, frames[2], 3, "sha256:"+strings.Repeat("a", 64))
			prepared, err := prepareFencedRequest(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			want := string(prepared.payload)
			request.Checkpoint.Checkpoint.Prepared.Attempt.Targets[0].FindingID = "PRIVATE-caller"
			request.Checkpoint.Checkpoint.Prepared.Completion.OriginalDigest = "sha256:" + strings.Repeat("f", 64)
			entry := &request.Checkpoint.Checkpoint.Prepared.Completion.Feed.Entries[0]
			if entry.EPSS != nil {
				*entry.EPSS = 0
			}
			if entry.KEVDateAdded != nil {
				*entry.KEVDateAdded = entry.KEVDateAdded.Add(time.Hour)
			}
			if got := jsonValueForInspection(t, prepared.checkpoint.Checkpoint); got != want {
				t.Fatal("caller mutation changed private prepared CP")
			}
			business, err := prepareFencedBusiness(prepared)
			if err != nil {
				t.Fatal(err)
			}
			business.completion.Attempt.Targets[0].Revision = strings.Repeat("f", 64)
			business.completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
			if p := business.completion.Feed.Entries[0].Percentile; p != nil {
				*p = 1
			}
			if p := business.completion.Feed.Entries[0].KEVDateAdded; p != nil {
				*p = p.Add(time.Hour)
			}
			if jsonValueForInspection(t, prepared.checkpoint.Checkpoint) != want || string(prepared.payload) != want {
				t.Fatal("typed business conversion aliased private prepared CP")
			}
		})
	}
}

func TestFencedCompleteHistoricalReplayAndPartialEvidenceRemainExact(t *testing.T) {
	for _, kind := range []string{"historical-current-change", "nil-entries", "empty-entries", "known-zero"} {
		t.Run(kind, func(t *testing.T) {
			db, completion, reservation, _ := fencedContractFixture(t, "epss", 2450)
			switch kind {
			case "nil-entries":
				completion.Feed.Entries = nil
			case "empty-entries":
				completion.Feed.Entries = completion.Feed.Entries[:0]
			case "known-zero":
				zero := 0.0
				completion.Feed.Entries[0].EPSS, completion.Feed.Entries[0].Percentile = &zero, &zero
			}
			frames := inspectionContractFrames(t, completion, 2450)
			for i := range frames {
				frames[i].OperationID = reservation.Reserved.Checkpoint.OperationID
			}
			begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
			fencedContractAppend(t, db, begin)
			fencedContractApply(t, db, begin, "running")
			complete := fencedContractRequest(t, reservation, frames[2], 3, begin.CheckpointDigest)
			fencedContractAppend(t, db, complete)
			written := fencedContractApply(t, db, complete, "success")
			if kind == "historical-current-change" {
				if _, err := db.db.Exec("UPDATE findings SET body_json=json_set(body_json,'$.title','newer synthetic title')"); err != nil {
					t.Fatal(err)
				}
				newer, feed := enrichmentFixture(t, 2451, "epss", completion.Feed.PublishedAt.Add(time.Minute), completion.Feed.ObservedAt.Add(time.Minute))
				mustEnrichment(t, db, newer, feed)
			}
			before := journalSnapshot(t, db, false)
			proof := fencedContractRead(t, db, complete, true, "success")
			replay, err := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), complete)
			if err != nil || !fencedContractAckMatches(replay.Acknowledgement, complete, true) || proof.Business.Receipt != written.Business.Receipt || replay.Business.Receipt != written.Business.Receipt || journalSnapshot(t, db, false) != before {
				t.Fatal("historical/partial receipt changed or revalidated current Finding")
			}
			stored := inspectWithoutTableChanges(t, db, reservation.Reserved.Checkpoint.OperationID, "valid", "success", false)
			entries := stored.Checkpoint.Prepared.Completion.Feed.Entries
			if (entries == nil) != (completion.Feed.Entries == nil) || len(entries) != len(completion.Feed.Entries) {
				t.Fatal("nil/empty partial CP evidence was normalized away")
			}
			if kind == "known-zero" && (entries[0].EPSS == nil || *entries[0].EPSS != 0 || entries[0].Percentile == nil || *entries[0].Percentile != 0) {
				t.Fatal("known zero became missing")
			}
		})
	}
}

func TestFencedPostWriteFenceChangeRollsBackInsideSameTransaction(t *testing.T) {
	for _, kind := range []string{"checkpoint", "business"} {
		t.Run(kind, func(t *testing.T) {
			db, _, reservation, frames := fencedContractFixture(t, "epss", 2460)
			request := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
			table := "security_enrichment_checkpoints"
			if kind == "business" {
				fencedContractAppend(t, db, request)
				fencedContractApply(t, db, request, "running")
				request = fencedContractRequest(t, reservation, frames[2], 3, request.CheckpointDigest)
				fencedContractAppend(t, db, request)
				table = "security_enrichment_observations"
			}
			if _, err := db.db.Exec("CREATE TRIGGER synthetic_fence_change BEFORE INSERT ON " + table + " BEGIN UPDATE security_enrichment_source_generations SET generation=2 WHERE connector='epss_feed'; END"); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, db, false)
			if kind == "checkpoint" {
				ack, err := db.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), request)
				if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentFencedAcknowledgement{}) {
					t.Fatal("changed in-Tx generation was acknowledged")
				}
			} else {
				proof, err := db.ApplySecurityEnrichmentFencedRefresh(context.Background(), request)
				if err == nil {
					t.Fatal("changed in-Tx generation was acknowledged")
				}
				fencedAssertNoAck(t, proof)
			}
			if journalSnapshot(t, db, false) != before {
				t.Fatal("generation mutation/business/CP write survived rollback")
			}
		})
	}
}
