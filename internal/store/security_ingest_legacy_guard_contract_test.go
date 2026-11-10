package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func ingestGuardContractRunning(t *testing.T, source string, id int) legacyGuardContractFixture {
	t.Helper()
	f := legacyGuardContractFixtureFor(t, source, id)
	legacyGuardContractPrepare(t, &f, "begin", false, true)
	fencedContractAppend(t, f.db, f.fenced)
	fencedContractApply(t, f.db, f.fenced, "running")
	return f
}

func ingestGuardContractStartReject(t *testing.T, db *Store, connector string, at time.Time) {
	t.Helper()
	before := journalSnapshot(t, db, false)
	run, err := db.StartIngestRun(context.Background(), connector, "synthetic-owned-scope", at)
	if err == nil {
		t.Fatal("adopted-source legacy Start must be rejected; valid generic call succeeded")
	}
	if !errors.Is(err, ErrIngestConflict) || !reflect.DeepEqual(run, model.IngestRun{}) || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, db, false) != before {
		t.Fatalf("adopted Start exposed run/raw text, lost conflict identity or changed tables: %v", err)
	}
}

func ingestGuardContractFinishReject(t *testing.T, db *Store, id string, at time.Time, adopted bool) {
	t.Helper()
	before := journalSnapshot(t, db, false)
	err := db.FinishIngestRun(context.Background(), id, "success", "partial", "", at)
	if err == nil {
		t.Fatal("adopted-source legacy Finish must be rejected; valid generic call succeeded")
	}
	if adopted && !errors.Is(err, ErrIngestConflict) || errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, db, false) != before {
		t.Fatalf("ambiguous/adopted Finish became missing, leaked raw text or changed tables: %v", err)
	}
}

func ingestGuardContractPositive(t *testing.T, db *Store, connector, scope string, at time.Time) model.IngestRun {
	t.Helper()
	run, err := db.StartIngestRun(context.Background(), connector, scope, at)
	if err != nil || !securityUUID(run.ID) || run.Connector != connector || run.Scope != scope || !run.StartedAt.Equal(at) || run.StartedAt.Location() != time.UTC || run.Result != "running" || run.Coverage != "unknown" || run.FinishedAt != nil || run.Cursor != "" || run.Error != "" {
		t.Fatalf("valid unadopted Start control=%+v err=%v", run, err)
	}
	return run
}

func ingestGuardContractFinishPositive(t *testing.T, db *Store, run model.IngestRun, at time.Time) {
	t.Helper()
	if err := db.FinishIngestRun(context.Background(), run.ID, "partial", "unknown", "rate_limited", at); err != nil {
		t.Fatal(err)
	}
	var body, finished string
	if err := db.db.QueryRow("SELECT body_json,finished_at FROM ingest_runs WHERE id=?", run.ID).Scan(&body, &finished); err != nil {
		t.Fatal(err)
	}
	var got model.IngestRun
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	run.Result, run.Coverage, run.Error = "partial", "unknown", "rate_limited"
	utc := at.UTC()
	run.FinishedAt = &utc
	if !reflect.DeepEqual(run, got) || finished != utc.Format(time.RFC3339Nano) {
		t.Fatal("legacy Finish changed retained identity, scope, input clocks or UTC result")
	}
}

func TestLegacyIngestGuardContractAdoptedStartAndFinishRefuseWhileFencedWorks(t *testing.T) {
	for index, source := range []string{"epss", "kev"} {
		for _, api := range []string{"start", "finish"} {
			t.Run(source+"/"+api, func(t *testing.T) {
				// A valid identical source is allowed without adoption. This
				// proves that the new runtime rejection is not an invalid fixture.
				control := journalOwnedStore(t)
				at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.FixedZone("synthetic-offset", 2*60*60))
				run := ingestGuardContractPositive(t, control, source+"_feed", "synthetic-owned-scope", at)
				ingestGuardContractFinishPositive(t, control, run, at.Add(time.Minute))

				f := ingestGuardContractRunning(t, source, 3300+index)
				if api == "start" {
					ingestGuardContractStartReject(t, f.db, source+"_feed", f.completion.Attempt.StartedAt)
				} else {
					ingestGuardContractFinishReject(t, f.db, f.completion.Attempt.RunID, f.completion.FinishedAt, true)
				}
				// Rejection must not change the retained running receipt or
				// block the explicit fenced same-UUID completion.
				fencedContractRead(t, f.db, f.fenced, true, "running")
				complete := fencedContractRequest(t, f.root, f.frames[2], 3, f.fenced.CheckpointDigest)
				fencedContractAppend(t, f.db, complete)
				fencedContractApply(t, f.db, complete, "success")
				fencedContractRead(t, f.db, complete, true, "success")
			})
		}
	}
}

func TestLegacyIngestGuardContractFinishClassificationAndLegacyControls(t *testing.T) {
	probe := ingestGuardContractRunning(t, "epss", 3310)
	// The top-level Red must first reach the existing valid Finish call.
	ingestGuardContractFinishReject(t, probe.db, probe.completion.Attempt.RunID, probe.completion.FinishedAt, true)

	for index, kind := range []string{"column-feed-body-nonfeed", "body-feed-column-nonfeed", "escaped-feed-key", "case-feed-key", "duplicate-key", "duplicate-escaped-key", "duplicate-case-key", "body-null-source", "body-number-source", "body-id-mismatch", "blob-id", "text-and-blob-id", "blob-connector", "blob-body", "large-adopted-body"} {
		t.Run(kind, func(t *testing.T) {
			f := ingestGuardContractRunning(t, "epss", 3320+index)
			run := ingestGuardContractPositive(t, f.db, "dependabot", "synthetic-owned-scope", f.completion.Attempt.StartedAt)
			body, err := json.Marshal(run)
			if err != nil {
				t.Fatal(err)
			}
			query := "UPDATE ingest_runs SET body_json=? WHERE id=?"
			args := []any{string(body), run.ID}
			switch kind {
			case "column-feed-body-nonfeed":
				query, args = "UPDATE ingest_runs SET connector='epss_feed' WHERE id=?", []any{run.ID}
			case "body-feed-column-nonfeed":
				run.Connector = "epss_feed"
			case "escaped-feed-key":
				body = []byte(strings.Replace(string(body), "\"connector\":\"dependabot\"", "\"conne\\u0063tor\":\"epss_feed\"", 1))
			case "case-feed-key":
				body = []byte(strings.Replace(string(body), "\"connector\":\"dependabot\"", "\"Connector\":\"epss_feed\"", 1))
			case "duplicate-key":
				body = []byte(strings.Replace(string(body), "\"connector\":\"dependabot\"", "\"connector\":\"dependabot\",\"connector\":\"epss_feed\"", 1))
			case "duplicate-escaped-key":
				body = []byte(strings.Replace(string(body), "\"connector\":\"dependabot\"", "\"connector\":\"dependabot\",\"conne\\u0063tor\":\"epss_feed\"", 1))
			case "duplicate-case-key":
				body = []byte(strings.Replace(string(body), "\"connector\":\"dependabot\"", "\"connector\":\"dependabot\",\"Connector\":\"epss_feed\"", 1))
			case "body-null-source":
				body = []byte(strings.Replace(string(body), "\"connector\":\"dependabot\"", "\"connector\":null", 1))
			case "body-number-source":
				body = []byte(strings.Replace(string(body), "\"connector\":\"dependabot\"", "\"connector\":123", 1))
			case "body-id-mismatch":
				run.ID = "PRIVATE-other-row-identity"
			case "blob-id":
				query, args = "UPDATE ingest_runs SET id=CAST(id AS BLOB) WHERE id=?", []any{run.ID}
			case "text-and-blob-id":
				query, args = "INSERT INTO ingest_runs SELECT CAST(id AS BLOB),connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json FROM ingest_runs WHERE id=?", []any{run.ID}
			case "blob-connector":
				query, args = "UPDATE ingest_runs SET connector=CAST('epss_feed' AS BLOB) WHERE id=?", []any{run.ID}
			case "blob-body":
				query, args = "UPDATE ingest_runs SET body_json=CAST(body_json AS BLOB) WHERE id=?", []any{run.ID}
			case "large-adopted-body":
				query = "UPDATE ingest_runs SET connector='epss_feed',scope=?,body_json=? WHERE id=?"
				run.Connector, run.Scope = "epss_feed", strings.Repeat("synthetic-scope", 1000)
			}
			if kind == "body-feed-column-nonfeed" || kind == "body-id-mismatch" || kind == "large-adopted-body" {
				body, err = json.Marshal(run)
				if err != nil {
					t.Fatal(err)
				}
			}
			if query == "UPDATE ingest_runs SET body_json=? WHERE id=?" {
				args[0] = string(body)
			}
			if kind == "large-adopted-body" {
				args = []any{run.Scope, string(body), args[1]}
			}
			if !json.Valid(body) {
				t.Fatal("corruption fixture must retain syntactically valid JSON")
			}
			if _, err := f.db.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			id := args[len(args)-1].(string)
			ingestGuardContractFinishReject(t, f.db, id, f.completion.FinishedAt, false)
		})
	}
	t.Run("healthy-arbitrary-identity-big-body-labels-and-utc", func(t *testing.T) {
		f := ingestGuardContractRunning(t, "epss", 3340)
		at := f.completion.Attempt.StartedAt.In(time.FixedZone("synthetic-offset", -3*60*60))
		for index, connector := range []string{"dependabot", "epss_offline", "kev_offline", " epss_feed", "EPSS_FEED", "custom feed label", "kev_feed"} {
			scope := strings.Repeat("synthetic-scope", 1000)
			run := ingestGuardContractPositive(t, f.db, connector, scope, at)
			oldID := run.ID
			run.ID = fmt.Sprintf("legacy-id:synthetic/α/%d", index)
			body, err := json.Marshal(run)
			if err != nil || len(body) <= 4096 {
				t.Fatal("healthy large non-UUID fixture is not large valid JSON")
			}
			if _, err := f.db.db.Exec("UPDATE ingest_runs SET id=?,body_json=? WHERE id=?", run.ID, string(body), oldID); err != nil {
				t.Fatal(err)
			}
			// Arbitrary labels are not trimmed/case-folded into a real feed.
			// kev_feed is genuinely unadopted idle0; it also keeps its old
			// large-scope body behavior. No blanket UUID/4KiB rule is allowed.
			ingestGuardContractFinishPositive(t, f.db, run, at.Add(time.Minute))
			before := journalSnapshot(t, f.db, false)
			if err := f.db.FinishIngestRun(context.Background(), run.ID, "success", "full", "", at.Add(2*time.Minute)); !errors.Is(err, sql.ErrNoRows) || journalSnapshot(t, f.db, false) != before {
				t.Fatal("already-finished legacy ID no longer has ErrNoRows semantics")
			}
		}
	})
	t.Run("missing-input-order-and-zero-rows", func(t *testing.T) {
		db := journalOwnedStore(t)
		at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
		before := journalSnapshot(t, db, false)
		if err := db.FinishIngestRun(context.Background(), "not-a-uuid/missing", "success", "full", "", at); !errors.Is(err, sql.ErrNoRows) || journalSnapshot(t, db, false) != before {
			t.Fatal("missing arbitrary ID changed semantics")
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if err := db.FinishIngestRun(cancelled, "missing", "invalid", "unknown", "PRIVATE", at); err == nil || err.Error() != "ingest runの完了状態が不正です" {
			t.Fatal("result/coverage/time validation did not precede code/context/SQL")
		}
		if err := db.FinishIngestRun(cancelled, "missing", "failed", "unknown", "PRIVATE", at); err == nil || err.Error() != "ingest error codeが不正です" {
			t.Fatal("machine-code validation did not precede context/SQL")
		}
		if run, err := db.StartIngestRun(cancelled, "", "scope", at); err == nil || !reflect.DeepEqual(run, model.IngestRun{}) || err.Error() != "ingest runのsource/scope/時刻が未設定です" {
			t.Fatal("Start input validation order/zero result changed")
		}
		run := ingestGuardContractPositive(t, db, "ignore-fixture", "scope", at)
		if err := db.FinishIngestRun(context.Background(), run.ID, "failed", "unknown", "", at.Add(-time.Second)); err == nil || err.Error() != "ingest run終了が開始より前です" {
			t.Fatal("caller-provided finish clock comparison changed")
		}
		if _, err := db.db.Exec("CREATE TRIGGER ingest_guard_ignore BEFORE UPDATE ON ingest_runs WHEN NEW.connector='ignore-fixture' BEGIN SELECT RAISE(IGNORE); END"); err != nil {
			t.Fatal(err)
		}
		before = journalSnapshot(t, db, false)
		if err := db.FinishIngestRun(context.Background(), run.ID, "success", "full", "", at.Add(time.Minute)); err != nil || journalSnapshot(t, db, false) != before {
			t.Fatal("legacy RowsAffected=0 must remain an unchecked nil result")
		}
	})
}

type ingestGuardContractLostReturn struct {
	db       *Store
	calls    int
	retained model.IngestRun
}

func (w *ingestGuardContractLostReturn) start(at time.Time) (model.IngestRun, error) {
	w.calls++
	run, err := w.db.StartIngestRun(context.Background(), "epss_feed", "synthetic-owned-scope", at)
	if err != nil {
		return run, err
	}
	w.retained = run
	return model.IngestRun{}, errors.New("synthetic start return lost")
}

func (w *ingestGuardContractLostReturn) finish(run model.IngestRun, at time.Time) error {
	w.calls++
	if err := w.db.FinishIngestRun(context.Background(), run.ID, "success", "full", "", at); err != nil {
		return err
	}
	utc := at.UTC()
	run.FinishedAt, run.Result, run.Coverage = &utc, "success", "full"
	w.retained = run
	return errors.New("synthetic finish return lost")
}

func TestLegacyIngestGuardContractIndependentConnectionsRollbackAndLostReturn(t *testing.T) {
	probe := ingestGuardContractRunning(t, "epss", 3350)
	ingestGuardContractStartReject(t, probe.db, "epss_feed", probe.completion.Attempt.StartedAt)

	t.Run("store-opened-before-adoption", func(t *testing.T) {
		f := legacyGuardContractFixtureFor(t, "epss", 3351)
		var path string
		if err := f.db.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
			t.Fatal("owned SQLite path unavailable")
		}
		second, err := NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		legacyGuardContractPrepare(t, &f, "begin", false, true)
		fencedContractAppend(t, f.db, f.fenced)
		fencedContractApply(t, f.db, f.fenced, "running")
		ingestGuardContractStartReject(t, second, "epss_feed", f.completion.Attempt.StartedAt)
		ingestGuardContractFinishReject(t, second, f.completion.Attempt.RunID, f.completion.FinishedAt, true)
	})
	t.Run("reserve-versus-start-at-most-one-path-no-progress-promise", func(t *testing.T) {
		db := journalOwnedStore(t)
		var path string
		if err := db.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
			t.Fatal("owned SQLite path unavailable")
		}
		second, err := NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		request := reservationContractRequest(t, 3352, "epss_feed")
		at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
		type result struct {
			reserve bool
			ack     SecurityEnrichmentReservationAcknowledgement
			run     model.IngestRun
			err     error
		}
		start, results := make(chan struct{}), make(chan result, 2)
		go func() {
			<-start
			ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), request)
			results <- result{reserve: true, ack: ack, err: err}
		}()
		go func() {
			<-start
			run, err := second.StartIngestRun(context.Background(), "epss_feed", "synthetic-owned-scope", at)
			results <- result{run: run, err: err}
		}()
		close(start)
		successes := 0
		for i := 0; i < 2; i++ {
			out := <-results
			if out.err == nil {
				successes++
				if out.reserve && !reservationContractAckMatches(out.ack, request, false) || !out.reserve && !securityUUID(out.run.ID) {
					t.Fatal("competing acknowledged result lost exact identity")
				}
			} else if out.reserve && !reflect.DeepEqual(out.ack, SecurityEnrichmentReservationAcknowledgement{}) || !out.reserve && errors.Is(out.err, ErrIngestConflict) && !reflect.DeepEqual(out.run, model.IngestRun{}) {
				t.Fatal("failed competing operation exposed acknowledgement")
			}
		}
		var runs, bindings int
		if err := db.db.QueryRow("SELECT COUNT(*) FROM ingest_runs WHERE connector='epss_feed'").Scan(&runs); err != nil {
			t.Fatal(err)
		}
		if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_reservations").Scan(&bindings); err != nil || runs > 1 || bindings > 1 || runs+bindings > 1 || successes > 1 || successes > runs+bindings {
			t.Fatal("adoption and an unguarded legacy write both committed")
		}
		reservationContractCounts(t, db, bindings, bindings, bindings, bindings)
		// Read-only stored state is not ownership or a reason to retry. Lock
		// and commit failures need not guarantee progress for either caller.
		before := journalSnapshot(t, db, false)
		if bindings == 1 {
			proof, err := db.ReadSecurityEnrichmentReservation(context.Background(), request)
			if err != nil || proof.State != "matched" || !reservationContractAckMatches(proof.Acknowledgement, request, true) {
				t.Fatal("atomic reservation lacks its exact storage proof")
			}
		}
		if journalSnapshot(t, db, false) != before {
			t.Fatal("competition readback wrote data")
		}
	})
	t.Run("trigger-rollback-keeps-id-after-generation-and-old-finish-state", func(t *testing.T) {
		db := journalOwnedStore(t)
		at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
		if _, err := db.db.Exec("CREATE TRIGGER ingest_guard_start_abort BEFORE INSERT ON ingest_runs WHEN NEW.connector='epss_feed' BEGIN SELECT RAISE(ABORT,'synthetic-start-block'); END"); err != nil {
			t.Fatal(err)
		}
		before := journalSnapshot(t, db, false)
		run, err := db.StartIngestRun(context.Background(), "epss_feed", "scope", at)
		if err == nil || !securityUUID(run.ID) || run.Connector != "epss_feed" || !run.StartedAt.Equal(at) || journalSnapshot(t, db, false) != before {
			t.Fatal("post-generation INSERT failure lost retained run or left partial data")
		}
		nonfeed := ingestGuardContractPositive(t, db, "dependabot", "scope", at)
		if _, err := db.db.Exec("CREATE TRIGGER ingest_guard_finish_abort BEFORE UPDATE ON ingest_runs BEGIN SELECT RAISE(ABORT,'synthetic-finish-block'); END"); err != nil {
			t.Fatal(err)
		}
		before = journalSnapshot(t, db, false)
		if err := db.FinishIngestRun(context.Background(), nonfeed.ID, "success", "full", "", at.Add(time.Minute)); err == nil || journalSnapshot(t, db, false) != before {
			t.Fatal("failed Finish left partial data")
		}
	})
	t.Run("real-commit-then-outer-lost-return-is-not-driver-commit-injection", func(t *testing.T) {
		db := journalOwnedStore(t)
		at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
		wrapper := &ingestGuardContractLostReturn{db: db}
		run, err := wrapper.start(at)
		if err == nil || !reflect.DeepEqual(run, model.IngestRun{}) || wrapper.calls != 1 || !securityUUID(wrapper.retained.ID) {
			t.Fatal("synthetic lost return did not follow one actual successful commit")
		}
		before := journalSnapshot(t, db, false)
		var body string
		if err := db.db.QueryRow("SELECT body_json FROM ingest_runs WHERE id=?", wrapper.retained.ID).Scan(&body); err != nil {
			t.Fatal(err)
		}
		var stored model.IngestRun
		if err := json.Unmarshal([]byte(body), &stored); err != nil || !reflect.DeepEqual(stored, wrapper.retained) {
			t.Fatal("actual same-UUID committed test row absent")
		}
		// This owned-SQLite inspection is test evidence, not a new public
		// exact-proof API. No manifest/completion is invented for ReadAttempt,
		// no ownership is granted, and the uncertain caller does not retry.
		if wrapper.calls != 1 || journalSnapshot(t, db, false) != before {
			t.Fatal("unknown-outcome inspection retried or mutated a write")
		}
		// Finish loss uses a separate, acknowledged Start; an uncertain Start
		// above is never followed by another business operation.
		other := journalOwnedStore(t)
		known := ingestGuardContractPositive(t, other, "dependabot", "scope", at)
		finishWrapper := &ingestGuardContractLostReturn{db: other}
		if err := finishWrapper.finish(known, at.Add(time.Minute)); err == nil || finishWrapper.calls != 1 {
			t.Fatal("Finish lost-return fixture did not follow one successful update")
		}
		before = journalSnapshot(t, other, false)
		if err := other.db.QueryRow("SELECT body_json FROM ingest_runs WHERE id=?", known.ID).Scan(&body); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(body), &stored); err != nil || !reflect.DeepEqual(stored, finishWrapper.retained) || stored.ID != known.ID || finishWrapper.calls != 1 || journalSnapshot(t, other, false) != before {
			t.Fatal("Finish uncertain-return inspection retried or changed same-ID evidence")
		}
	})
}
