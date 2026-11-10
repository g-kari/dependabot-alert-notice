package store

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// These are behavior contracts against the existing public APIs, not new
// stubs. Every top-level contract starts with a valid adopted-source call
// which succeeds on the unguarded baseline and must instead be rejected.
type legacyGuardContractFixture struct {
	db         *Store
	completion SecurityEnrichmentRefreshCompletion
	root       SecurityEnrichmentReservationRequest
	frames     []enrichmentjournal.Checkpoint
	call       enrichmentjournal.AppendRequest
	fenced     SecurityEnrichmentFencedRequest
}

func legacyGuardContractFixtureFor(t *testing.T, source string, id int) legacyGuardContractFixture {
	t.Helper()
	db, completion := refreshContractFixture(t, source, id)
	root := reservationContractRequest(t, id, source+"_feed")
	frames := inspectionContractFrames(t, completion, id)
	for i := range frames {
		frames[i].OperationID = root.Reserved.Checkpoint.OperationID
	}
	root.Reserved.Checkpoint = frames[0]
	reservationContractDigest(t, &root)
	return legacyGuardContractFixture{db: db, completion: completion, root: root, frames: frames}
}

func legacyGuardContractPrepare(t *testing.T, f *legacyGuardContractFixture, api string, replay, adopted bool) {
	t.Helper()
	ctx := context.Background()
	if adopted {
		reservationContractRequire(t, f.db, f.root)
	} else {
		appendJournalFrame(t, f.db, f.frames[0], 1, "")
	}
	begin := fencedContractRequest(t, f.root, f.frames[1], 2, f.root.ReservedDigest)
	f.fenced, f.call = begin, begin.Checkpoint
	if api == "append" {
		if replay {
			f.call = f.root.Reserved
		}
		return
	}
	if api == "begin" && !replay {
		return
	}
	if adopted {
		fencedContractAppend(t, f.db, begin)
		fencedContractApply(t, f.db, begin, "running")
	} else {
		appendJournalFrame(t, f.db, f.frames[1], 2, f.root.ReservedDigest)
		if got, err := f.db.BeginSecurityEnrichmentRefresh(ctx, f.completion.Attempt); err != nil || got {
			t.Fatalf("valid unadopted Begin precondition replay=%v err=%v", got, err)
		}
	}
	if api == "begin" {
		return
	}
	stage := f.frames[2]
	business := "success"
	if api == "fail" {
		stage = f.frames[1]
		prepared := *stage.Prepared
		prepared.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: f.completion.FinishedAt}
		stage.Stage, stage.Prepared = enrichmentjournal.Fail, &prepared
		business = "failed"
	}
	f.fenced = fencedContractRequest(t, f.root, stage, 3, begin.CheckpointDigest)
	if adopted {
		fencedContractAppend(t, f.db, f.fenced)
	} else {
		appendJournalFrame(t, f.db, stage, 3, begin.CheckpointDigest)
	}
	if replay {
		if adopted {
			fencedContractApply(t, f.db, f.fenced, business)
		} else if api == "complete" {
			result, err := f.db.CompleteSecurityEnrichmentRefresh(ctx, f.completion)
			if err != nil || result.Replay || result.Entries != len(f.completion.Feed.Entries) {
				t.Fatalf("valid unadopted Complete precondition=%+v err=%v", result, err)
			}
		} else if got, err := f.db.FailSecurityEnrichmentRefresh(ctx, f.completion.Attempt, "fetch_failed", f.completion.FinishedAt); err != nil || got {
			t.Fatalf("valid unadopted Fail precondition replay=%v err=%v", got, err)
		}
	}
}

func legacyGuardContractCall(db *Store, api string, f legacyGuardContractFixture) (bool, bool, error) {
	ctx := context.Background()
	switch api {
	case "append":
		ack, err := db.AppendSecurityEnrichmentCheckpoint(ctx, f.call)
		return reflect.DeepEqual(ack, enrichmentjournal.Acknowledgement{}), ack.Replay, err
	case "begin":
		replay, err := db.BeginSecurityEnrichmentRefresh(ctx, f.completion.Attempt)
		return !replay, replay, err
	case "complete":
		result, err := db.CompleteSecurityEnrichmentRefresh(ctx, f.completion)
		return reflect.DeepEqual(result, SecurityEnrichmentImportResult{}), result.Replay, err
	case "fail":
		replay, err := db.FailSecurityEnrichmentRefresh(ctx, f.completion.Attempt, "fetch_failed", f.completion.FinishedAt)
		return !replay, replay, err
	default:
		panic("unknown test API")
	}
}

func legacyGuardContractReject(t *testing.T, db *Store, api string, f legacyGuardContractFixture) {
	t.Helper()
	before := journalSnapshot(t, db, false)
	zero, _, err := legacyGuardContractCall(db, api, f)
	if err == nil {
		t.Fatalf("adopted-source legacy %s must be rejected; valid generic call succeeded", api)
	}
	if !zero || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, db, false) != before {
		t.Fatalf("refused legacy %s exposed acknowledgement/raw error or changed a table: %v", api, err)
	}
}

func legacyGuardContractProbe(t *testing.T, id int) {
	t.Helper()
	f := legacyGuardContractFixtureFor(t, "epss", id)
	legacyGuardContractPrepare(t, &f, "append", false, true)
	legacyGuardContractReject(t, f.db, "append", f)
}

func TestLegacyFeedGuardContractFourGenericAPIsDenyAdoptedFreshAndReplay(t *testing.T) {
	for sourceIndex, source := range []string{"epss", "kev"} {
		for apiIndex, api := range []string{"append", "begin", "complete", "fail"} {
			for _, replay := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/replay-%v", source, api, replay), func(t *testing.T) {
					id := 2700 + sourceIndex*100 + apiIndex*10
					if replay {
						id++
					}
					// The same valid shape must work on a genuinely unadopted
					// source. A malformed fixture is not evidence for this Red.
					control := legacyGuardContractFixtureFor(t, source, id+1000)
					legacyGuardContractPrepare(t, &control, api, replay, false)
					if _, gotReplay, err := legacyGuardContractCall(control.db, api, control); err != nil || gotReplay != replay {
						t.Fatalf("unadopted positive control %s replay=%v err=%v", api, gotReplay, err)
					}
					f := legacyGuardContractFixtureFor(t, source, id)
					legacyGuardContractPrepare(t, &f, api, replay, true)
					legacyGuardContractReject(t, f.db, api, f)
					if !replay {
						// Shared private helpers used by the explicit fenced
						// entrypoints must not inherit the legacy public guard.
						switch api {
						case "append":
							fencedContractAppend(t, f.db, f.fenced)
						case "begin":
							fencedContractAppend(t, f.db, f.fenced)
							fencedContractApply(t, f.db, f.fenced, "running")
						case "complete":
							fencedContractApply(t, f.db, f.fenced, "success")
						case "fail":
							fencedContractApply(t, f.db, f.fenced, "failed")
						}
					}
				})
			}
		}
	}
}

func TestLegacyFeedGuardContractCorruptOrPositiveIdleNeverMeansUnadopted(t *testing.T) {
	legacyGuardContractProbe(t, 2900)
	queries := []struct{ name, query string }{
		{"source-blob-alias", "UPDATE security_enrichment_source_generations SET connector=CAST(connector AS BLOB) WHERE connector='epss_feed'"},
		{"source-incomplete-pair", "DELETE FROM security_enrichment_source_generations WHERE connector='kev_feed'"},
		{"registry-missing-reservation-remains", "DELETE FROM security_enrichment_source_generations"},
		{"idle-zero-reservation-remains", "UPDATE security_enrichment_source_generations SET generation=0,active_operation_id=NULL,active_intent_id=NULL WHERE connector='epss_feed'"},
		{"generation-blob", "UPDATE security_enrichment_source_generations SET generation=CAST(generation AS BLOB) WHERE connector='epss_feed'"},
		// This is an owned malformed/forward-state fixture, not a release
		// certificate or proof of positive-idle reservation eligibility.
		{"positive-idle-still-adopted", "UPDATE security_enrichment_source_generations SET active_operation_id=NULL,active_intent_id=NULL WHERE connector='epss_feed'"},
	}
	for index, corrupt := range queries {
		for apiIndex, api := range []string{"append", "begin", "complete", "fail"} {
			t.Run(corrupt.name+"/"+api, func(t *testing.T) {
				f := legacyGuardContractFixtureFor(t, "epss", 2910+index*10+apiIndex)
				legacyGuardContractPrepare(t, &f, api, false, true)
				for _, query := range []string{"PRAGMA foreign_keys=OFF", "PRAGMA ignore_check_constraints=ON", corrupt.query} {
					if _, err := f.db.db.Exec(query); err != nil {
						t.Fatal(err)
					}
				}
				legacyGuardContractReject(t, f.db, api, f)
			})
		}
	}
	t.Run("other-source-idle-zero-offline-and-legacy-remain-independent", func(t *testing.T) {
		f := legacyGuardContractFixtureFor(t, "epss", 2980)
		legacyGuardContractPrepare(t, &f, "append", false, true)
		var generation int
		if err := f.db.db.QueryRow("SELECT generation FROM security_enrichment_source_generations WHERE connector='kev_feed'").Scan(&generation); err != nil || generation != 0 {
			t.Fatal("other source is not genuinely unadopted")
		}
		at := f.completion.Feed.ObservedAt
		_, feed := enrichmentFixture(t, 2981, "kev", at.Add(-time.Hour), at)
		other := f.completion
		other.Attempt.RunID, other.Attempt.Connector, other.Feed = "10000000-0000-4000-8000-000000002981", "kev_feed", feed
		if replay, err := f.db.BeginSecurityEnrichmentRefresh(context.Background(), other.Attempt); err != nil || replay {
			t.Fatalf("unadopted other-source Begin rejected: %v", err)
		}
		if result, err := f.db.CompleteSecurityEnrichmentRefresh(context.Background(), other); err != nil || result.Replay || result.Entries != 1 {
			t.Fatalf("unadopted other-source Complete rejected: %+v %v", result, err)
		}
		otherRoot := reservationContractRequest(t, 2983, "kev_feed")
		if ack, err := f.db.AppendSecurityEnrichmentCheckpoint(context.Background(), otherRoot.Reserved); err != nil || ack.Replay || ack.Digest != otherRoot.ReservedDigest {
			t.Fatalf("unadopted other-source Append rejected: %+v %v", ack, err)
		}
		failed := other.Attempt
		failed.RunID = "10000000-0000-4000-8000-000000002984"
		if _, err := f.db.BeginSecurityEnrichmentRefresh(context.Background(), failed); err != nil {
			t.Fatal(err)
		}
		if replay, err := f.db.FailSecurityEnrichmentRefresh(context.Background(), failed, "fetch_failed", other.FinishedAt); err != nil || replay {
			t.Fatalf("unadopted other-source Fail rejected: %v", err)
		}
		// An honest offline origin may publish independent common facts even
		// when epss_feed is adopted. This guard is not an exclusive facts lock.
		run, feed := enrichmentFixture(t, 2982, "epss", at.Add(-time.Hour), at)
		if result, err := f.db.ImportSecurityEnrichment(context.Background(), run, feed); err != nil || result.Replay || result.Entries != 1 {
			t.Fatalf("independent offline enrichment rejected: %+v %v", result, err)
		}
		value := 0.25
		if err := f.db.UpsertThreat(context.Background(), "epss", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-9876", EPSS: &value, FetchedAt: at}}); err != nil {
			t.Fatal(err)
		}
		detail, err := f.db.GetFindingDetail(context.Background(), f.completion.Attempt.Targets[0].FindingID)
		if err != nil || detail.Enrichment == nil || detail.Enrichment.EPSS == nil || detail.Enrichment.EPSS.EPSS == nil || *detail.Enrichment.EPSS.EPSS != 0 || detail.Enrichment.EPSS.RunID != run.ID || detail.Enrichment.KEV == nil || !detail.Enrichment.KEV.KEV || detail.Enrichment.KEV.RunID != other.Attempt.RunID {
			t.Fatal("independent offline/other-source common facts are absent")
		}
		var legacyRows int
		if err := f.db.db.QueryRow("SELECT COUNT(*) FROM threat_snapshots WHERE advisory_key='cve:CVE-2026-9876'").Scan(&legacyRows); err != nil || legacyRows != 1 {
			t.Fatal("nonempty legacy threat row is absent")
		}
		if !f.db.SaveObserved(phase0Record()) {
			t.Fatal("default dependabot projection was blocked")
		}
		// Compare the actual bound operation, not all facts: the legitimate
		// offline, legacy and default writes are intentionally non-exclusive.
		proof, err := f.db.ReadSecurityEnrichmentReservation(context.Background(), f.root)
		if err != nil || proof.State != "matched" || !reservationContractAckMatches(proof.Acknowledgement, f.root, true) {
			t.Fatal("offline/legacy writes changed binding or failed to retain nonempty data")
		}
		legacyGuardContractReject(t, f.db, "append", f)
	})
}

func TestLegacyFeedGuardContractOpenConnectionsCompetitionAndRollback(t *testing.T) {
	legacyGuardContractProbe(t, 3000)
	t.Run("store-opened-before-adoption-reads-current-database", func(t *testing.T) {
		f := legacyGuardContractFixtureFor(t, "epss", 3001)
		var path string
		if err := f.db.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
			t.Fatal("owned SQLite path unavailable")
		}
		second, err := NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		legacyGuardContractPrepare(t, &f, "append", false, true)
		legacyGuardContractReject(t, second, "append", f)
		begin := f.fenced
		fencedContractAppend(t, f.db, begin)
		f.call = begin.Checkpoint
		legacyGuardContractReject(t, second, "begin", f)
		fencedContractApply(t, f.db, begin, "running")
		legacyGuardContractReject(t, second, "begin", f)
		complete := fencedContractRequest(t, f.root, f.frames[2], 3, begin.CheckpointDigest)
		fencedContractAppend(t, f.db, complete)
		legacyGuardContractReject(t, second, "complete", f)
		legacyGuardContractReject(t, second, "fail", f)
		fencedContractApply(t, f.db, complete, "success")
		legacyGuardContractReject(t, second, "complete", f)
	})
	t.Run("independent-connection-cp-race-has-no-legacy-winner", func(t *testing.T) {
		f := legacyGuardContractFixtureFor(t, "epss", 3002)
		legacyGuardContractPrepare(t, &f, "append", false, true)
		var path string
		if err := f.db.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
			t.Fatal("owned SQLite path unavailable")
		}
		second, err := NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		beforeBusiness := reservationContractOldData(t, f.db)
		type result struct {
			legacy bool
			zero   bool
			err    error
		}
		start, results := make(chan struct{}), make(chan result, 2)
		go func() {
			<-start
			zero, _, err := legacyGuardContractCall(second, "append", f)
			results <- result{true, zero, err}
		}()
		go func() {
			<-start
			ack, err := f.db.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), f.fenced)
			results <- result{false, reflect.DeepEqual(ack, SecurityEnrichmentFencedAcknowledgement{}), err}
		}()
		close(start)
		for i := 0; i < 2; i++ {
			got := <-results
			if got.legacy && (got.err == nil || !got.zero) || got.err != nil && !got.zero {
				t.Fatal("legacy concurrent append acquired acknowledgement")
			}
		}
		var count, head int
		if err := f.db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_checkpoints WHERE operation_id=?", f.root.Reserved.Checkpoint.OperationID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if err := f.db.db.QueryRow("SELECT head_sequence FROM security_enrichment_operations WHERE operation_id=?", f.root.Reserved.Checkpoint.OperationID).Scan(&head); err != nil || count < 1 || count > 2 || head != count || reservationContractOldData(t, f.db) != beforeBusiness {
			t.Fatal("competition left partial CP/head or changed business rows")
		}
		// A lock or commit error need not promise progress. Readback is not a
		// retry, a business success receipt or an execution-ownership grant.
		beforeRead := journalSnapshot(t, f.db, false)
		proof, err := f.db.ReadSecurityEnrichmentFencedCheckpoint(context.Background(), f.fenced)
		if err != nil || (proof.State == "matched") != (count == 2) || proof.Business.Receipt != "" || journalSnapshot(t, f.db, false) != beforeRead {
			t.Fatal("competition readback mismatched exact committed checkpoint")
		}
	})
	t.Run("unadopted-trigger-rollback-and-adopted-private-path-rollback", func(t *testing.T) {
		for _, adopted := range []bool{false, true} {
			f := legacyGuardContractFixtureFor(t, "epss", 3003)
			legacyGuardContractPrepare(t, &f, "append", false, adopted)
			if _, err := f.db.db.Exec("CREATE TRIGGER legacy_guard_cp_abort BEFORE INSERT ON security_enrichment_checkpoints WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'PRIVATE-block'); END"); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, f.db, false)
			if adopted {
				legacyGuardContractReject(t, f.db, "append", f)
				ack, err := f.db.AppendSecurityEnrichmentFencedCheckpoint(context.Background(), f.fenced)
				if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentFencedAcknowledgement{}) || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("fenced trigger failure exposed acknowledgement/raw text")
				}
			} else {
				zero, _, err := legacyGuardContractCall(f.db, "append", f)
				if err == nil || !zero || strings.Contains(err.Error(), "PRIVATE") {
					t.Fatal("unadopted trigger failure exposed acknowledgement/raw text")
				}
			}
			if journalSnapshot(t, f.db, false) != before {
				t.Fatal("trigger failure left partial writes")
			}
		}
	})
}
