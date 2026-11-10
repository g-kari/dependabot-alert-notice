package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func reservationContractRequest(t *testing.T, id int, connector string) SecurityEnrichmentReservationRequest {
	t.Helper()
	checkpoint := journalStoreFrames(t)[0]
	checkpoint.OperationID = fmt.Sprintf("a1000000-0000-4000-8000-%012d", id)
	checkpoint.Request.Connector = connector
	request := SecurityEnrichmentReservationRequest{IntentID: fmt.Sprintf("a2000000-0000-4000-8000-%012d", id), Reserved: enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: checkpoint}}
	reservationContractDigest(t, &request)
	return request
}
func reservationContractDigest(t *testing.T, request *SecurityEnrichmentReservationRequest) {
	t.Helper()
	payload, err := enrichmentjournal.Encode(request.Reserved.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	request.ReservedDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
}
func reservationContractAckMatches(a SecurityEnrichmentReservationAcknowledgement, request SecurityEnrichmentReservationRequest, replay bool) bool {
	return a.IntentID == request.IntentID && a.Connector == request.Reserved.Checkpoint.Request.Connector && a.Generation == request.ExpectedGeneration+1 &&
		a.Journal.OperationID == request.Reserved.Checkpoint.OperationID && a.Journal.Sequence == 1 && a.Journal.Digest == request.ReservedDigest && a.Journal.Replay == replay
}
func reservationContractRequire(t *testing.T, db *Store, request SecurityEnrichmentReservationRequest) SecurityEnrichmentReservationAcknowledgement {
	t.Helper()
	ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !reservationContractAckMatches(ack, request, false) {
		t.Fatalf("fresh atomic storage proof mismatched: %+v", ack)
	}
	return ack
}
func reservationContractOldData(t *testing.T, db *Store) string {
	t.Helper()
	var tables map[string]json.RawMessage
	if err := json.Unmarshal([]byte(journalSnapshot(t, db, false)), &tables); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"security_enrichment_operations", "security_enrichment_checkpoints", "security_enrichment_reservations", "security_enrichment_source_generations"} {
		delete(tables, table)
	}
	data, err := json.Marshal(tables)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func reservationContractCounts(t *testing.T, db *Store, operations, checkpoints, intents, active int) {
	t.Helper()
	for table, want := range map[string]int{"security_enrichment_operations": operations, "security_enrichment_checkpoints": checkpoints, "security_enrichment_reservations": intents, "security_enrichment_source_generations WHERE active_operation_id IS NOT NULL": active} {
		var count int
		if err := db.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != want {
			t.Fatalf("atomic table=%s count=%d want=%d err=%v", table, count, want, err)
		}
	}
}

func TestOperationReservationContractAtomicBindingAndExactReplay(t *testing.T) {
	db := journalOwnedStore(t)
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	value := 0.25
	if err := db.UpsertThreat(context.Background(), "epss", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-9876", EPSS: &value, FetchedAt: at}}); err != nil {
		t.Fatal(err)
	}
	beforeOld := reservationContractOldData(t, db)
	if !strings.Contains(beforeOld, "CVE-2026-9876") {
		t.Fatal("legacy preservation fixture is empty")
	}
	request := reservationContractRequest(t, 2100, "epss_feed")
	reservationContractRequire(t, db, request)
	reservationContractCounts(t, db, 1, 1, 1, 1)
	if reservationContractOldData(t, db) != beforeOld {
		t.Fatal("reservation changed existing legacy/business rows")
	}
	var generation int64
	var active string
	if err := db.db.QueryRow("SELECT generation,active_operation_id FROM security_enrichment_source_generations WHERE connector=?", "epss_feed").Scan(&generation, &active); err != nil || generation != 1 || active != request.Reserved.Checkpoint.OperationID {
		t.Fatalf("source CAS not bound to reserved operation generation=%d active=%s err=%v", generation, active, err)
	}
	beforeReplay := journalSnapshot(t, db, false)
	replay, err := db.ReserveSecurityEnrichmentOperation(context.Background(), request)
	if err != nil || !reservationContractAckMatches(replay, request, true) || journalSnapshot(t, db, false) != beforeReplay {
		t.Fatal("exact replay rewrote reservation/source/journal or changed its proof")
	}
	for _, kind := range []string{"intent", "operation", "source", "request", "generation", "sequence", "previous", "digest"} {
		t.Run(kind, func(t *testing.T) {
			wrong := request
			switch kind {
			case "intent":
				wrong.IntentID = "a2000000-0000-4000-8000-000000002101"
			case "operation":
				wrong.Reserved.Checkpoint.OperationID = "a1000000-0000-4000-8000-000000002101"
			case "source":
				wrong.Reserved.Checkpoint.Request.Connector = "kev_feed"
			case "request":
				wrong.Reserved.Checkpoint.Request.After, wrong.Reserved.Checkpoint.Progress.NextAfter = "cursor-x", "cursor-x"
			case "generation":
				wrong.ExpectedGeneration = 1
			case "sequence":
				wrong.Reserved.Sequence = 2
			case "previous":
				wrong.Reserved.PreviousDigest = "sha256:" + strings.Repeat("f", 64)
			}
			reservationContractDigest(t, &wrong)
			if kind == "digest" {
				wrong.ReservedDigest = "sha256:" + strings.Repeat("f", 64)
			}
			ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), wrong)
			if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || journalSnapshot(t, db, false) != beforeReplay {
				t.Fatalf("changed %s acquired proof or caused partial write: %+v %v", kind, ack, err)
			}
		})
	}
	runs, err := db.QueryIngestRuns(context.Background())
	if err != nil || len(runs) != 0 {
		t.Fatal("storage reservation fabricated a business UUID/receipt")
	}
}

type reservationContractLostReturn struct {
	db        *Store
	calls     int
	committed bool
}

func (r *reservationContractLostReturn) reserve(ctx context.Context, request SecurityEnrichmentReservationRequest) (SecurityEnrichmentReservationAcknowledgement, error) {
	r.calls++
	if _, err := r.db.ReserveSecurityEnrichmentOperation(ctx, request); err != nil {
		return SecurityEnrichmentReservationAcknowledgement{}, err
	}
	r.committed = true
	// A real Store commit followed by a synthetic lost return, not injection
	// into the SQLite driver's actual Commit result.
	return SecurityEnrichmentReservationAcknowledgement{}, errors.New("PRIVATE-lost-return")
}

func TestOperationReservationContractPostCommitLostReturnUsesOnlyExactReadonlyProof(t *testing.T) {
	db := journalOwnedStore(t)
	request := reservationContractRequest(t, 2110, "epss_feed")
	wrapper := &reservationContractLostReturn{db: db}
	ack, err := wrapper.reserve(context.Background(), request)
	if !wrapper.committed {
		t.Fatal(err)
	}
	if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || wrapper.calls != 1 {
		t.Fatal("lost return exposed ack or retried write")
	}
	before := journalSnapshot(t, db, false)
	proof, err := db.ReadSecurityEnrichmentReservation(context.Background(), request)
	if err != nil || proof.State != "matched" || !reservationContractAckMatches(proof.Acknowledgement, request, true) || proof.HeadSequence != 1 || proof.HeadDigest != request.ReservedDigest {
		t.Fatalf("same retained intent did not match: %+v %v", proof, err)
	}
	wrong := request
	wrong.IntentID = "a2000000-0000-4000-8000-000000002111"
	conflict, err := db.ReadSecurityEnrichmentReservation(context.Background(), wrong)
	if err != nil || conflict.State != "conflict" || !reflect.DeepEqual(conflict.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) || conflict.HeadDigest != "" || conflict.HeadSequence != 0 {
		t.Fatal("different intent received proof")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	unknown, err := db.ReadSecurityEnrichmentReservation(cancelled, request)
	if !errors.Is(err, context.Canceled) || unknown.State != "unknown" || !reflect.DeepEqual(unknown.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) || unknown.HeadDigest != "" {
		t.Fatal("canceled read exposed reservation proof")
	}
	if wrapper.calls != 1 || journalSnapshot(t, db, false) != before {
		t.Fatal("readback retried reserve or changed any table")
	}
	empty := journalOwnedStore(t)
	emptyBefore := journalSnapshot(t, empty, false)
	missing, err := empty.ReadSecurityEnrichmentReservation(context.Background(), request)
	if err != nil || missing.State != "missing" || !reflect.DeepEqual(missing.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) || missing.HeadDigest != "" || journalSnapshot(t, empty, false) != emptyBefore {
		t.Fatal("missing request acquired proof or initialized/repaired storage")
	}
}

func TestOperationReservationContractConnectionsRollbackAndLegacyAdmission(t *testing.T) {
	// This positive probe makes the new runtime contract fail at the new stub,
	// rather than at a missing schema/table or an unrelated pre-existing test.
	probe := journalOwnedStore(t)
	reservationContractRequire(t, probe, reservationContractRequest(t, 2120, "epss_feed"))

	t.Run("independent-connections-at-most-one-binding", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "owned-reservation-race.sqlite")
		first, err := NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = first.Close() }()
		second, err := NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		requests := []SecurityEnrichmentReservationRequest{reservationContractRequest(t, 2121, "epss_feed"), reservationContractRequest(t, 2122, "epss_feed")}
		type result struct {
			request SecurityEnrichmentReservationRequest
			ack     SecurityEnrichmentReservationAcknowledgement
			err     error
		}
		start := make(chan struct{})
		results := make(chan result, 2)
		for i, db := range []*Store{first, second} {
			go func(db *Store, request SecurityEnrichmentReservationRequest) {
				<-start
				ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), request)
				results <- result{request, ack, err}
			}(db, requests[i])
		}
		close(start)
		winners := 0
		for i := 0; i < 2; i++ {
			r := <-results
			if r.err == nil {
				winners++
				if !reservationContractAckMatches(r.ack, r.request, false) {
					t.Fatal("winner proof mismatched")
				}
			} else if !reflect.DeepEqual(r.ack, SecurityEnrichmentReservationAcknowledgement{}) {
				t.Fatal("loser exposed proof")
			}
		}
		if winners > 1 {
			t.Fatalf("independent source reservations had %d acknowledged winners", winners)
		}
		var stored int
		if err := first.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_reservations").Scan(&stored); err != nil || stored < winners || stored > 1 {
			t.Fatalf("competing reservation storage=%d acknowledgements=%d err=%v", stored, winners, err)
		}
		reservationContractCounts(t, first, stored, stored, stored, stored)
		// Lock/commit errors need not promise progress. Any committed binding
		// must still have one exact read-only proof; a loser cannot own it.
		beforeRead := journalSnapshot(t, first, false)
		matched := 0
		for _, request := range requests {
			proof, err := first.ReadSecurityEnrichmentReservation(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if proof.State == "matched" {
				matched++
				if !reservationContractAckMatches(proof.Acknowledgement, request, true) {
					t.Fatal("competition readback borrowed the other intent")
				}
			} else if (proof.State != "missing" && proof.State != "conflict") || !reflect.DeepEqual(proof.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) {
				t.Fatal("nonmatching competing intent exposed proof")
			}
		}
		if matched != stored || journalSnapshot(t, first, false) != beforeRead {
			t.Fatal("competition proof count differs from atomic storage or performed writes")
		}
	})

	t.Run("trigger-rollback-and-next-fresh-reservation", func(t *testing.T) {
		db := journalOwnedStore(t)
		request := reservationContractRequest(t, 2130, "epss_feed")
		if _, err := db.db.Exec("CREATE TRIGGER reservation_abort BEFORE INSERT ON security_enrichment_reservations BEGIN SELECT RAISE(ABORT,'PRIVATE-reservation-block'); END"); err != nil {
			t.Fatal(err)
		}
		before := journalSnapshot(t, db, false)
		ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), request)
		if err == nil || strings.Contains(err.Error(), "PRIVATE") || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || journalSnapshot(t, db, false) != before {
			t.Fatal("failed atomic reservation leaked data or left partial rows")
		}
		reservationContractCounts(t, db, 0, 0, 0, 0)
		if _, err := db.db.Exec("DROP TRIGGER reservation_abort"); err != nil {
			t.Fatal(err)
		}
		reservationContractRequire(t, db, request)
		reservationContractCounts(t, db, 1, 1, 1, 1)
	})

	for _, kind := range []string{"old-unbound-feed-running", "v1-pending-journal"} {
		t.Run(kind, func(t *testing.T) {
			db, c := refreshContractFixture(t, "epss", 2140)
			if kind == "old-unbound-feed-running" {
				if _, err := db.BeginSecurityEnrichmentRefresh(context.Background(), c.Attempt); err != nil {
					t.Fatal(err)
				}
			} else {
				frames := journalStoreFrames(t)
				previous := ""
				for i, frame := range frames[:4] {
					ack := appendJournalFrame(t, db, frame, int64(i+1), previous)
					previous = ack.Digest
				}
			}
			before := journalSnapshot(t, db, false)
			ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), reservationContractRequest(t, 2141, "epss_feed"))
			if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || journalSnapshot(t, db, false) != before {
				t.Fatal("legacy evidence was adopted, modified, failed or granted a new intent")
			}
			var intents, active int
			if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_reservations").Scan(&intents); err != nil {
				t.Fatal(err)
			}
			if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_source_generations WHERE active_operation_id IS NOT NULL").Scan(&active); err != nil || intents != 0 || active != 0 {
				t.Fatal("legacy admission refusal retained a partial new reservation")
			}
		})
	}
}
