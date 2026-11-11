package store

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrelease"
)

func admissionContractClose(t *testing.T, db *Store, source, kind string, id int, generation int64) (enrichmentrelease.ReleaseRequest, string) {
	t.Helper()
	reservation := reservationContractRequest(t, id, source+"_feed")
	reservation.ExpectedGeneration = generation - 1
	if kind == "no_run" {
		reservationContractRequire(t, db, reservation)
		// The last allowed active generation must still support exact replay/read.
		replay, err := db.ReserveSecurityEnrichmentOperation(context.Background(), reservation)
		if err != nil || !reservationContractAckMatches(replay, reservation, true) {
			t.Fatalf("active replay at generation %d: %v", generation, err)
		}
		proof, err := db.ReadSecurityEnrichmentReservation(context.Background(), reservation)
		if err != nil || proof.State != "matched" {
			t.Fatalf("active read at generation %d: %v", generation, err)
		}
		returned := reservation.Reserved.Checkpoint
		returned.Stage = enrichmentjournal.Returned
		returned.Progress.Outcome, returned.Progress.Exhausted = "exhausted", true
		terminal := fencedContractRequest(t, reservation, returned, 2, reservation.ReservedDigest)
		fencedContractAppend(t, db, terminal)
		request := releaseContractRequest(t, reservation, terminal)
		releaseContractRequire(t, db, request, "")
		return request, ""
	}
	_, completion := refreshContractFixture(t, source, id)
	page, err := db.QuerySecurityEnrichmentRefreshTargets(context.Background(), "", 200)
	if err != nil || len(page.Targets) == 0 {
		t.Fatalf("current targets: %+v %v", page, err)
	}
	completion.Attempt.Targets = page.Targets
	frames := inspectionContractFrames(t, completion, id)
	for i := range frames {
		frames[i].OperationID = reservation.Reserved.Checkpoint.OperationID
	}
	reservation.Reserved.Checkpoint = frames[0]
	reservationContractDigest(t, &reservation)
	reservationContractRequire(t, db, reservation)
	replay, err := db.ReserveSecurityEnrichmentOperation(context.Background(), reservation)
	if err != nil || !reservationContractAckMatches(replay, reservation, true) {
		t.Fatalf("business active replay: %v", err)
	}
	begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	fencedContractAppend(t, db, begin)
	fencedContractApply(t, db, begin, "running")
	write, returned := frames[2], frames[3]
	if kind == "failed" {
		write = frames[1]
		prepared := *write.Prepared
		prepared.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: completion.FinishedAt}
		write.Stage, write.Prepared = enrichmentjournal.Fail, &prepared
		returned = write
		returned.Stage = enrichmentjournal.Returned
		returned.Progress.Outcome, returned.Progress.Code, returned.Progress.Pending = "failed", "fetch_failed", false
	}
	prepared := fencedContractRequest(t, reservation, write, 3, begin.CheckpointDigest)
	fencedContractAppend(t, db, prepared)
	fencedContractApply(t, db, prepared, kind)
	business := fencedContractRead(t, db, prepared, true, kind)
	terminal := fencedContractRequest(t, reservation, returned, 4, prepared.CheckpointDigest)
	fencedContractAppend(t, db, terminal)
	request := releaseContractRequest(t, reservation, terminal)
	releaseContractRequire(t, db, request, business.Business.Receipt)
	return request, business.Business.Receipt
}

func admissionContractReject(t *testing.T, db *Store, next SecurityEnrichmentReservationRequest, corrupt bool) {
	t.Helper()
	before := journalSnapshot(t, db, false)
	ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), next)
	if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) {
		t.Fatalf("rejected candidate ack=%+v err=%v", ack, err)
	}
	if !corrupt && !errors.Is(err, errReservationConflict) {
		t.Fatalf("capacity/stale refusal: %v", err)
	}
	proof, err := db.ReadSecurityEnrichmentReservation(context.Background(), next)
	if corrupt {
		if err == nil || proof.State != "unknown" {
			t.Fatalf("corrupt read=%+v err=%v", proof, err)
		}
	} else if err != nil || proof.State != "conflict" {
		t.Fatalf("conflict read=%+v err=%v", proof, err)
	}
	if !reflect.DeepEqual(proof.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) || proof.HeadSequence != 0 || proof.HeadDigest != "" || journalSnapshot(t, db, false) != before {
		t.Fatal("refusal acknowledged or changed storage")
	}
}

func TestGenerationAdmissionContractFiniteLifetimeBothSourcesAllBranches(t *testing.T) {
	for _, source := range []string{"epss", "kev"} {
		for _, kind := range []string{"success", "failed", "no_run"} {
			t.Run(source+"-"+kind, func(t *testing.T) {
				db, first, receipt := releaseContractFixture(t, source, kind, 4500)
				firstAck := releaseContractRequire(t, db, first, receipt)
				var last enrichmentrelease.ReleaseRequest
				var lastReceipt string
				for generation := int64(2); generation <= reservationHistoryLimit; generation++ {
					last, lastReceipt = admissionContractClose(t, db, source, kind, 4500+int(generation), generation)
					releaseContractRead(t, db, first, firstAck)
				}
				releaseContractRead(t, db, last, releaseContractExpected(t, last, lastReceipt))
				next := reservationContractRequest(t, 4510, source+"_feed")
				next.ExpectedGeneration = reservationHistoryLimit
				admissionContractReject(t, db, next, false)
				stale := SecurityEnrichmentReservationRequest{IntentID: first.Reservation.IntentID, ExpectedGeneration: first.Reservation.ExpectedGeneration, Reserved: first.Reservation.Reserved, ReservedDigest: first.Reservation.ReservedDigest}
				admissionContractReject(t, db, stale, false)
				other := "epss"
				if source == "epss" {
					other = "kev"
				}
				// Exhaustion is per source, not a shared quota.
				admissionContractClose(t, db, other, "no_run", 4511, 1)
				releaseContractRead(t, db, first, firstAck)
			})
		}
	}
}

func TestGenerationAdmissionContractReprovesOldBusinessAfterLaterClosure(t *testing.T) {
	for _, damage := range []string{"receipt", "manifest", "observation", "failure", "root", "journal"} {
		t.Run(damage, func(t *testing.T) {
			kind := "success"
			if damage == "failure" {
				kind = "failed"
			}
			db, first, receipt := releaseContractFixture(t, "epss", kind, 4520)
			releaseContractRequire(t, db, first, receipt)
			admissionContractClose(t, db, "epss", "no_run", 4521, 2)
			releaseGreenAllowOwnedCorruption(t, db)
			run := first.Terminal.Checkpoint.Prepared.Attempt.RunID
			query := ""
			switch damage {
			case "receipt":
				query = "UPDATE ingest_runs SET result='running' WHERE id=?"
			case "manifest":
				query = "DELETE FROM security_enrichment_runs WHERE ingest_run_id=?"
			case "observation":
				query = "DELETE FROM security_enrichment_observations WHERE ingest_run_id=?"
			case "failure":
				query = "UPDATE ingest_runs SET error='other' WHERE id=?"
			case "root":
				query = "UPDATE security_enrichment_reservations SET reserved_digest='sha256:" + strings.Repeat("f", 64) + "' WHERE operation_id=?"
				run = first.Reservation.Reserved.Checkpoint.OperationID
			case "journal":
				query = "DELETE FROM security_enrichment_checkpoints WHERE operation_id=? AND sequence=2"
				run = first.Reservation.Reserved.Checkpoint.OperationID
			}
			if _, err := db.db.Exec(query, run); err != nil {
				t.Fatal(err)
			}
			next := reservationContractRequest(t, 4522, "epss_feed")
			next.ExpectedGeneration = 2
			admissionContractReject(t, db, next, true)
		})
	}
}

func TestGenerationAdmissionContractMetadataRejectsGapsAliasesAndOverflow(t *testing.T) {
	for _, table := range []string{"security_enrichment_reservations", "security_enrichment_release_certificates"} {
		for _, damage := range []string{"gap", "connector-alias", "generation-alias", "duplicate-alias", "overflow"} {
			t.Run(table+"-"+damage, func(t *testing.T) {
				db, first, receipt := releaseContractFixture(t, "kev", "no_run", 4530)
				releaseContractRequire(t, db, first, receipt)
				admissionContractClose(t, db, "kev", "no_run", 4531, 2)
				releaseGreenAllowOwnedCorruption(t, db)
				query := ""
				switch damage {
				case "gap":
					query = "DELETE FROM " + table + " WHERE generation=1"
				case "connector-alias":
					query = "UPDATE " + table + " SET connector=CAST(connector AS BLOB) WHERE generation=1"
				case "generation-alias":
					query = "UPDATE " + table + " SET generation=CAST(generation AS BLOB) WHERE generation=1"
				case "duplicate-alias":
					query = `INSERT INTO security_enrichment_reservations
SELECT CAST(operation_id AS BLOB),CAST(intent_id AS BLOB),CAST(connector AS BLOB),expected_generation,generation,reserved_digest,reserved_payload_json
FROM security_enrichment_reservations WHERE generation=1`
					if table == "security_enrichment_release_certificates" {
						query = `INSERT INTO security_enrichment_release_certificates
SELECT CAST(operation_id AS BLOB),CAST(intent_id AS BLOB),CAST(connector AS BLOB),generation,format_version,reserved_digest,terminal_sequence,terminal_previous_digest,terminal_digest,kind,run_id,receipt,certificate_digest,certificate_json
FROM security_enrichment_release_certificates WHERE generation=1`
					}
				case "overflow":
					query = fmt.Sprintf("UPDATE %s SET generation=%d WHERE generation=1", table, reservationHistoryLimit+1)
				}
				if _, err := db.db.Exec(query); err != nil {
					t.Fatal(err)
				}
				next := reservationContractRequest(t, 4532, "kev_feed")
				next.ExpectedGeneration = 2
				admissionContractReject(t, db, next, true)
			})
		}
	}
}

// Payload expressions in this owned view raise a SQLite error if selected.
// A premature first-source payload read would yield storage, not the expected
// second-source metadata corruption. No production schema/view is changed.
func TestGenerationAdmissionContractBothSourceOverflowPrecedesPayloadRead(t *testing.T) {
	for _, table := range []string{"security_enrichment_reservations", "security_enrichment_release_certificates"} {
		t.Run(table, func(t *testing.T) {
			db, first, receipt := releaseContractFixture(t, "kev", "no_run", 4540)
			releaseContractRequire(t, db, first, receipt)
			active := reservationContractRequest(t, 4541, "epss_feed")
			reservationContractRequire(t, db, active)
			releaseGreenAllowOwnedCorruption(t, db)
			for generation := 2; generation <= reservationHistoryLimit+1; generation++ {
				operation := fmt.Sprintf("a1000000-0000-4000-8000-%012d", 4550+generation)
				intent := fmt.Sprintf("a2000000-0000-4000-8000-%012d", 4550+generation)
				query := `INSERT INTO security_enrichment_reservations
(operation_id,intent_id,connector,expected_generation,generation,reserved_digest,reserved_payload_json)
SELECT ?,?,connector,?-1,?,reserved_digest,reserved_payload_json FROM security_enrichment_reservations WHERE connector='kev_feed' AND generation=1`
				args := []any{operation, intent, generation, generation}
				if table == "security_enrichment_release_certificates" {
					query = `INSERT INTO security_enrichment_release_certificates
(operation_id,intent_id,connector,generation,format_version,reserved_digest,terminal_sequence,terminal_previous_digest,terminal_digest,kind,run_id,receipt,certificate_digest,certificate_json)
SELECT ?,?,connector,?,format_version,reserved_digest,terminal_sequence,terminal_previous_digest,terminal_digest,kind,run_id,receipt,certificate_digest,certificate_json
FROM security_enrichment_release_certificates WHERE connector='kev_feed' AND generation=1`
					args = []any{operation, intent, generation}
				}
				if _, err := db.db.Exec(query, args...); err != nil {
					t.Fatal(err)
				}
			}
			for _, statement := range []string{
				"ALTER TABLE security_enrichment_reservations RENAME TO owned_admission_bindings",
				`CREATE VIEW security_enrichment_reservations AS SELECT operation_id,intent_id,connector,expected_generation,generation,reserved_digest,
json_extract('PRIVATE-invalid-json','$') AS reserved_payload_json FROM owned_admission_bindings`,
			} {
				if _, err := db.db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), active)
			if !errors.Is(err, errReservationCorrupt) || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) {
				t.Fatalf("overflow did not precede payload proof: %+v %v", ack, err)
			}
		})
	}
}

func TestGenerationAdmissionContractUnboundEvidenceStillBlocksPositiveIdle(t *testing.T) {
	for _, residue := range []string{"receipt", "journal"} {
		t.Run(residue, func(t *testing.T) {
			db, first, receipt := releaseContractFixture(t, "epss", "success", 4560)
			releaseContractRequire(t, db, first, receipt)
			query := `INSERT INTO ingest_runs
SELECT '10000000-0000-4000-8000-000000004561',connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json
FROM ingest_runs WHERE connector='epss_feed'`
			if residue == "journal" {
				query = `INSERT INTO security_enrichment_operations
SELECT 'a1000000-0000-4000-8000-000000004561',format_version,connector,request_after,request_limit,NULL,head_sequence,head_digest
FROM security_enrichment_operations WHERE connector='epss_feed'`
			}
			if _, err := db.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			next := reservationContractRequest(t, 4562, "epss_feed")
			next.ExpectedGeneration = 1
			admissionContractReject(t, db, next, false)
		})
	}
}
