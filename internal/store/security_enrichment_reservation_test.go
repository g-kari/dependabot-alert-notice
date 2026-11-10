package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func reservationReadOnlyReject(t *testing.T, db *Store, request SecurityEnrichmentReservationRequest, want string) {
	t.Helper()
	before := journalSnapshot(t, db, false)
	proof, readErr := db.ReadSecurityEnrichmentReservation(context.Background(), request)
	if proof.State != want || (readErr != nil) != (want == "unknown") || !reflect.DeepEqual(proof.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) || proof.HeadSequence != 0 || proof.HeadDigest != "" {
		t.Fatalf("rejected reservation proof=%+v err=%v want=%s", proof, readErr, want)
	}
	if readErr != nil && strings.Contains(readErr.Error(), "PRIVATE") {
		t.Fatal("raw stored content leaked")
	}
	ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), request)
	if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, db, false) != before {
		t.Fatal("rejected/read-only path exposed ack, leaked raw error or changed a table")
	}
}

func TestReservationSourceCASFailureRollsBackEveryNewRow(t *testing.T) {
	for _, action := range []string{"RAISE(ABORT,'PRIVATE-source-cas')", "RAISE(IGNORE)"} {
		t.Run(action, func(t *testing.T) {
			db := journalOwnedStore(t)
			request := reservationContractRequest(t, 2280, "epss_feed")
			if _, err := db.db.Exec("CREATE TRIGGER source_cas_abort BEFORE UPDATE ON security_enrichment_source_generations BEGIN SELECT " + action + "; END"); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, db, false)
			ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), request)
			if err == nil || strings.Contains(err.Error(), "PRIVATE") || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || journalSnapshot(t, db, false) != before {
				t.Fatal("failed/zero-row source CAS retained a partial reservation")
			}
			reservationContractCounts(t, db, 0, 0, 0, 0)
			if _, err := db.db.Exec("DROP TRIGGER source_cas_abort"); err != nil {
				t.Fatal(err)
			}
			reservationContractRequire(t, db, request)
		})
	}
}

func TestReservationInvalidRequestsCancelAndNilStoreNeverProduceProof(t *testing.T) {
	original := reservationContractRequest(t, 2200, "epss_feed")
	for _, kind := range []string{"intent", "extra-hyphens", "operation", "generation-negative", "generation-overflow", "sequence", "previous", "digest", "cursor", "source", "stage"} {
		t.Run(kind, func(t *testing.T) {
			request := original
			switch kind {
			case "intent":
				request.IntentID = strings.Repeat("PRIVATE", 10000)
			case "extra-hyphens":
				request.IntentID = "a2000000-0000-4000-8000-0000000000--"
			case "operation":
				request.Reserved.Checkpoint.OperationID = "A1000000-0000-4000-8000-000000002200"
			case "generation-negative":
				request.ExpectedGeneration = -1
			case "generation-overflow":
				request.ExpectedGeneration = reservationMaxGeneration
			case "sequence":
				request.Reserved.Sequence = 2
			case "previous":
				request.Reserved.PreviousDigest = original.ReservedDigest
			case "digest":
				request.ReservedDigest = "sha256:" + strings.Repeat("f", 64)
			case "cursor":
				request.Reserved.Checkpoint.Request.After = strings.Repeat("x", 129)
			case "source":
				request.Reserved.Checkpoint.Request.Connector = "epss_offline"
			case "stage":
				request.Reserved.Checkpoint.Stage = enrichmentjournal.Begin
			}
			var absent *Store
			ack, err := absent.ReserveSecurityEnrichmentOperation(context.Background(), request)
			proof, readErr := absent.ReadSecurityEnrichmentReservation(context.Background(), request)
			if err == nil || readErr == nil || strings.Contains(err.Error(), "PRIVATE") || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || proof.State != "unknown" || proof.HeadDigest != "" {
				t.Fatal("invalid request reached nil dependency or became a proof")
			}
		})
	}
	db := journalOwnedStore(t)
	before := journalSnapshot(t, db, false)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer expire()
	for _, ctx := range []context.Context{nil, cancelled, expired} {
		ack, err := db.ReserveSecurityEnrichmentOperation(ctx, original)
		proof, readErr := db.ReadSecurityEnrichmentReservation(ctx, original)
		if err == nil || readErr == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || proof.State != "unknown" || proof.HeadDigest != "" || journalSnapshot(t, db, false) != before {
			t.Fatal("invalid/cancelled context initialized or proved a reservation")
		}
		if ctx != nil && (!errors.Is(err, ctx.Err()) || !errors.Is(readErr, ctx.Err())) {
			t.Fatal("context error identity lost")
		}
	}
	var absent *Store
	if ack, err := absent.ReserveSecurityEnrichmentOperation(context.Background(), original); err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) {
		t.Fatal("valid request accepted by nil Store")
	}
	if proof, err := absent.ReadSecurityEnrichmentReservation(context.Background(), original); err == nil || proof.State != "unknown" || proof.HeadDigest != "" {
		t.Fatal("nil Store returned a read proof")
	}
}

func TestReservationStorageIsSourceBoundAndCopiesExactEscapedPayload(t *testing.T) {
	db := journalOwnedStore(t)
	epss := reservationContractRequest(t, 2210, "epss_feed")
	epss.Reserved.Checkpoint.Request.After = strings.Repeat("\\\"", 64)
	epss.Reserved.Checkpoint.Progress.NextAfter = epss.Reserved.Checkpoint.Request.After
	reservationContractDigest(t, &epss)
	payload, err := enrichmentjournal.Encode(epss.Reserved.Checkpoint)
	if err != nil || len(payload) >= enrichmentjournal.MaxCheckpointBytes {
		t.Fatal("bounded maximum-escape reserved request does not fit")
	}
	reservationContractRequire(t, db, epss)
	kev := reservationContractRequest(t, 2211, "kev_feed")
	reservationContractRequire(t, db, kev)
	reservationContractCounts(t, db, 2, 2, 2, 2)
	before := journalSnapshot(t, db, false)
	if _, err := db.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	proof, err := db.ReadSecurityEnrichmentReservation(context.Background(), epss)
	if err != nil || proof.State != "matched" || !reservationContractAckMatches(proof.Acknowledgement, epss, true) {
		t.Fatal("exact escaped payload was not retained")
	}
	proof.Acknowledgement.IntentID, proof.HeadDigest = "PRIVATE-caller", "PRIVATE-head"
	changed := epss
	changed.Reserved.Checkpoint.Request.Limit = 1
	reservationContractDigest(t, &changed)
	wrong, err := db.ReadSecurityEnrichmentReservation(context.Background(), changed)
	if err != nil || wrong.State != "conflict" || wrong.HeadDigest != "" {
		t.Fatal("mutated request retained the old binding")
	}
	again, err := db.ReadSecurityEnrichmentReservation(context.Background(), epss)
	if err != nil || !reservationContractAckMatches(again.Acknowledgement, epss, true) || journalSnapshot(t, db, false) != before {
		t.Fatal("caller mutation or read-only proof changed private/DB state")
	}
}

func TestReservationRejectsBoundStorageCorruptionWithoutRepair(t *testing.T) {
	for _, kind := range []string{"binding-payload-blob", "binding-oversize", "binding-space", "binding-digest", "binding-identity-alias", "intent-alias", "connector-alias", "source-alias", "source-third-row", "source-incomplete-pair", "source-generation-blob", "source-overflow", "source-positive-idle", "source-active-orphan", "binding-orphan", "checkpoint-orphan", "checkpoint-digest", "journal-source-alias"} {
		t.Run(kind, func(t *testing.T) {
			db := journalOwnedStore(t)
			request := reservationContractRequest(t, 2220, "epss_feed")
			reservationContractRequire(t, db, request)
			for _, query := range []string{"PRAGMA foreign_keys=OFF", "PRAGMA ignore_check_constraints=ON"} {
				if _, err := db.db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			query := ""
			var args []any
			switch kind {
			case "binding-payload-blob":
				query = "UPDATE security_enrichment_reservations SET reserved_payload_json=CAST(reserved_payload_json AS BLOB)"
			case "binding-oversize":
				query, args = "UPDATE security_enrichment_reservations SET reserved_payload_json=?", []any{strings.Repeat(" ", enrichmentjournal.MaxCheckpointBytes+1)}
			case "binding-space":
				query = "UPDATE security_enrichment_reservations SET reserved_payload_json=' '||reserved_payload_json"
			case "binding-digest":
				query, args = "UPDATE security_enrichment_reservations SET reserved_digest=?", []any{"sha256:" + strings.Repeat("f", 64)}
			case "binding-identity-alias":
				query = "UPDATE security_enrichment_reservations SET operation_id=CAST(operation_id AS BLOB)"
			case "intent-alias":
				query = "UPDATE security_enrichment_reservations SET intent_id=CAST(intent_id AS BLOB)"
			case "connector-alias":
				query = "UPDATE security_enrichment_reservations SET connector=CAST(connector AS BLOB)"
			case "source-alias":
				query = "UPDATE security_enrichment_source_generations SET connector=CAST(connector AS BLOB) WHERE connector='epss_feed'"
			case "source-third-row":
				query = "INSERT INTO security_enrichment_source_generations VALUES('PRIVATE-unknown',0,NULL,NULL)"
			case "source-incomplete-pair":
				query = "DELETE FROM security_enrichment_source_generations WHERE connector='kev_feed'"
			case "source-generation-blob":
				query = "UPDATE security_enrichment_source_generations SET generation=CAST(generation AS BLOB) WHERE connector='epss_feed'"
			case "source-overflow":
				query = "UPDATE security_enrichment_source_generations SET generation=9223372036854775808 WHERE connector='epss_feed'"
			case "source-positive-idle":
				query = "UPDATE security_enrichment_source_generations SET active_operation_id=NULL,active_intent_id=NULL WHERE connector='epss_feed'"
			case "source-active-orphan":
				query = "UPDATE security_enrichment_source_generations SET active_operation_id='a1000000-0000-4000-8000-000000009999' WHERE connector='epss_feed'"
			case "binding-orphan":
				query = "DELETE FROM security_enrichment_reservations"
			case "checkpoint-orphan":
				query = "DELETE FROM security_enrichment_checkpoints"
			case "checkpoint-digest":
				query, args = "UPDATE security_enrichment_checkpoints SET payload_digest=?", []any{"sha256:" + strings.Repeat("f", 64)}
			case "journal-source-alias":
				query = "UPDATE security_enrichment_operations SET connector=CAST(connector AS BLOB)"
			}
			if _, err := db.db.Exec(query, args...); err != nil {
				t.Fatal(err)
			}
			reservationReadOnlyReject(t, db, request, "unknown")
		})
	}
}

func TestReservationIdleOrMissingSourceCannotHideIntentOrJournalOrphans(t *testing.T) {
	db := journalOwnedStore(t)
	request := reservationContractRequest(t, 2230, "epss_feed")
	reservationContractRequire(t, db, request)
	if _, err := db.db.Exec("DELETE FROM security_enrichment_source_generations"); err != nil {
		t.Fatal(err)
	}
	reservationReadOnlyReject(t, db, request, "unknown")
}

func TestReservationLegacyFeedTerminalAndOtherSourceJournalBlockInitialEnrollment(t *testing.T) {
	for _, kind := range []string{"success", "failed", "other-source-reserved"} {
		t.Run(kind, func(t *testing.T) {
			db, c := refreshContractFixture(t, "epss", 2240)
			if kind == "other-source-reserved" {
				frame := journalStoreFrames(t)[0]
				frame.Request.Connector = "kev_feed"
				appendJournalFrame(t, db, frame, 1, "")
			} else {
				if _, err := db.BeginSecurityEnrichmentRefresh(context.Background(), c.Attempt); err != nil {
					t.Fatal(err)
				}
				if kind == "success" {
					if _, err := db.CompleteSecurityEnrichmentRefresh(context.Background(), c); err != nil {
						t.Fatal(err)
					}
				} else if _, err := db.FailSecurityEnrichmentRefresh(context.Background(), c.Attempt, "fetch_failed", c.FinishedAt); err != nil {
					t.Fatal(err)
				}
			}
			before := journalSnapshot(t, db, false)
			ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), reservationContractRequest(t, 2241, "epss_feed"))
			if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || journalSnapshot(t, db, false) != before {
				t.Fatal("legacy success/failure/other-source history was adopted or changed")
			}
		})
	}
}

func reservationUpgradeOldSnapshot(t *testing.T, db *Store) string {
	t.Helper()
	var tables map[string][][]any
	if err := json.Unmarshal([]byte(journalSnapshot(t, db, false)), &tables); err != nil {
		t.Fatal(err)
	}
	delete(tables, "security_enrichment_reservations")
	delete(tables, "security_enrichment_source_generations")
	var migrations [][]any
	for _, row := range tables["app_migrations"] {
		if row[0] != float64(5) {
			migrations = append(migrations, row)
		}
	}
	tables["app_migrations"] = migrations
	data, err := json.Marshal(tables)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestReservationAdditiveUpgradePreservesNonemptyOldRowsAndIndexesDetection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-reservation-upgrade.sqlite")
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
	run, item := importFixture()
	if _, err := db.ImportSecurityFindings(context.Background(), run, []model.SecurityFinding{item}); err != nil {
		t.Fatal(err)
	}
	value := 0.25
	if err := db.UpsertThreat(context.Background(), "epss", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-9876", EPSS: &value, FetchedAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}}); err != nil {
		t.Fatal(err)
	}
	frames := journalStoreFrames(t)
	previous := ""
	for i, frame := range frames[:4] {
		ack := appendJournalFrame(t, db, frame, int64(i+1), previous)
		previous = ack.Digest
	}
	for _, query := range []string{"DROP TABLE security_enrichment_source_generations", "DROP TABLE security_enrichment_reservations", "DROP INDEX security_enrichment_operation_source", "DELETE FROM app_migrations WHERE version=5"} {
		if _, err := db.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	before := reservationUpgradeOldSnapshot(t, db)
	var receiptCount, journalCount int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM ingest_runs").Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_checkpoints").Scan(&journalCount); err != nil || receiptCount == 0 || journalCount == 0 || !strings.Contains(before, "CVE-2026-9876") {
		t.Fatal("nonempty legacy/receipt/journal upgrade fixture missing")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if reservationUpgradeOldSnapshot(t, db) != before {
		t.Fatal("additive reservation migration changed an old table row")
	}
	var marker, indexes int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM app_migrations WHERE version=5").Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if err := db.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('security_enrichment_operation_source','ingest_runs_scope_lookup')").Scan(&indexes); err != nil || marker != 1 || indexes != 2 {
		t.Fatal("new marker/indexes not installed exactly once")
	}
	for _, check := range []struct{ query, index string }{
		{"SELECT 1 FROM ingest_runs WHERE connector='epss_feed' LIMIT 1", "ingest_runs_scope_lookup"},
		{"SELECT 1 FROM security_enrichment_operations WHERE connector='epss_feed' LIMIT 1", "security_enrichment_operation_source"},
	} {
		rows, err := db.db.Query("EXPLAIN QUERY PLAN " + check.query)
		if err != nil {
			t.Fatal(err)
		}
		used := false
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			used = used || strings.Contains(detail, check.index)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			t.Fatal(err)
		}
		if err := rows.Close(); err != nil || !used {
			t.Fatalf("source existence lookup did not use index %s: %v", check.index, err)
		}
	}
	rejectBefore := journalSnapshot(t, db, false)
	ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), reservationContractRequest(t, 2250, "epss_feed"))
	if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || journalSnapshot(t, db, false) != rejectBefore {
		t.Fatal("upgrade silently enrolled pre-existing journal")
	}
}

func TestReservationAdvancedGenericHeadAndBusinessAPIsRemainUnfenced(t *testing.T) {
	db, c := refreshContractFixture(t, "epss", 2260)
	frames := inspectionContractFrames(t, c, 2260)
	request := reservationContractRequest(t, 2260, "epss_feed")
	for i := range frames {
		frames[i].OperationID = request.Reserved.Checkpoint.OperationID
	}
	request.Reserved.Checkpoint = frames[0]
	reservationContractDigest(t, &request)
	reservationContractRequire(t, db, request)
	appendJournalFrame(t, db, frames[1], 2, request.ReservedDigest)
	// This slice intentionally does NOT enforce business-write fencing or add
	// guards to old APIs. The capability remains unconnected/experimental.
	if _, err := db.BeginSecurityEnrichmentRefresh(context.Background(), c.Attempt); err != nil {
		t.Fatal("old Begin API behavior changed")
	}
	reservationReadOnlyReject(t, db, request, "conflict")
}

func TestReservationReadErrorsAndClosedDBNeverReturnProof(t *testing.T) {
	db := journalOwnedStore(t)
	request := reservationContractRequest(t, 2270, "epss_feed")
	reservationContractRequire(t, db, request)
	if _, err := db.db.Exec("ALTER TABLE security_enrichment_reservations RENAME TO PRIVATE_unavailable_reservations"); err != nil {
		t.Fatal(err)
	}
	reservationReadOnlyReject(t, db, request, "unknown")
	closed, err := NewWithPath(filepath.Join(t.TempDir(), "closed-reservation.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	ack, err := closed.ReserveSecurityEnrichmentOperation(context.Background(), request)
	proof, readErr := closed.ReadSecurityEnrichmentReservation(context.Background(), request)
	if err == nil || readErr == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) || proof.State != "unknown" || proof.HeadDigest != "" {
		t.Fatal("closed DB yielded reservation proof")
	}
}
