package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrelease"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func releaseGreenReject(t *testing.T, db *Store, request enrichmentrelease.ReleaseRequest) {
	t.Helper()
	before := journalSnapshot(t, db, false)
	ack, err := db.ReleaseSecurityEnrichmentOperation(context.Background(), request)
	if err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("unproved release succeeded or leaked a provider value")
	}
	releaseContractNoAck(t, ack)
	proof, err := db.ReadSecurityEnrichmentRelease(context.Background(), request)
	if err == nil || proof.State != "unknown" || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("damaged proof was not unknown/corrupt: %+v %v", proof, err)
	}
	releaseContractNoAck(t, proof.Acknowledgement)
	if journalSnapshot(t, db, false) != before {
		t.Fatal("corruption refusal wrote or repaired a table")
	}
}

func releaseGreenMigrationSnapshot(t *testing.T, db *Store) string {
	t.Helper()
	var tables map[string][][]any
	if err := json.Unmarshal([]byte(journalSnapshot(t, db, false)), &tables); err != nil {
		t.Fatal(err)
	}
	delete(tables, "security_enrichment_release_certificates")
	var migrations [][]any
	for _, row := range tables["app_migrations"] {
		if len(row) == 0 || row[0] != float64(6) {
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

// Reconstructs the immediately preceding schema in an owned file. This is not
// an old-binary execution or operational database migration/restore test.
func TestOperationReleaseAdditiveUpgradePreservesPreexistingReceiptsAndLegacyData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-release-upgrade.sqlite")
	db, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if db != nil {
			_ = db.Close()
		}
	})
	run, item := importFixture()
	if _, err := db.ImportSecurityFindings(context.Background(), run, []model.SecurityFinding{item}); err != nil {
		t.Fatal(err)
	}
	value := 0.0
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	if err := db.UpsertThreat(context.Background(), "epss", []model.ThreatSnapshot{{AdvisoryKey: "cve:CVE-2026-9876", EPSS: &value, FetchedAt: at}}); err != nil {
		t.Fatal(err)
	}
	var receipts int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM ingest_runs").Scan(&receipts); err != nil || receipts == 0 {
		t.Fatal("upgrade receipt preservation fixture is empty")
	}
	if _, err := db.db.Exec("DROP TABLE security_enrichment_release_certificates"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec("DELETE FROM app_migrations WHERE version=6"); err != nil {
		t.Fatal(err)
	}
	before := releaseGreenMigrationSnapshot(t, db)
	if !strings.Contains(before, "CVE-2026-9876") {
		t.Fatal("upgrade legacy preservation fixture is empty")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if releaseGreenMigrationSnapshot(t, db) != before {
		t.Fatal("additive release upgrade changed an old row")
	}
	var migration, certificates, withoutRowID int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM app_migrations WHERE version=6").Scan(&migration); err != nil || migration != 1 {
		t.Fatal("release migration record missing")
	}
	if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_release_certificates").Scan(&certificates); err != nil || certificates != 0 {
		t.Fatal("migration invented a certificate")
	}
	if err := db.db.QueryRow("SELECT wr FROM pragma_table_list WHERE name='security_enrichment_release_certificates'").Scan(&withoutRowID); err != nil || withoutRowID != 1 {
		t.Fatal("upgrade did not create WITHOUT ROWID certificate storage")
	}
}

// SQLite RAISE(IGNORE) is a successful SQL statement without the intended
// insert/update. The public write cannot acknowledge a nonexistent or restored
// pair even when no driver error is returned.
func TestOperationReleaseSuppressedOrRestoredWriteNeverAcknowledges(t *testing.T) {
	for index, statement := range []string{
		"CREATE TRIGGER release_green_ignore BEFORE INSERT ON security_enrichment_release_certificates BEGIN SELECT RAISE(IGNORE); END",
		"CREATE TRIGGER release_green_ignore BEFORE UPDATE ON security_enrichment_source_generations WHEN NEW.active_operation_id IS NULL BEGIN SELECT RAISE(IGNORE); END",
		"CREATE TRIGGER release_green_restore AFTER UPDATE ON security_enrichment_source_generations WHEN NEW.active_operation_id IS NULL BEGIN UPDATE security_enrichment_source_generations SET active_operation_id=OLD.active_operation_id,active_intent_id=OLD.active_intent_id WHERE connector=OLD.connector; END",
	} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			db, request, _ := releaseContractFixture(t, "epss", "success", 4460+index)
			if _, err := db.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, db, false)
			ack, err := db.ReleaseSecurityEnrichmentOperation(context.Background(), request)
			if err == nil {
				t.Fatal("suppressed/restored release obtained acknowledgement")
			}
			releaseContractNoAck(t, ack)
			if journalSnapshot(t, db, false) != before {
				t.Fatal("suppressed/restored write left a partial certificate/source pair")
			}
		})
	}
}

func TestOperationReleaseCertificateIsWithoutRowIDAndImmutableUnderOrdinaryDML(t *testing.T) {
	db, request, receipt := releaseContractFixture(t, "epss", "success", 4300)
	ack := releaseContractRequire(t, db, request, receipt)
	var withoutRowID int
	if err := db.db.QueryRow("SELECT wr FROM pragma_table_list WHERE name='security_enrichment_release_certificates'").Scan(&withoutRowID); err != nil || withoutRowID != 1 {
		t.Fatal("certificate table retains a hidden rowid replacement path")
	}
	var definition string
	if err := db.db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='security_enrichment_release_certificates'").Scan(&definition); err != nil || !strings.Contains(definition, "operation_id TEXT NOT NULL PRIMARY KEY") {
		t.Fatal("certificate primary key is not explicitly NOT NULL")
	}
	if _, err := db.db.Exec("PRAGMA recursive_triggers=OFF"); err != nil {
		t.Fatal(err)
	}
	before := journalSnapshot(t, db, false)
	for _, statement := range []string{
		"DELETE FROM security_enrichment_release_certificates",
		"UPDATE security_enrichment_release_certificates SET receipt=receipt",
		"UPDATE OR REPLACE security_enrichment_release_certificates SET operation_id='a1000000-0000-4000-8000-000000009991',intent_id='a2000000-0000-4000-8000-000000009991',connector='kev_feed',generation=99",
		"INSERT OR REPLACE INTO security_enrichment_release_certificates SELECT * FROM security_enrichment_release_certificates",
	} {
		if _, err := db.db.Exec(statement); err == nil || !strings.Contains(err.Error(), "release certificate immutable") {
			t.Fatalf("ordinary immutable DML reached another constraint or succeeded: %s %v", statement, err)
		}
		if journalSnapshot(t, db, false) != before {
			t.Fatal("immutable DML changed the stored certificate/source/evidence")
		}
	}
	columns := "operation_id,intent_id,connector,generation,format_version,reserved_digest,terminal_sequence,terminal_previous_digest,terminal_digest,kind,run_id,receipt,certificate_digest,certificate_json"
	for _, collision := range []string{"operation", "intent", "source-generation"} {
		operation := "'a1000000-0000-4000-8000-000000009992'"
		intent := "'a2000000-0000-4000-8000-000000009992'"
		connector, generation := "'kev_feed'", "99"
		switch collision {
		case "operation":
			operation = "operation_id"
		case "intent":
			intent = "intent_id"
		case "source-generation":
			connector, generation = "connector", "generation"
		}
		statement := "INSERT OR REPLACE INTO security_enrichment_release_certificates(" + columns + ") SELECT " + operation + "," + intent + "," + connector + "," + generation +
			",format_version,reserved_digest,terminal_sequence,terminal_previous_digest,terminal_digest,kind,run_id,receipt,certificate_digest,certificate_json FROM security_enrichment_release_certificates"
		if _, err := db.db.Exec(statement); err == nil || !strings.Contains(err.Error(), "release certificate immutable") {
			t.Fatalf("logical %s REPLACE did not stop before FK/unique replacement: %v", collision, err)
		}
		if journalSnapshot(t, db, false) != before {
			t.Fatal("logical key REPLACE deleted the old row")
		}
	}
	// All logical keys differ. A normal TEXT-PK table could still replace
	// an old row by reusing its hidden rowid; WITHOUT ROWID removes it.
	if _, err := db.db.Exec("INSERT OR REPLACE INTO security_enrichment_release_certificates(rowid,operation_id,intent_id,connector,generation) VALUES(1,'a1000000-0000-4000-8000-000000009993','a2000000-0000-4000-8000-000000009993','kev_feed',99)"); err == nil || !strings.Contains(err.Error(), "rowid") {
		t.Fatal("hidden-rowid replacement path remains")
	}
	if journalSnapshot(t, db, false) != before {
		t.Fatal("hidden-rowid attempt changed data")
	}
	releaseContractRead(t, db, request, ack)
}

func TestOperationReleaseReprovesHistoricalBusinessAfterCertificateCommit(t *testing.T) {
	for index, damage := range []string{"receipt", "manifest", "observation", "failure-code", "failure-finish"} {
		t.Run(damage, func(t *testing.T) {
			kind := "success"
			if strings.HasPrefix(damage, "failure") {
				kind = "failed"
			}
			db, request, receipt := releaseContractFixture(t, "epss", kind, 4310+index)
			releaseContractRequire(t, db, request, receipt)
			id := request.Terminal.Checkpoint.Progress.RunID
			switch damage {
			case "observation":
				result, err := db.db.Exec("DELETE FROM security_enrichment_observations WHERE ingest_run_id=?", id)
				if err != nil {
					t.Fatal(err)
				}
				if count, err := result.RowsAffected(); err != nil || count == 0 {
					t.Fatal("observation damage fixture is empty")
				}
			case "manifest":
				if _, err := db.db.Exec("UPDATE security_enrichment_runs SET original_digest=? WHERE ingest_run_id=?", "sha256:"+strings.Repeat("f", 64), id); err != nil {
					t.Fatal(err)
				}
			default:
				var body string
				if err := db.db.QueryRow("SELECT body_json FROM ingest_runs WHERE id=?", id).Scan(&body); err != nil {
					t.Fatal(err)
				}
				var run model.IngestRun
				if err := json.Unmarshal([]byte(body), &run); err != nil {
					t.Fatal(err)
				}
				switch damage {
				case "receipt":
					run.Cursor = "refresh-success-v1:sha256:" + strings.Repeat("f", 64)
				case "failure-code":
					run.Error = "parse_failed"
				case "failure-finish":
					if run.FinishedAt == nil {
						t.Fatal("expected failure fixture has no finish")
					}
					finish := run.FinishedAt.Add(time.Nanosecond)
					run.FinishedAt = &finish
				}
				encoded, err := json.Marshal(run)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.db.Exec("UPDATE ingest_runs SET cursor=?,error=?,finished_at=?,body_json=? WHERE id=?", run.Cursor, run.Error, run.FinishedAt.UTC().Format(time.RFC3339Nano), string(encoded), id); err != nil {
					t.Fatal(err)
				}
			}
			releaseGreenReject(t, db, request)
			// Another source cannot use a certificate as an attestation while
			// its historical receipt/manifest/observation/failure is damaged.
			before := journalSnapshot(t, db, false)
			other := reservationContractRequest(t, 4350+index, "kev_feed")
			ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), other)
			if err == nil {
				t.Fatal("other-source admission trusted damaged closed history")
			}
			if !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) {
				t.Fatal("damaged historical proof exposed another reservation acknowledgement")
			}
			if journalSnapshot(t, db, false) != before {
				t.Fatal("historical damage admission rewrote evidence or source state")
			}
		})
	}
}

func TestOperationReleaseHistoricalProofIgnoresLegitimateNewCurrentFactsAndFindingRevision(t *testing.T) {
	db, request, receipt := releaseContractFixture(t, "epss", "success", 4360)
	ack := releaseContractRequire(t, db, request, receipt)
	prepared := request.Terminal.Checkpoint.Prepared
	if prepared == nil || prepared.Completion == nil {
		t.Fatal("positive fixture lacks full retained completion")
	}
	f := prepared.Completion.Feed
	newer, feed := enrichmentFixture(t, 4361, "epss", f.PublishedAt.Add(2*time.Hour), f.ObservedAt.Add(2*time.Hour))
	mustEnrichment(t, db, newer, feed)
	id := prepared.Attempt.Targets[0].FindingID
	if _, err := db.db.Exec("UPDATE findings SET body_json=json_set(body_json,'$.title','later legal synthetic revision') WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	detail, err := db.GetFindingDetail(context.Background(), id)
	if err != nil || detail.Enrichment == nil || detail.Enrichment.EPSS == nil || detail.Enrichment.EPSS.RunID != newer.ID {
		t.Fatal("positive fixture did not produce a distinct later common fact")
	}
	releaseContractRead(t, db, request, ack)
	// The old feed receipt remains valid historical evidence even though
	// the target's current revision and independent offline fact changed.
	other := reservationContractRequest(t, 4362, "kev_feed")
	reservationContractRequire(t, db, other)
}

func releaseGreenDualActive(t *testing.T, id int) (*Store, enrichmentrelease.ReleaseRequest, string, SecurityEnrichmentReservationRequest, SecurityEnrichmentFencedRequest, enrichmentjournal.Checkpoint) {
	t.Helper()
	db, request, receipt := releaseContractFixture(t, "epss", "success", id)
	_, _, completion := operationInspectionPrepared(*request.Terminal.Checkpoint.Prepared)
	if completion == nil {
		t.Fatal("dual-source fixture lacks completion")
	}
	completion.Attempt.RunID = fmt.Sprintf("10000000-0000-4000-8000-%012d", id+1)
	completion.Attempt.Connector = "kev_feed"
	_, completion.Feed = enrichmentFixture(t, id+1, "kev", completion.Feed.PublishedAt, completion.Feed.ObservedAt)
	completion.OriginalDigest = "sha256:" + strings.Repeat("b", 64)
	reservation := reservationContractRequest(t, id+1, "kev_feed")
	frames := inspectionContractFrames(t, *completion, id+1)
	for i := range frames {
		frames[i].OperationID = reservation.Reserved.Checkpoint.OperationID
	}
	reservation.Reserved.Checkpoint = frames[0]
	reservationContractDigest(t, &reservation)
	reservationContractRequire(t, db, reservation)
	begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	fencedContractAppend(t, db, begin)
	fencedContractApply(t, db, begin, "running")
	return db, request, receipt, reservation, begin, frames[2]
}

func TestOperationReleaseOneOfTwoActiveSourcesLeavesOtherFenceAndBusinessUsable(t *testing.T) {
	db, request, receipt, other, begin, completeFrame := releaseGreenDualActive(t, 4370)
	before := fencedContractRead(t, db, begin, true, "running")
	oldBusiness := releaseContractBusinessTables(t, db)
	var otherSourceBefore string
	if err := db.db.QueryRow("SELECT json_object('generation',generation,'operation',active_operation_id,'intent',active_intent_id) FROM security_enrichment_source_generations WHERE connector='kev_feed'").Scan(&otherSourceBefore); err != nil {
		t.Fatal(err)
	}
	ack := releaseContractRequire(t, db, request, receipt)
	var otherSourceAfter string
	if err := db.db.QueryRow("SELECT json_object('generation',generation,'operation',active_operation_id,'intent',active_intent_id) FROM security_enrichment_source_generations WHERE connector='kev_feed'").Scan(&otherSourceAfter); err != nil {
		t.Fatal(err)
	}
	after := fencedContractRead(t, db, begin, true, "running")
	if otherSourceAfter != otherSourceBefore || !reflect.DeepEqual(before, after) || releaseContractBusinessTables(t, db) != oldBusiness {
		t.Fatal("releasing one source changed the other active binding/head/business or any old row")
	}
	complete := fencedContractRequest(t, other, completeFrame, 3, begin.CheckpointDigest)
	fencedContractAppend(t, db, complete)
	fencedContractApply(t, db, complete, "success")
	fencedContractRead(t, db, complete, true, "success")
	releaseContractRead(t, db, request, ack)
	// Same terminal CP is still current in the journal, but its released
	// source is no longer an active fence for append/business/read.
	old := SecurityEnrichmentFencedRequest{
		Reservation: SecurityEnrichmentReservationRequest{IntentID: request.Reservation.IntentID, ExpectedGeneration: request.Reservation.ExpectedGeneration, Reserved: request.Reservation.Reserved, ReservedDigest: request.Reservation.ReservedDigest},
		Checkpoint:  request.Terminal, CheckpointDigest: request.TerminalDigest,
	}
	fencedContractRejectWithoutWrites(t, db, old)
}

func releaseGreenAllowOwnedCorruption(t *testing.T, db *Store) {
	t.Helper()
	// Only a test-owned database bypasses ordinary-DML immutability. This
	// models corrupt/admin-modified storage, not a product repair API.
	for _, statement := range []string{
		"DROP TRIGGER security_enrichment_release_insert_once",
		"DROP TRIGGER security_enrichment_release_no_update",
		"DROP TRIGGER security_enrichment_release_no_delete",
		"PRAGMA ignore_check_constraints=ON",
		"PRAGMA foreign_keys=OFF",
	} {
		if _, err := db.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOperationReleaseCertificateScalarAliasBoundsAndCanonicalCorruption(t *testing.T) {
	updates := []string{
		"operation_id=CAST(operation_id AS BLOB)",
		"intent_id=CAST(intent_id AS BLOB)",
		"connector=CAST(connector AS BLOB)",
		"certificate_json=CAST(certificate_json AS BLOB)",
		"certificate_json=printf('%05000d',0)",
		"certificate_json=' '||certificate_json",
		"kind='failed'",
		"certificate_digest='sha256:" + strings.Repeat("f", 64) + "'",
	}
	for index, update := range updates {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			db, request, receipt := releaseContractFixture(t, "epss", "success", 4390+index)
			releaseContractRequire(t, db, request, receipt)
			releaseGreenAllowOwnedCorruption(t, db)
			if _, err := db.db.Exec("UPDATE security_enrichment_release_certificates SET " + update); err != nil {
				t.Fatal(err)
			}
			releaseGreenReject(t, db, request)
		})
	}
}

func TestOperationReleaseCertificateOnlyResidualCannotResetEnrollmentOrLegacyGuard(t *testing.T) {
	for index, kind := range []string{"missing-registry", "idle-zero", "journal-intent-identity"} {
		t.Run(kind, func(t *testing.T) {
			db, request, receipt := releaseContractFixture(t, "epss", "no_run", 4410+index)
			releaseContractRequire(t, db, request, receipt)
			releaseGreenAllowOwnedCorruption(t, db)
			if kind == "journal-intent-identity" {
				// Certificate source/op and reservation source are corrupt,
				// but the original journal -> reservation intent still binds.
				if _, err := db.db.Exec("UPDATE security_enrichment_release_certificates SET connector='other',operation_id='a1000000-0000-4000-8000-000000009998'"); err != nil {
					t.Fatal(err)
				}
				if _, err := db.db.Exec("UPDATE security_enrichment_reservations SET connector='other'"); err != nil {
					t.Fatal(err)
				}
			} else {
				for _, table := range []string{"security_enrichment_checkpoints", "security_enrichment_reservations", "security_enrichment_operations"} {
					if _, err := db.db.Exec("DELETE FROM " + table); err != nil {
						t.Fatal(err)
					}
				}
			}
			statement := "UPDATE security_enrichment_source_generations SET generation=0,active_operation_id=NULL,active_intent_id=NULL"
			if kind == "missing-registry" {
				statement = "DELETE FROM security_enrichment_source_generations"
			}
			if _, err := db.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			before := journalSnapshot(t, db, false)
			next := reservationContractRequest(t, 4430+index, "epss_feed")
			ack, err := db.ReserveSecurityEnrichmentOperation(context.Background(), next)
			if err == nil || !reflect.DeepEqual(ack, SecurityEnrichmentReservationAcknowledgement{}) {
				t.Fatal("residual certificate reset source enrollment")
			}
			read, err := db.ReadSecurityEnrichmentReservation(context.Background(), next)
			if err == nil || read.State != "unknown" || !reflect.DeepEqual(read.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) {
				t.Fatal("residual certificate became clean missing/unadopted")
			}
			run, err := db.StartIngestRun(context.Background(), "epss_feed", "synthetic", time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
			if err == nil || !reflect.DeepEqual(run, model.IngestRun{}) || journalSnapshot(t, db, false) != before {
				t.Fatal("certificate-only adoption was bypassed by legacy Start")
			}
		})
	}
}

func TestOperationReleaseCancellationNilClosedReadErrorsAndIndependentReturn(t *testing.T) {
	db, request, receipt := releaseContractFixture(t, "epss", "success", 4450)
	before := journalSnapshot(t, db, false)
	for _, makeContext := range []func() (context.Context, context.CancelFunc){
		func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, cancel
		},
		func() (context.Context, context.CancelFunc) {
			return context.WithDeadline(context.Background(), time.Unix(1, 0))
		},
	} {
		ctx, cancel := makeContext()
		ack, err := db.ReleaseSecurityEnrichmentOperation(ctx, request)
		if !errors.Is(err, ctx.Err()) {
			t.Fatal("release lost cancellation/deadline identity")
		}
		releaseContractNoAck(t, ack)
		proof, err := db.ReadSecurityEnrichmentRelease(ctx, request)
		cancel()
		if !errors.Is(err, ctx.Err()) || proof.State != "unknown" {
			t.Fatal("canceled proof escaped or context identity changed")
		}
		releaseContractNoAck(t, proof.Acknowledgement)
	}
	if journalSnapshot(t, db, false) != before {
		t.Fatal("canceled release/read wrote")
	}
	var absent *Store
	closed := journalOwnedStore(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	for _, store := range []*Store{absent, closed} {
		ack, err := store.ReleaseSecurityEnrichmentOperation(context.Background(), request)
		if err == nil {
			t.Fatal("nil/closed Store released")
		}
		releaseContractNoAck(t, ack)
		proof, err := store.ReadSecurityEnrichmentRelease(context.Background(), request)
		if err == nil || proof.State != "unknown" {
			t.Fatal("nil/closed Store exposed proof")
		}
		releaseContractNoAck(t, proof.Acknowledgement)
	}
	ack := releaseContractRequire(t, db, request, receipt)
	want := releaseContractExpected(t, request, receipt)
	if ack.Certificate.RunID == nil {
		t.Fatal("success fixture has no certificate RunID")
	}
	*ack.Certificate.RunID = "PRIVATE-caller-mutation"
	releaseContractRead(t, db, request, want)
	proof, err := db.ReadSecurityEnrichmentRelease(context.Background(), request)
	if err != nil || proof.Acknowledgement.Certificate.RunID == nil {
		t.Fatal("matched read missing independent RunID")
	}
	*proof.Acknowledgement.Certificate.RunID = "PRIVATE-read-mutation"
	releaseContractRead(t, db, request, want)
	if _, err := db.db.Exec("ALTER TABLE security_enrichment_operations RENAME TO PRIVATE_unavailable_operation"); err != nil {
		t.Fatal(err)
	}
	before = journalSnapshot(t, db, false)
	proof, err = db.ReadSecurityEnrichmentRelease(context.Background(), request)
	if err == nil || proof.State != "unknown" || strings.Contains(err.Error(), "PRIVATE") || journalSnapshot(t, db, false) != before {
		t.Fatal("read failure exposed provider details, acknowledgement or writes")
	}
	releaseContractNoAck(t, proof.Acknowledgement)
}
