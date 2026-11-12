package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrelease"
)

func releaseContractRequest(t *testing.T, reservation SecurityEnrichmentReservationRequest, terminal SecurityEnrichmentFencedRequest) enrichmentrelease.ReleaseRequest {
	t.Helper()
	request := enrichmentrelease.ReleaseRequest{
		Reservation: enrichmentrelease.ReservationRequest{
			IntentID: reservation.IntentID, ExpectedGeneration: reservation.ExpectedGeneration,
			Reserved: reservation.Reserved, ReservedDigest: reservation.ReservedDigest,
		},
		Terminal: terminal.Checkpoint, TerminalDigest: terminal.CheckpointDigest,
	}
	owned, err := enrichmentrelease.InspectTerminal(request)
	if err != nil {
		t.Fatalf("positive pure terminal fixture: %v", err)
	}
	return owned.Request
}

// All terminal fixtures use the existing atomic reservation, explicit fenced
// checkpoint/business APIs and full journal inspection before any new API.
// The root/terminal pair alone is not claimed to prove intermediate history.
func releaseContractFixture(t *testing.T, source, kind string, id int) (*Store, enrichmentrelease.ReleaseRequest, string) {
	t.Helper()
	ctx := context.Background()
	if kind == "no_run" {
		db := journalOwnedStore(t)
		reservation := reservationContractRequest(t, id, source+"_feed")
		reservationContractRequire(t, db, reservation)
		returned := reservation.Reserved.Checkpoint
		returned.Stage = enrichmentjournal.Returned
		returned.Progress.Outcome, returned.Progress.Exhausted = "exhausted", true
		terminal := fencedContractRequest(t, reservation, returned, 2, reservation.ReservedDigest)
		fencedContractAppend(t, db, terminal)
		fencedContractRead(t, db, terminal, false, "unknown")
		inspection, err := db.InspectSecurityEnrichmentOperation(ctx, returned.OperationID)
		if err != nil || inspection.State != "valid" || inspection.Business.State != "no_run" || inspection.Business.Receipt != "" || inspection.Checkpoint == nil || inspection.Checkpoint.Prepared != nil || inspection.Checkpoint.Progress.RunID != "" {
			t.Fatal("no-run fixture invented a business receipt or UUID")
		}
		return db, releaseContractRequest(t, reservation, terminal), ""
	}
	db, completion, reservation, frames := fencedContractFixture(t, source, id)
	begin := fencedContractRequest(t, reservation, frames[1], 2, reservation.ReservedDigest)
	fencedContractAppend(t, db, begin)
	fencedContractApply(t, db, begin, "running")
	write := frames[2]
	returned := frames[3]
	if kind == "failed" {
		write = frames[1]
		prepared := *write.Prepared
		prepared.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: completion.FinishedAt}
		write.Stage, write.Prepared = enrichmentjournal.Fail, &prepared
		returned = write
		returned.Stage = enrichmentjournal.Returned
		returned.Progress.Outcome, returned.Progress.Code = "failed", "fetch_failed"
		returned.Progress.Pending = false
	}
	prepared := fencedContractRequest(t, reservation, write, 3, begin.CheckpointDigest)
	fencedContractAppend(t, db, prepared)
	fencedContractApply(t, db, prepared, kind)
	proof := fencedContractRead(t, db, prepared, true, kind)
	terminal := fencedContractRequest(t, reservation, returned, 4, prepared.CheckpointDigest)
	fencedContractAppend(t, db, terminal)
	inspection, err := db.InspectSecurityEnrichmentOperation(ctx, returned.OperationID)
	if err != nil || inspection.State != "valid" || inspection.Business.State != kind || inspection.Business.Receipt != proof.Business.Receipt || inspection.HeadSequence != 4 || inspection.HeadDigest != terminal.CheckpointDigest {
		t.Fatalf("positive fixture lacks complete historical business proof: %+v %v", inspection, err)
	}
	if kind == "success" && proof.Business.Receipt == "" || kind == "failed" && proof.Business.Receipt != "" {
		t.Fatal("business receipt and journal acknowledgement were confused")
	}
	return db, releaseContractRequest(t, reservation, terminal), proof.Business.Receipt
}

func releaseContractExpected(t *testing.T, request enrichmentrelease.ReleaseRequest, receipt string) SecurityEnrichmentReleaseAcknowledgement {
	t.Helper()
	inspection, err := enrichmentrelease.InspectTerminal(request)
	if err != nil {
		t.Fatal(err)
	}
	certificate := enrichmentrelease.Certificate{
		Version:     enrichmentrelease.CertificateVersion,
		OperationID: request.Reservation.Reserved.Checkpoint.OperationID,
		IntentID:    request.Reservation.IntentID, Connector: request.Reservation.Reserved.Checkpoint.Request.Connector,
		Generation: request.Reservation.ExpectedGeneration + 1, ReservedDigest: request.Reservation.ReservedDigest,
		TerminalSequence: request.Terminal.Sequence, TerminalPreviousDigest: request.Terminal.PreviousDigest,
		TerminalDigest: request.TerminalDigest, Kind: inspection.Kind, Receipt: receipt,
	}
	if inspection.RunID != "" {
		runID := inspection.RunID
		certificate.RunID = &runID
	}
	data, err := enrichmentrelease.EncodeCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return SecurityEnrichmentReleaseAcknowledgement{Certificate: certificate, CertificateDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(data))}
}

func releaseContractRequire(t *testing.T, db *Store, request enrichmentrelease.ReleaseRequest, receipt string) SecurityEnrichmentReleaseAcknowledgement {
	t.Helper()
	want := releaseContractExpected(t, request, receipt)
	ack, err := db.ReleaseSecurityEnrichmentOperation(context.Background(), request)
	if err != nil {
		t.Fatalf("valid fresh terminal release must succeed: %v", err)
	}
	if !reflect.DeepEqual(ack, want) {
		t.Fatalf("release acknowledgement differs from retained request/business receipt: %+v", ack)
	}
	return ack
}

func releaseContractBusinessTables(t *testing.T, db *Store) string {
	t.Helper()
	var tables map[string]json.RawMessage
	if err := json.Unmarshal([]byte(journalSnapshot(t, db, false)), &tables); err != nil {
		t.Fatal(err)
	}
	delete(tables, "security_enrichment_source_generations")
	delete(tables, "security_enrichment_release_certificates")
	data, err := json.Marshal(tables)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func releaseContractNoAck(t *testing.T, ack SecurityEnrichmentReleaseAcknowledgement) {
	t.Helper()
	if !reflect.DeepEqual(ack, SecurityEnrichmentReleaseAcknowledgement{}) {
		t.Fatalf("unverified release exposed acknowledgement: %+v", ack)
	}
}

func releaseContractRead(t *testing.T, db *Store, request enrichmentrelease.ReleaseRequest, want SecurityEnrichmentReleaseAcknowledgement) {
	t.Helper()
	before := journalSnapshot(t, db, false)
	proof, err := db.ReadSecurityEnrichmentRelease(context.Background(), request)
	if err != nil || proof.State != "matched" || !reflect.DeepEqual(proof.Acknowledgement, want) || journalSnapshot(t, db, false) != before {
		t.Fatalf("same-full-request readonly release proof differs or writes: %+v %v", proof, err)
	}
}

func TestOperationReleaseContractAtomicCertificateAndSourceCAS(t *testing.T) {
	for index, fixture := range []struct{ source, kind string }{
		{"epss", "success"}, {"kev", "success"}, {"epss", "failed"}, {"kev", "no_run"},
	} {
		t.Run(fixture.source+"-"+fixture.kind, func(t *testing.T) {
			db, request, receipt := releaseContractFixture(t, fixture.source, fixture.kind, 4100+index)
			old := releaseContractBusinessTables(t, db)
			// First new operation is a positive fresh-release call. Red must
			// reach its fixed runtime error, never absent migration/schema.
			ack := releaseContractRequire(t, db, request, receipt)
			var generation int64
			var operation, intent sql.NullString
			if err := db.db.QueryRow("SELECT generation,active_operation_id,active_intent_id FROM security_enrichment_source_generations WHERE connector=?", ack.Certificate.Connector).Scan(&generation, &operation, &intent); err != nil || generation != ack.Certificate.Generation || operation.Valid || intent.Valid {
				t.Fatal("certificate did not atomically clear both active fields while preserving generation")
			}
			var count int
			if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_release_certificates WHERE operation_id=?", ack.Certificate.OperationID).Scan(&count); err != nil || count != 1 {
				t.Fatal("release did not retain exactly one certificate")
			}
			if releaseContractBusinessTables(t, db) != old {
				t.Fatal("release changed an old journal, reservation, finding or business evidence row")
			}
			releaseContractRead(t, db, request, ack)
		})
	}
}

func TestOperationReleaseContractRefusalOtherSourceCompetitionAndRollback(t *testing.T) {
	probe, request, receipt := releaseContractFixture(t, "epss", "success", 4120)
	releaseContractRequire(t, probe, request, receipt)

	t.Run("both-sources-continue-after-proved-release", func(t *testing.T) {
		before := journalSnapshot(t, probe, false)
		next := reservationContractRequest(t, 4121, "epss_feed")
		next.ExpectedGeneration = 1
		missing, err := probe.ReadSecurityEnrichmentReservation(context.Background(), next)
		if err != nil || missing.State != "missing" || !reflect.DeepEqual(missing.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) || journalSnapshot(t, probe, false) != before {
			t.Fatal("proved positive-idle candidate must be read-only missing")
		}
		reservationContractRequire(t, probe, next)
		other := reservationContractRequest(t, 4122, "kev_feed")
		reservationContractRequire(t, probe, other)
		returned := other.Reserved.Checkpoint
		returned.Stage = enrichmentjournal.Returned
		returned.Progress.Outcome, returned.Progress.Exhausted = "exhausted", true
		terminal := fencedContractRequest(t, other, returned, 2, other.ReservedDigest)
		fencedContractAppend(t, probe, terminal)
		fencedContractRead(t, probe, terminal, false, "unknown")
	})

	for index, kind := range []string{"intent", "digest", "pending", "observation-missing"} {
		t.Run(kind, func(t *testing.T) {
			db, request, _ := releaseContractFixture(t, "epss", "success", 4130+index)
			switch kind {
			case "intent":
				request.Reservation.IntentID = "a2000000-0000-4000-8000-000000009999"
			case "digest":
				request.TerminalDigest = "sha256:" + strings.Repeat("f", 64)
			case "pending":
				request.Terminal.Checkpoint.Progress.Outcome = "pending"
				request.Terminal.Checkpoint.Progress.Code = "completion_unknown"
				request.Terminal.Checkpoint.Progress.Pending = true
				request.Terminal.Checkpoint.Progress.Advance = false
				request.Terminal.Checkpoint.Progress.NextAfter = request.Terminal.Checkpoint.Request.After
				data, err := enrichmentjournal.Encode(request.Terminal.Checkpoint)
				if err != nil {
					t.Fatal(err)
				}
				request.TerminalDigest = fmt.Sprintf("sha256:%x", sha256.Sum256(data))
			case "observation-missing":
				result, err := db.db.Exec("DELETE FROM security_enrichment_observations WHERE ingest_run_id=?", request.Terminal.Checkpoint.Progress.RunID)
				if err != nil {
					t.Fatal(err)
				}
				if count, err := result.RowsAffected(); err != nil || count == 0 {
					t.Fatal("negative fixture did not remove real observations")
				}
			}
			before := journalSnapshot(t, db, false)
			ack, err := db.ReleaseSecurityEnrichmentOperation(context.Background(), request)
			if err == nil {
				t.Fatal("unproved terminal was released")
			}
			releaseContractNoAck(t, ack)
			proof, _ := db.ReadSecurityEnrichmentRelease(context.Background(), request)
			if proof.State == "matched" {
				t.Fatal("unproved terminal obtained readonly acknowledgement")
			}
			releaseContractNoAck(t, proof.Acknowledgement)
			if journalSnapshot(t, db, false) != before {
				t.Fatal("refused release left a partial certificate/CAS or repaired evidence")
			}
		})
	}
	t.Run("CAS-trigger-rollback", func(t *testing.T) {
		db, request, _ := releaseContractFixture(t, "kev", "success", 4140)
		_, err := db.db.Exec("CREATE TRIGGER release_contract_stop BEFORE UPDATE ON security_enrichment_source_generations WHEN NEW.active_operation_id IS NULL BEGIN SELECT RAISE(ABORT,'PRIVATE-cas-failure'); END")
		if err != nil {
			t.Fatal(err)
		}
		before := journalSnapshot(t, db, false)
		ack, err := db.ReleaseSecurityEnrichmentOperation(context.Background(), request)
		if err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("CAS failure succeeded or leaked raw trigger text")
		}
		releaseContractNoAck(t, ack)
		if journalSnapshot(t, db, false) != before {
			t.Fatal("certificate INSERT survived failed source CAS")
		}
	})
	t.Run("separate-connections-at-most-one-fresh-release", func(t *testing.T) {
		db, request, receipt := releaseContractFixture(t, "epss", "success", 4141)
		var path string
		if err := db.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
			t.Fatal("owned SQLite path missing")
		}
		second, err := NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		type result struct {
			ack SecurityEnrichmentReleaseAcknowledgement
			err error
		}
		start := make(chan struct{})
		results := make(chan result, 2)
		for _, db := range []*Store{db, second} {
			go func(db *Store) {
				<-start
				ack, err := db.ReleaseSecurityEnrichmentOperation(context.Background(), request)
				results <- result{ack, err}
			}(db)
		}
		close(start)
		fresh := 0
		for i := 0; i < 2; i++ {
			result := <-results
			if result.err != nil {
				releaseContractNoAck(t, result.ack)
			} else {
				fresh++
				if !reflect.DeepEqual(result.ack, releaseContractExpected(t, request, receipt)) {
					t.Fatal("competing release changed exact identity")
				}
			}
		}
		var certificates int
		if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_release_certificates").Scan(&certificates); err != nil || certificates > 1 || fresh > 1 || fresh > certificates {
			t.Fatal("competing writers duplicated release/certificate")
		}
		// SQLite contention need not guarantee progress; no write retry.
	})
}

type releaseContractLostReturn struct {
	db        *Store
	calls     int
	committed bool
}

func (wrapper *releaseContractLostReturn) release(ctx context.Context, request enrichmentrelease.ReleaseRequest) (SecurityEnrichmentReleaseAcknowledgement, error) {
	wrapper.calls++
	if _, err := wrapper.db.ReleaseSecurityEnrichmentOperation(ctx, request); err != nil {
		return SecurityEnrichmentReleaseAcknowledgement{}, err
	}
	wrapper.committed = true
	// Real Store commit followed by an outer synthetic lost return. This
	// does not inject a failure into the SQLite driver's Commit result.
	return SecurityEnrichmentReleaseAcknowledgement{}, errors.New("PRIVATE-lost-return")
}

func TestOperationReleaseContractLostReturnUsesOnlySameRequestReadonlyProof(t *testing.T) {
	db, request, receipt := releaseContractFixture(t, "epss", "success", 4160)
	wrapper := &releaseContractLostReturn{db: db}
	ack, err := wrapper.release(context.Background(), request)
	if !wrapper.committed {
		t.Fatalf("positive fresh release must commit before synthetic lost return: %v", err)
	}
	if err == nil || wrapper.calls != 1 {
		t.Fatal("lost return was hidden or retried")
	}
	releaseContractNoAck(t, ack)
	before := journalSnapshot(t, db, false)
	expected := releaseContractExpected(t, request, receipt)
	releaseContractRead(t, db, request, expected)
	repeated, err := db.ReleaseSecurityEnrichmentOperation(context.Background(), request)
	if err == nil {
		t.Fatal("already released request was accepted as a fresh release")
	}
	releaseContractNoAck(t, repeated)
	reservation := SecurityEnrichmentReservationRequest{
		IntentID: request.Reservation.IntentID, ExpectedGeneration: request.Reservation.ExpectedGeneration,
		Reserved: request.Reservation.Reserved, ReservedDigest: request.Reservation.ReservedDigest,
	}
	stale, err := db.ReadSecurityEnrichmentReservation(context.Background(), reservation)
	if err != nil || stale.State != "conflict" || !reflect.DeepEqual(stale.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) {
		t.Fatal("fully certified closed reservation became corruption or fresh ownership")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	unknown, err := db.ReadSecurityEnrichmentRelease(cancelled, request)
	if !errors.Is(err, context.Canceled) || unknown.State != "unknown" {
		t.Fatal("canceled read exposed release proof or lost cancellation identity")
	}
	releaseContractNoAck(t, unknown.Acknowledgement)
	if wrapper.calls != 1 || journalSnapshot(t, db, false) != before {
		t.Fatal("readonly recovery/rejected repeat changed a table or resent the uncertain write")
	}

	t.Run("clean-active-missing-versus-impossible-idle-missing", func(t *testing.T) {
		active, request, _ := releaseContractFixture(t, "kev", "success", 4161)
		before := journalSnapshot(t, active, false)
		proof, err := active.ReadSecurityEnrichmentRelease(context.Background(), request)
		if err != nil || proof.State != "missing" || journalSnapshot(t, active, false) != before {
			t.Fatal("fully proved still-active terminal is not a clean pre-release missing snapshot")
		}
		releaseContractNoAck(t, proof.Acknowledgement)
		_, err = active.db.Exec("UPDATE security_enrichment_source_generations SET active_operation_id=NULL,active_intent_id=NULL WHERE connector='kev_feed'")
		if err != nil {
			t.Fatal(err)
		}
		before = journalSnapshot(t, active, false)
		proof, err = active.ReadSecurityEnrichmentRelease(context.Background(), request)
		if err == nil || proof.State != "unknown" || journalSnapshot(t, active, false) != before {
			t.Fatal("positive idle without certificate was treated as clean missing/retry permission")
		}
		releaseContractNoAck(t, proof.Acknowledgement)
	})
	t.Run("certificate-and-same-generation-active-is-corrupt", func(t *testing.T) {
		_, err := db.db.Exec("UPDATE security_enrichment_source_generations SET active_operation_id=?,active_intent_id=? WHERE connector='epss_feed'", reservation.Reserved.Checkpoint.OperationID, reservation.IntentID)
		if err != nil {
			t.Fatal(err)
		}
		before := journalSnapshot(t, db, false)
		proof, err := db.ReadSecurityEnrichmentRelease(context.Background(), request)
		if err == nil || proof.State != "unknown" || journalSnapshot(t, db, false) != before {
			t.Fatal("impossible atomic release mixture matched its certificate")
		}
		releaseContractNoAck(t, proof.Acknowledgement)
	})
}
