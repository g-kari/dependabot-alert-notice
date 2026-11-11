package store

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
)

// This locked follow-up is separate from the reconstructed original contracts.
// A no-run release has no ingest receipt that could accidentally block Reserve.
func TestOperationReleaseAdmissionContractNoRunPositiveIdleCannotReserveOrLookMissing(t *testing.T) {
	for index, source := range []string{"epss", "kev"} {
		t.Run(source, func(t *testing.T) {
			db, request, receipt := releaseContractFixture(t, source, "no_run", 4180+index)
			runs, err := db.QueryIngestRuns(context.Background())
			if err != nil || len(runs) != 0 || receipt != "" || request.Terminal.Checkpoint.Prepared != nil || request.Terminal.Checkpoint.Progress.RunID != "" {
				t.Fatal("no-run admission fixture is masked by a business run or receipt")
			}
			// A legitimate positive fixture reaches the new fixed stub first.
			ack := releaseContractRequire(t, db, request, receipt)
			releaseContractRead(t, db, request, ack)
			before := journalSnapshot(t, db, false)
			next := reservationContractRequest(t, 4190+index, source+"_feed")
			next.ExpectedGeneration = ack.Certificate.Generation
			reserved, reserveErr := db.ReserveSecurityEnrichmentOperation(context.Background(), next)
			if !errors.Is(reserveErr, errReservationConflict) || !reflect.DeepEqual(reserved, SecurityEnrichmentReservationAcknowledgement{}) {
				t.Fatal("no-run positive idle admitted next generation or exposed acknowledgement")
			}
			proof, readErr := db.ReadSecurityEnrichmentReservation(context.Background(), next)
			if readErr != nil || proof.State != "conflict" || !reflect.DeepEqual(proof.Acknowledgement, SecurityEnrichmentReservationAcknowledgement{}) || proof.HeadSequence != 0 || proof.HeadDigest != "" {
				t.Fatal("no-run positive idle became a clean missing/admission candidate")
			}
			runs, err = db.QueryIngestRuns(context.Background())
			if err != nil || len(runs) != 0 || journalSnapshot(t, db, false) != before {
				t.Fatal("blocked no-run admission changed a table or fabricated a business UUID")
			}
		})
	}
}

func TestOperationReleaseAdmissionContractCompetitionPreservesCertificateCASAtomicPair(t *testing.T) {
	probe, request, receipt := releaseContractFixture(t, "epss", "no_run", 4200)
	// Red reaches a positive new API before any query of the future table.
	releaseContractRequire(t, probe, request, receipt)

	db, request, receipt := releaseContractFixture(t, "kev", "success", 4201)
	var path string
	if err := db.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil || path == "" {
		t.Fatal("owned SQLite path missing")
	}
	second, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	before := journalSnapshot(t, db, false)
	beforeBusiness := releaseContractBusinessTables(t, db)
	want := releaseContractExpected(t, request, receipt)
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
			if !reflect.DeepEqual(result.ack, want) {
				t.Fatal("concurrent release changed retained identity or business receipt")
			}
		}
	}
	var certificates int
	if err := db.db.QueryRow("SELECT COUNT(*) FROM security_enrichment_release_certificates").Scan(&certificates); err != nil || certificates < 0 || certificates > 1 || fresh > 1 || fresh > certificates {
		t.Fatal("concurrent release duplicated certificate/acknowledgement")
	}
	var generation int64
	var activeOperation, activeIntent sql.NullString
	if err := db.db.QueryRow("SELECT generation,active_operation_id,active_intent_id FROM security_enrichment_source_generations WHERE connector=?", want.Certificate.Connector).Scan(&generation, &activeOperation, &activeIntent); err != nil || generation != want.Certificate.Generation {
		t.Fatal("concurrent release changed generation or lost its source")
	}
	if releaseContractBusinessTables(t, db) != beforeBusiness {
		t.Fatal("concurrent release changed journal/reservation/business evidence")
	}
	if certificates == 0 {
		if fresh != 0 || !activeOperation.Valid || activeOperation.String != want.Certificate.OperationID || !activeIntent.Valid || activeIntent.String != want.Certificate.IntentID || journalSnapshot(t, db, false) != before {
			t.Fatal("uncommitted release left a partial source CAS, certificate or other write")
		}
		beforeRead := journalSnapshot(t, db, false)
		proof, err := db.ReadSecurityEnrichmentRelease(context.Background(), request)
		if err != nil || proof.State != "missing" || journalSnapshot(t, db, false) != beforeRead {
			t.Fatal("fully active terminal without a certificate is not clean missing")
		}
		releaseContractNoAck(t, proof.Acknowledgement)
	} else {
		if activeOperation.Valid || activeIntent.Valid {
			t.Fatal("certificate committed without clearing both exact active fields")
		}
		releaseContractRead(t, db, request, want)
	}
	// Contention need not make progress. No Reserve/Release write retry is
	// used to decide which complete atomic pair actually committed.
}
