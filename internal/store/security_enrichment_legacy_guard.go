package store

import (
	"context"
	"database/sql"
)

// guardLegacyEnrichmentWriteTx admits only genuinely unadopted feed sources.
// It runs in the public legacy entrypoint's write transaction, before replay or
// mutation. Positive generation remains adopted even without an active owner.
// This is not a reservation/release proof, an execution grant, or a lock on
// independent offline/common-fact writers. Fenced private helpers do not call it.
func guardLegacyEnrichmentWriteTx(ctx context.Context, tx *sql.Tx, connector string) error {
	if ctx == nil || tx == nil || (connector != "epss_feed" && connector != "kev_feed") {
		return reservationError(ctx, errReservationConflict)
	}
	if ctx.Err() != nil {
		return reservationError(ctx, errReservationStorage)
	}
	// Existing reader returns at most three small, type/byte-guarded scalar
	// rows. A missing half, alias, oversized scalar or invalid generation
	// cannot become an unadopted source.
	sources, err := readReservationSources(ctx, tx)
	if err != nil {
		return err
	}
	if len(sources) == 0 {
		var residual bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM security_enrichment_reservations LIMIT 1)").Scan(&residual); err != nil {
			return reservationError(ctx, errReservationStorage)
		}
		certificate, certErr := anyReleaseCertificateTx(ctx, tx)
		if certErr != nil {
			return reservationError(ctx, errReservationStorage)
		}
		if residual || certificate {
			return reservationError(ctx, errReservationCorrupt)
		}
	} else {
		if sources[connector].Generation > 0 {
			return reservationError(ctx, ErrIngestConflict)
		}
		certificate, certErr := releaseCertificateResidualTx(ctx, tx, connector)
		if certErr != nil || certificate {
			return reservationError(ctx, errReservationCorrupt)
		}
		// Both selectors are indexed source lookups with finite BLOB aliases;
		// only an EXISTS boolean crosses SQL, never a payload/history. The
		// operation join also catches a residual binding whose connector was
		// corrupted while its journal still identifies this source. Unbound
		// legacy journals/running attempts are deliberately not adopted.
		var residual bool
		if err := tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM security_enrichment_reservations WHERE connector=? OR connector=CAST(? AS BLOB) LIMIT 1) OR
EXISTS(SELECT 1 FROM security_enrichment_operations AS o
WHERE (o.connector=? OR o.connector=CAST(? AS BLOB))
AND EXISTS(SELECT 1 FROM security_enrichment_reservations AS r
WHERE r.operation_id=o.operation_id OR r.operation_id=CAST(o.operation_id AS BLOB) LIMIT 1) LIMIT 1)`,
			connector, connector, connector, connector).Scan(&residual); err != nil {
			return reservationError(ctx, errReservationStorage)
		}
		if residual {
			return reservationError(ctx, errReservationCorrupt)
		}
	}
	if ctx.Err() != nil {
		return reservationError(ctx, errReservationStorage)
	}
	return nil
}
