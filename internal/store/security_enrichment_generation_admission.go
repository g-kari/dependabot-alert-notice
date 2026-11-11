package store

import (
	"context"
	"database/sql"
)

// reservationHistoryLimit is the finite lifetime budget per source, including
// its active generation. It is not the controller's independent 16-record cap.
// No eviction, reset or unbound-history adoption is implied by reaching it.
const reservationHistoryLimit = 4

// checkGenerationMetadataTx runs before any stored payload reader. Each source
// selector uses the existing (connector,generation) unique index, including the
// finite BLOB alias. H+1 rows suffice to reject overflow without reading bodies.
// Both reservation and certificate histories must be contiguous from one.
func checkGenerationMetadataTx(ctx context.Context, tx *sql.Tx, source reservationSource) error {
	if source.Generation < 0 || source.Generation > reservationHistoryLimit {
		return reservationError(ctx, errReservationCorrupt)
	}
	closed := source.Generation
	if source.OperationID != nil {
		closed--
	}
	for _, entry := range []struct {
		table string
		count int64
	}{
		{"security_enrichment_reservations", source.Generation},
		{"security_enrichment_release_certificates", closed},
	} {
		rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN
 typeof(connector)='text' AND connector=? AND
 typeof(generation)='integer' AND generation BETWEEN 1 AND ? AND
 typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36 AND
 typeof(intent_id)='text' AND length(CAST(intent_id AS BLOB))=36
 THEN generation END FROM `+entry.table+`
 WHERE connector=? OR connector=CAST(? AS BLOB) ORDER BY connector,generation LIMIT ?`,
			source.Connector, reservationHistoryLimit, source.Connector, source.Connector, reservationHistoryLimit+1)
		if err != nil {
			return reservationError(ctx, errReservationStorage)
		}
		count := int64(0)
		valid := true
		for rows.Next() {
			count++
			var generation sql.NullInt64
			if err := rows.Scan(&generation); err != nil {
				_ = rows.Close()
				return reservationError(ctx, errReservationStorage)
			}
			if count > reservationHistoryLimit || !generation.Valid || generation.Int64 != count {
				valid = false
			}
		}
		readErr := rows.Err()
		closeErr := rows.Close()
		if readErr != nil || closeErr != nil {
			return reservationError(ctx, errReservationStorage)
		}
		if !valid || count != entry.count {
			return reservationError(ctx, errReservationCorrupt)
		}
	}
	return nil
}

// checkClosedGenerationsTx proves one retained generation at a time, including
// every historical observation or exact failure. Certificates alone never
// authorize another reservation. No public API or source checker is called.
func checkClosedGenerationsTx(ctx context.Context, tx *sql.Tx, source reservationSource) error {
	closed := source.Generation
	if source.OperationID != nil {
		closed--
	}
	for generation := int64(1); generation <= closed; generation++ {
		records, err := readReleaseCertificatesTx(ctx, tx, "", "", source.Connector, generation)
		if err != nil || len(records) != 1 {
			return reservationError(ctx, errReservationCorrupt)
		}
		if err := verifyStoredReleaseTx(ctx, tx, records[0], source); err != nil {
			return reservationError(ctx, errReservationCorrupt)
		}
	}
	return nil
}
