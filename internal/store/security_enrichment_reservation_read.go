package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

type reservationSource struct {
	Connector   string  `json:"connector"`
	Generation  int64   `json:"generation"`
	OperationID *string `json:"operation_id"`
	IntentID    *string `json:"intent_id"`
}
type reservationBinding struct {
	OperationID        string `json:"operation_id"`
	IntentID           string `json:"intent_id"`
	Connector          string `json:"connector"`
	ExpectedGeneration int64  `json:"expected_generation"`
	Generation         int64  `json:"generation"`
	Digest             string `json:"digest"`
	payload            []byte
}

func readReservationSources(ctx context.Context, tx *sql.Tx) (map[string]reservationSource, error) {
	rows, err := tx.QueryContext(ctx, `SELECT CASE WHEN
typeof(connector)='text' AND connector IN ('epss_feed','kev_feed') AND
typeof(generation)='integer' AND generation BETWEEN 0 AND 9223372036854775807 AND
(active_operation_id IS NULL OR (typeof(active_operation_id)='text' AND length(CAST(active_operation_id AS BLOB))=36)) AND
(active_intent_id IS NULL OR (typeof(active_intent_id)='text' AND length(CAST(active_intent_id AS BLOB))=36))
THEN json_object('connector',connector,'generation',generation,'operation_id',active_operation_id,'intent_id',active_intent_id) ELSE NULL END
FROM security_enrichment_source_generations ORDER BY connector LIMIT 3`)
	if err != nil {
		return nil, reservationError(ctx, errReservationStorage)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]reservationSource)
	for rows.Next() {
		if len(out) >= 2 {
			return nil, reservationError(ctx, errReservationCorrupt)
		}
		var body sql.NullString
		var source reservationSource
		if err := rows.Scan(&body); err != nil {
			return nil, reservationError(ctx, errReservationStorage)
		}
		if !body.Valid || decodePreviewStoredJSON(body.String, &source) != nil || (source.OperationID == nil) != (source.IntentID == nil) || source.OperationID != nil && (!reservationUUID(*source.OperationID) || !reservationUUID(*source.IntentID)) || source.Generation == 0 && source.OperationID != nil {
			return nil, reservationError(ctx, errReservationCorrupt)
		}
		if _, exists := out[source.Connector]; exists {
			return nil, reservationError(ctx, errReservationCorrupt)
		}
		out[source.Connector] = source
	}
	if err := rows.Err(); err != nil {
		return nil, reservationError(ctx, errReservationStorage)
	}
	if err := rows.Close(); err != nil {
		return nil, reservationError(ctx, errReservationStorage)
	}
	if len(out) != 0 && (len(out) != 2 || out["epss_feed"].Connector != "epss_feed" || out["kev_feed"].Connector != "kev_feed") {
		return nil, reservationError(ctx, errReservationCorrupt)
	}
	return out, nil
}

func readReservationBindings(ctx context.Context, tx *sql.Tx, operationID, intentID string) ([]reservationBinding, error) {
	// Every selector is an indexed exact ID or its finite BLOB alias. At most
	// two distinct canonical rows can match; the third detects corruption.
	rows, err := tx.QueryContext(ctx, `WITH candidates AS (
SELECT *,(
typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36 AND
typeof(intent_id)='text' AND length(CAST(intent_id AS BLOB))=36 AND
typeof(connector)='text' AND connector IN ('epss_feed','kev_feed') AND
typeof(expected_generation)='integer' AND expected_generation BETWEEN 0 AND 9223372036854775806 AND
typeof(generation)='integer' AND generation=expected_generation+1 AND
typeof(reserved_digest)='text' AND length(CAST(reserved_digest AS BLOB))=71 AND
typeof(reserved_payload_json)='text' AND length(CAST(reserved_payload_json AS BLOB)) BETWEEN 2 AND 1048576
) AS valid FROM security_enrichment_reservations
WHERE operation_id=? OR intent_id=? OR operation_id=CAST(? AS BLOB) OR intent_id=CAST(? AS BLOB)
ORDER BY operation_id LIMIT 3)
SELECT CASE WHEN valid THEN json_object('operation_id',operation_id,'intent_id',intent_id,'connector',connector,'expected_generation',expected_generation,'generation',generation,'digest',reserved_digest) END,
CASE WHEN valid THEN reserved_payload_json END FROM candidates`, operationID, intentID, operationID, intentID)
	if err != nil {
		return nil, reservationError(ctx, errReservationStorage)
	}
	defer func() { _ = rows.Close() }()
	var out []reservationBinding
	for rows.Next() {
		if len(out) >= 2 {
			return nil, reservationError(ctx, errReservationCorrupt)
		}
		var metadata, payload sql.NullString
		if err := rows.Scan(&metadata, &payload); err != nil {
			return nil, reservationError(ctx, errReservationStorage)
		}
		var record reservationBinding
		if !metadata.Valid || !payload.Valid || decodePreviewStoredJSON(metadata.String, &record) != nil || !reservationUUID(record.OperationID) || !reservationUUID(record.IntentID) || !journalValidDigest(record.Digest) {
			return nil, reservationError(ctx, errReservationCorrupt)
		}
		data := []byte(payload.String)
		checkpoint, err := enrichmentjournal.Decode(data)
		if err != nil || checkpoint.OperationID != record.OperationID || checkpoint.Request.Connector != record.Connector || enrichmentjournal.ValidateTransition(nil, checkpoint) != nil || journalDigest(data) != record.Digest {
			return nil, reservationError(ctx, errReservationCorrupt)
		}
		canonical, err := enrichmentjournal.Encode(checkpoint)
		if err != nil || !bytes.Equal(canonical, data) {
			return nil, reservationError(ctx, errReservationCorrupt)
		}
		record.payload = data
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, reservationError(ctx, errReservationStorage)
	}
	if err := rows.Close(); err != nil {
		return nil, reservationError(ctx, errReservationStorage)
	}
	return out, nil
}

func reservationJournalTx(ctx context.Context, tx *sql.Tx, operationID string) (journalHeader, bool, []journalRow, error) {
	header, exists, err := readJournalHeader(ctx, tx, operationID)
	if err != nil {
		return header, false, nil, reservationError(ctx, errReservationCorrupt)
	}
	rows, err := readJournalRows(ctx, tx, operationID)
	if err != nil {
		return header, false, nil, reservationError(ctx, errReservationCorrupt)
	}
	if err := checkJournalHistory(header, exists, rows); err != nil {
		return header, false, nil, reservationError(ctx, errReservationCorrupt)
	}
	return header, exists, rows, nil
}

func checkReservationSources(ctx context.Context, tx *sql.Tx, sources map[string]reservationSource) error {
	if len(sources) == 0 {
		var orphan bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM security_enrichment_reservations LIMIT 1)").Scan(&orphan); err != nil {
			return reservationError(ctx, errReservationStorage)
		}
		if orphan {
			return reservationError(ctx, errReservationCorrupt)
		}
		return nil
	}
	for _, connector := range []string{"epss_feed", "kev_feed"} {
		source := sources[connector]
		var alias bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM security_enrichment_reservations WHERE connector=CAST(? AS BLOB) LIMIT 1)", connector).Scan(&alias); err != nil {
			return reservationError(ctx, errReservationStorage)
		}
		if alias {
			return reservationError(ctx, errReservationCorrupt)
		}
		var latest sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT CASE WHEN typeof(generation)='integer' AND generation BETWEEN 1 AND 9223372036854775807 THEN generation END
FROM security_enrichment_reservations WHERE connector=? ORDER BY generation DESC LIMIT 1`, connector).Scan(&latest)
		found := !errors.Is(err, sql.ErrNoRows)
		if err != nil && found {
			return reservationError(ctx, errReservationStorage)
		}
		if source.Generation == 0 && source.OperationID == nil && !found {
			continue
		}
		// This slice has no release API. A positive idle generation is not
		// silently accepted as evidence that a previous owner stopped.
		if !found || !latest.Valid || latest.Int64 != source.Generation || source.OperationID == nil || source.IntentID == nil {
			return reservationError(ctx, errReservationCorrupt)
		}
		records, err := readReservationBindings(ctx, tx, *source.OperationID, *source.IntentID)
		if err != nil {
			return err
		}
		if len(records) != 1 {
			return reservationError(ctx, errReservationCorrupt)
		}
		record := records[0]
		if record.OperationID != *source.OperationID || record.IntentID != *source.IntentID || record.Connector != connector || record.Generation != source.Generation {
			return reservationError(ctx, errReservationCorrupt)
		}
		_, exists, rows, err := reservationJournalTx(ctx, tx, record.OperationID)
		if err != nil {
			return err
		}
		if !exists || len(rows) == 0 || rows[0].digest != record.Digest || !bytes.Equal(rows[0].payload, record.payload) {
			return reservationError(ctx, errReservationCorrupt)
		}
	}
	return nil
}

func initialReservationAdmission(ctx context.Context, tx *sql.Tx) error {
	var legacy bool
	// Never infer intents or failures for pre-existing receipts/journals.
	// Only existence is returned; no history/body is materialized.
	if err := tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM security_enrichment_operations LIMIT 1) OR
EXISTS(SELECT 1 FROM security_enrichment_checkpoints LIMIT 1) OR
EXISTS(SELECT 1 FROM security_enrichment_reservations LIMIT 1) OR
EXISTS(SELECT 1 FROM ingest_runs WHERE connector IN ('epss_feed','kev_feed') LIMIT 1) OR
EXISTS(SELECT 1 FROM ingest_runs WHERE connector IN (CAST('epss_feed' AS BLOB),CAST('kev_feed' AS BLOB)) LIMIT 1)`).Scan(&legacy); err != nil {
		return reservationError(ctx, errReservationStorage)
	}
	if legacy {
		return reservationError(ctx, errReservationConflict)
	}
	return nil
}

func unboundReservationSource(ctx context.Context, tx *sql.Tx, connector string) (bool, error) {
	var legacy bool
	if err := tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM ingest_runs WHERE connector=? OR connector=CAST(? AS BLOB) LIMIT 1) OR
EXISTS(SELECT 1 FROM security_enrichment_operations AS o WHERE (o.connector=? OR o.connector=CAST(? AS BLOB))
AND NOT EXISTS(SELECT 1 FROM security_enrichment_reservations AS r WHERE r.operation_id=o.operation_id) LIMIT 1) OR
EXISTS(SELECT 1 FROM security_enrichment_checkpoints AS c WHERE NOT EXISTS
(SELECT 1 FROM security_enrichment_operations AS o WHERE o.operation_id=c.operation_id) LIMIT 1)`, connector, connector, connector, connector).Scan(&legacy); err != nil {
		return false, reservationError(ctx, errReservationStorage)
	}
	return legacy, nil
}
