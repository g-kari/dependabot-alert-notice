package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrelease"
)

type releaseCertificateRow struct {
	ack SecurityEnrichmentReleaseAcknowledgement
}

// readReleaseCertificatesTx uses three indexed logical keys and finite BLOB
// aliases. At most three canonical records can match; a fourth is corruption.
// Every scalar and the 4KiB payload cap is checked in SQL before Scan.
func readReleaseCertificatesTx(ctx context.Context, tx *sql.Tx, operationID, intentID, connector string, generation int64) ([]releaseCertificateRow, error) {
	rows, err := tx.QueryContext(ctx, `WITH candidates AS (
SELECT *,(
typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36 AND
typeof(intent_id)='text' AND length(CAST(intent_id AS BLOB))=36 AND
typeof(connector)='text' AND connector IN ('epss_feed','kev_feed') AND
typeof(generation)='integer' AND generation BETWEEN 1 AND 9223372036854775807 AND
typeof(format_version)='integer' AND format_version=1 AND
typeof(reserved_digest)='text' AND length(CAST(reserved_digest AS BLOB))=71 AND
typeof(terminal_sequence)='integer' AND terminal_sequence IN (2,4,5) AND
typeof(terminal_previous_digest)='text' AND length(CAST(terminal_previous_digest AS BLOB))=71 AND
typeof(terminal_digest)='text' AND length(CAST(terminal_digest AS BLOB))=71 AND
typeof(kind)='text' AND kind IN ('success','failed','no_run') AND
(run_id IS NULL OR (typeof(run_id)='text' AND length(CAST(run_id AS BLOB))=36)) AND
typeof(receipt)='text' AND length(CAST(receipt AS BLOB))<=128 AND
typeof(certificate_digest)='text' AND length(CAST(certificate_digest AS BLOB))=71 AND
typeof(certificate_json)='text' AND length(CAST(certificate_json AS BLOB)) BETWEEN 2 AND 4096
) AS valid FROM security_enrichment_release_certificates
WHERE operation_id=? OR operation_id=CAST(? AS BLOB) OR intent_id=? OR intent_id=CAST(? AS BLOB)
OR ((connector=? OR connector=CAST(? AS BLOB)) AND generation=?)
ORDER BY operation_id LIMIT 4)
SELECT CASE WHEN valid THEN json_object('version',format_version,'operation_id',operation_id,'intent_id',intent_id,
'connector',connector,'generation',generation,'reserved_digest',reserved_digest,'terminal_sequence',terminal_sequence,
'terminal_previous_digest',terminal_previous_digest,'terminal_digest',terminal_digest,'kind',kind,'run_id',run_id,'receipt',receipt) END,
CASE WHEN valid THEN certificate_digest END,CASE WHEN valid THEN certificate_json END FROM candidates`,
		operationID, operationID, intentID, intentID, connector, connector, generation)
	if err != nil {
		return nil, releaseError(ctx, errReleaseStorage)
	}
	defer func() { _ = rows.Close() }()
	var out []releaseCertificateRow
	for rows.Next() {
		if len(out) >= 3 {
			return nil, releaseError(ctx, errReleaseCorrupt)
		}
		var metadata, digest, payload sql.NullString
		if err := rows.Scan(&metadata, &digest, &payload); err != nil {
			return nil, releaseError(ctx, errReleaseStorage)
		}
		if !metadata.Valid || !digest.Valid || !payload.Valid || !journalValidDigest(digest.String) {
			return nil, releaseError(ctx, errReleaseCorrupt)
		}
		certificate, err := enrichmentrelease.DecodeCertificate([]byte(metadata.String))
		if err != nil {
			return nil, releaseError(ctx, errReleaseCorrupt)
		}
		data := []byte(payload.String)
		decoded, err := enrichmentrelease.DecodeCertificate(data)
		if err != nil {
			return nil, releaseError(ctx, errReleaseCorrupt)
		}
		canonical, err := enrichmentrelease.EncodeCertificate(certificate)
		if err != nil || !bytes.Equal(canonical, data) || journalDigest(data) != digest.String {
			return nil, releaseError(ctx, errReleaseCorrupt)
		}
		decodedCanonical, err := enrichmentrelease.EncodeCertificate(decoded)
		if err != nil || !bytes.Equal(decodedCanonical, canonical) {
			return nil, releaseError(ctx, errReleaseCorrupt)
		}
		out = append(out, releaseCertificateRow{ack: SecurityEnrichmentReleaseAcknowledgement{Certificate: certificate, CertificateDigest: digest.String}})
	}
	if err := rows.Err(); err != nil {
		return nil, releaseError(ctx, errReleaseStorage)
	}
	if err := rows.Close(); err != nil {
		return nil, releaseError(ctx, errReleaseStorage)
	}
	return out, nil
}

// releaseCertificateResidualTx returns only indexed existence flags, never
// payloads. Identity joins catch a corrupted certificate connector when its
// reservation/journal still attributes it to the otherwise-idle source.
func releaseCertificateResidualTx(ctx context.Context, tx *sql.Tx, connector string) (bool, error) {
	var residual bool
	err := tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM security_enrichment_release_certificates WHERE connector=? OR connector=CAST(? AS BLOB) LIMIT 1) OR
EXISTS(SELECT 1 FROM security_enrichment_reservations AS r
WHERE (r.connector=? OR r.connector=CAST(? AS BLOB)) AND
(EXISTS(SELECT 1 FROM security_enrichment_release_certificates AS c WHERE c.operation_id=r.operation_id OR c.operation_id=CAST(r.operation_id AS BLOB) LIMIT 1)
OR EXISTS(SELECT 1 FROM security_enrichment_release_certificates AS c WHERE c.intent_id=r.intent_id OR c.intent_id=CAST(r.intent_id AS BLOB) LIMIT 1)) LIMIT 1) OR
EXISTS(SELECT 1 FROM security_enrichment_operations AS o
WHERE (o.connector=? OR o.connector=CAST(? AS BLOB)) AND
(EXISTS(SELECT 1 FROM security_enrichment_release_certificates AS c WHERE c.operation_id=o.operation_id OR c.operation_id=CAST(o.operation_id AS BLOB) LIMIT 1)
OR EXISTS(SELECT 1 FROM security_enrichment_reservations AS r
WHERE (r.operation_id=o.operation_id OR r.operation_id=CAST(o.operation_id AS BLOB)) AND
EXISTS(SELECT 1 FROM security_enrichment_release_certificates AS c WHERE c.intent_id=r.intent_id OR c.intent_id=CAST(r.intent_id AS BLOB) LIMIT 1) LIMIT 1)) LIMIT 1)`,
		connector, connector, connector, connector, connector, connector).Scan(&residual)
	if err != nil {
		return false, releaseError(ctx, errReleaseStorage)
	}
	return residual, nil
}

func anyReleaseCertificateTx(ctx context.Context, tx *sql.Tx) (bool, error) {
	var present bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM security_enrichment_release_certificates LIMIT 1)").Scan(&present); err != nil {
		return false, releaseError(ctx, errReleaseStorage)
	}
	return present, nil
}

// certifiedReservationClosureTx narrows only a fully proved old binding's
// missing-active state to stale conflict. Other missing-active states stay
// corruption. It never returns an execution or reservation acknowledgement.
func certifiedReservationClosureTx(ctx context.Context, tx *sql.Tx, p preparedReservation, source reservationSource) (bool, error) {
	records, err := readReleaseCertificatesTx(ctx, tx, p.request.Reserved.Checkpoint.OperationID, p.request.IntentID, p.request.Reserved.Checkpoint.Request.Connector, p.generation)
	if err != nil {
		return false, err
	}
	if len(records) != 1 {
		return false, nil
	}
	c := records[0].ack.Certificate
	if c.OperationID != p.request.Reserved.Checkpoint.OperationID || c.IntentID != p.request.IntentID || c.Connector != p.request.Reserved.Checkpoint.Request.Connector || c.Generation != p.generation || c.ReservedDigest != p.request.ReservedDigest {
		return false, nil
	}
	if err := verifyStoredReleaseTx(ctx, tx, records[0], source); err != nil {
		return false, err
	}
	return true, nil
}

// rejectActiveReleaseCertificateTx forbids a stored certificate coexisting with
// the exact same-generation active binding, an impossible atomic-release state.
func rejectActiveReleaseCertificateTx(ctx context.Context, tx *sql.Tx, source reservationSource) error {
	records, err := readReleaseCertificatesTx(ctx, tx, *source.OperationID, *source.IntentID, source.Connector, source.Generation)
	if err != nil {
		return err
	}
	if len(records) != 0 {
		return releaseError(ctx, errReleaseCorrupt)
	}
	// A certificate beyond the current generation is not historical proof.
	var latest sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT CASE WHEN typeof(generation)='integer' AND generation BETWEEN 1 AND 9223372036854775807 THEN generation END
FROM security_enrichment_release_certificates WHERE connector=? OR connector=CAST(? AS BLOB)
ORDER BY generation DESC LIMIT 1`, source.Connector, source.Connector).Scan(&latest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return releaseError(ctx, errReleaseStorage)
	}
	if !latest.Valid || latest.Int64 >= source.Generation {
		return releaseError(ctx, errReleaseCorrupt)
	}
	return nil
}
