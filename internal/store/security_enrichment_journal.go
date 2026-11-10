package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

var errJournalConflict = errors.New("operation journal conflict")
var errJournalCorrupt = errors.New("operation journal stored data invalid")
var errJournalStorage = errors.New("operation journal storage unavailable")

// Five distinct checkpoints cover the longest v1 branch: reserved, begin,
// fail|complete, returned-pending, returned-terminal. Retry uses the same sequence.
const journalMaxCheckpoints = 5

type journalHeader struct {
	OperationID string  `json:"operation_id"`
	Version     int     `json:"format_version"`
	Connector   string  `json:"connector"`
	After       string  `json:"request_after"`
	Limit       int     `json:"request_limit"`
	RunID       *string `json:"run_id"`
	Sequence    int64   `json:"head_sequence"`
	Digest      string  `json:"head_digest"`
}

type journalRow struct {
	sequence   int64
	stage      string
	previous   string
	digest     string
	payload    []byte
	checkpoint enrichmentjournal.Checkpoint
}

func journalError(ctx context.Context, category error) error {
	if ctx != nil && ctx.Err() != nil {
		return fmt.Errorf("operation journal: %w", ctx.Err())
	}
	// Underlying SQL/trigger text is deliberately not exposed or retained.
	return fmt.Errorf("operation journal: %w", category)
}

func journalDigest(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

func journalValidDigest(value string) bool {
	return len(value) == 71 && value[:7] == "sha256:" && securityDigest(value[7:])
}

// AppendSecurityEnrichmentCheckpoint atomically appends one immutable checkpoint
// and CAS-updates its bound operation head. Exact retained payload replay returns
// the original acknowledgement. It never writes existing enrichment receipts,
// creates an ingest run, grants fetch ownership or retries an uncertain commit.
// Commit errors return no acknowledgement; callers retain the exact AppendRequest.
func (s *Store) AppendSecurityEnrichmentCheckpoint(ctx context.Context, request enrichmentjournal.AppendRequest) (enrichmentjournal.Acknowledgement, error) {
	empty := enrichmentjournal.Acknowledgement{}
	if ctx == nil || request.Sequence < 1 || request.Sequence > journalMaxCheckpoints || (request.Sequence == 1 && request.PreviousDigest != "") || (request.Sequence > 1 && !journalValidDigest(request.PreviousDigest)) {
		return empty, journalError(ctx, errJournalConflict)
	}
	if ctx.Err() != nil {
		return empty, journalError(ctx, errJournalStorage)
	}
	payload, err := enrichmentjournal.Encode(request.Checkpoint)
	if err != nil {
		return empty, journalError(ctx, errJournalConflict)
	}
	digest := journalDigest(payload)
	c := request.Checkpoint
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, journalError(ctx, errJournalStorage)
	}
	defer func() { _ = tx.Rollback() }()
	header, exists, err := readJournalHeader(ctx, tx, c.OperationID)
	if err != nil {
		return empty, err
	}
	rows, err := readJournalRows(ctx, tx, c.OperationID)
	if err != nil {
		return empty, err
	}
	if err := checkJournalHistory(header, exists, rows); err != nil {
		return empty, journalError(ctx, err)
	}
	if exists && request.Sequence <= header.Sequence {
		row := rows[request.Sequence-1]
		if row.previous != request.PreviousDigest || row.digest != digest || !bytes.Equal(row.payload, payload) {
			return empty, journalError(ctx, errJournalConflict)
		}
		if err := tx.Commit(); err != nil {
			return empty, journalError(ctx, errJournalStorage)
		}
		return enrichmentjournal.Acknowledgement{OperationID: c.OperationID, Sequence: request.Sequence, Digest: digest, Replay: true}, nil
	}
	if !exists {
		if request.Sequence != 1 || request.PreviousDigest != "" || enrichmentjournal.ValidateTransition(nil, c) != nil {
			return empty, journalError(ctx, errJournalConflict)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO security_enrichment_operations(operation_id,format_version,connector,request_after,request_limit,run_id,head_sequence,head_digest) VALUES(?,?,?,?,?,NULL,?,?)`,
			c.OperationID, c.Version, c.Request.Connector, c.Request.After, c.Request.Limit, request.Sequence, digest)
		if err != nil {
			return empty, journalError(ctx, errJournalStorage)
		}
	} else {
		last := rows[len(rows)-1]
		if request.Sequence != header.Sequence+1 || request.PreviousDigest != header.Digest || enrichmentjournal.ValidateTransition(&last.checkpoint, c) != nil {
			return empty, journalError(ctx, errJournalConflict)
		}
		if header.RunID != nil && *header.RunID != c.Progress.RunID {
			return empty, journalError(ctx, errJournalConflict)
		}
	}
	if c.Progress.RunID != "" {
		var aliases bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM security_enrichment_operations WHERE run_id=CAST(? AS BLOB))`, c.Progress.RunID).Scan(&aliases); err != nil {
			return empty, journalError(ctx, errJournalStorage)
		}
		if aliases {
			return empty, journalError(ctx, errJournalCorrupt)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO security_enrichment_checkpoints(operation_id,sequence,stage,previous_digest,payload_digest,payload_json) VALUES(?,?,?,?,?,?)`,
		c.OperationID, request.Sequence, string(c.Stage), request.PreviousDigest, digest, string(payload)); err != nil {
		return empty, journalError(ctx, errJournalStorage)
	}
	if exists {
		var runID any
		if c.Progress.RunID != "" {
			runID = c.Progress.RunID
		}
		var oldRunID any
		if header.RunID != nil {
			oldRunID = *header.RunID
		}
		result, err := tx.ExecContext(ctx, `UPDATE security_enrichment_operations SET run_id=?,head_sequence=?,head_digest=? WHERE operation_id=? AND head_sequence=? AND head_digest=? AND format_version=? AND connector=? AND request_after=? AND request_limit=? AND run_id IS ?`,
			runID, request.Sequence, digest, c.OperationID, header.Sequence, header.Digest, header.Version, header.Connector, header.After, header.Limit, oldRunID)
		if err != nil {
			return empty, journalError(ctx, errJournalStorage)
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return empty, journalError(ctx, errJournalConflict)
		}
	}
	if err := tx.Commit(); err != nil {
		return empty, journalError(ctx, errJournalStorage)
	}
	return enrichmentjournal.Acknowledgement{OperationID: c.OperationID, Sequence: request.Sequence, Digest: digest}, nil
}

func readJournalHeader(ctx context.Context, tx *sql.Tx, id string) (journalHeader, bool, error) {
	var header journalHeader
	var alias bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM security_enrichment_operations WHERE operation_id=CAST(? AS BLOB))`, id).Scan(&alias); err != nil {
		return header, false, journalError(ctx, errJournalStorage)
	}
	if alias {
		return header, false, journalError(ctx, errJournalCorrupt)
	}
	// Every scalar is storage-type/byte checked before SQLite constructs the
	// small JSON value returned to Go. A corrupt/oversize row returns NULL.
	var body sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT CASE WHEN
typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36 AND
typeof(format_version)='integer' AND format_version=1 AND
typeof(connector)='text' AND length(CAST(connector AS BLOB))<=9 AND
typeof(request_after)='text' AND length(CAST(request_after AS BLOB))<=128 AND
typeof(request_limit)='integer' AND request_limit BETWEEN 1 AND 200 AND
(run_id IS NULL OR (typeof(run_id)='text' AND length(CAST(run_id AS BLOB))=36)) AND
typeof(head_sequence)='integer' AND head_sequence BETWEEN 1 AND 5 AND
typeof(head_digest)='text' AND length(CAST(head_digest AS BLOB))=71
THEN json_object('operation_id',operation_id,'format_version',format_version,'connector',connector,'request_after',request_after,'request_limit',request_limit,'run_id',run_id,'head_sequence',head_sequence,'head_digest',head_digest)
ELSE NULL END FROM security_enrichment_operations WHERE operation_id=?`, id).Scan(&body)
	if err == sql.ErrNoRows {
		return header, false, nil
	}
	if err != nil {
		return header, false, journalError(ctx, errJournalStorage)
	}
	if !body.Valid || decodePreviewStoredJSON(body.String, &header) != nil || header.OperationID != id || !journalValidDigest(header.Digest) || header.RunID != nil && !securityUUID(*header.RunID) {
		return header, false, journalError(ctx, errJournalCorrupt)
	}
	reserved := enrichmentjournal.Checkpoint{Version: header.Version, OperationID: id,
		Request: enrichmentjournal.Request{Connector: header.Connector, After: header.After, Limit: header.Limit}, Stage: enrichmentjournal.Reserved,
		Progress: enrichmentjournal.Progress{NextAfter: header.After}}
	if _, err := enrichmentjournal.Encode(reserved); err != nil {
		return header, false, journalError(ctx, errJournalCorrupt)
	}
	if header.RunID != nil {
		var runAlias bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM security_enrichment_operations WHERE run_id=CAST(? AS BLOB))`, *header.RunID).Scan(&runAlias); err != nil {
			return header, false, journalError(ctx, errJournalStorage)
		}
		if runAlias {
			return header, false, journalError(ctx, errJournalCorrupt)
		}
	}
	return header, true, nil
}

func readJournalRows(ctx context.Context, tx *sql.Tx, id string) ([]journalRow, error) {
	rows, err := tx.QueryContext(ctx, `WITH candidates AS (
SELECT *, (
typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36 AND
typeof(sequence)='integer' AND sequence BETWEEN 1 AND 5 AND
typeof(stage)='text' AND length(CAST(stage AS BLOB))<=8 AND
typeof(previous_digest)='text' AND length(CAST(previous_digest AS BLOB)) IN (0,71) AND
typeof(payload_digest)='text' AND length(CAST(payload_digest AS BLOB))=71 AND
typeof(payload_json)='text' AND length(CAST(payload_json AS BLOB)) BETWEEN 2 AND 1048576
) AS valid
FROM security_enrichment_checkpoints WHERE operation_id=? OR operation_id=CAST(? AS BLOB)
ORDER BY sequence LIMIT 6)
SELECT CASE WHEN valid THEN sequence END,CASE WHEN valid THEN stage END,
CASE WHEN valid THEN previous_digest END,CASE WHEN valid THEN payload_digest END,
CASE WHEN valid THEN payload_json END FROM candidates ORDER BY sequence`, id, id)
	if err != nil {
		return nil, journalError(ctx, errJournalStorage)
	}
	defer func() { _ = rows.Close() }()
	var out []journalRow
	for rows.Next() {
		if len(out) >= journalMaxCheckpoints {
			return nil, journalError(ctx, errJournalCorrupt)
		}
		var sequence sql.NullInt64
		var stage, previous, digest, payload sql.NullString
		if err := rows.Scan(&sequence, &stage, &previous, &digest, &payload); err != nil {
			return nil, journalError(ctx, errJournalStorage)
		}
		if !sequence.Valid || !stage.Valid || !previous.Valid || !digest.Valid || !payload.Valid {
			return nil, journalError(ctx, errJournalCorrupt)
		}
		data := []byte(payload.String)
		checkpoint, err := enrichmentjournal.Decode(data)
		if err != nil {
			return nil, journalError(ctx, errJournalCorrupt)
		}
		canonical, err := enrichmentjournal.Encode(checkpoint)
		if err != nil || !bytes.Equal(canonical, data) || checkpoint.OperationID != id || string(checkpoint.Stage) != stage.String || journalDigest(data) != digest.String {
			return nil, journalError(ctx, errJournalCorrupt)
		}
		out = append(out, journalRow{sequence: sequence.Int64, stage: stage.String, previous: previous.String, digest: digest.String, payload: data, checkpoint: checkpoint})
	}
	if err := rows.Err(); err != nil {
		return nil, journalError(ctx, errJournalStorage)
	}
	if err := rows.Close(); err != nil {
		return nil, journalError(ctx, errJournalStorage)
	}
	return out, nil
}

func checkJournalHistory(header journalHeader, exists bool, rows []journalRow) error {
	if !exists {
		if len(rows) != 0 {
			return errJournalCorrupt
		}
		return nil
	}
	if len(rows) == 0 || int64(len(rows)) != header.Sequence {
		return errJournalCorrupt
	}
	previousDigest := ""
	var previous *enrichmentjournal.Checkpoint
	for i := range rows {
		row := &rows[i]
		if row.sequence != int64(i+1) || row.previous != previousDigest || enrichmentjournal.ValidateTransition(previous, row.checkpoint) != nil {
			return errJournalCorrupt
		}
		previous, previousDigest = &row.checkpoint, row.digest
	}
	last := rows[len(rows)-1]
	if last.digest != header.Digest || last.checkpoint.Version != header.Version || last.checkpoint.Request.Connector != header.Connector || last.checkpoint.Request.After != header.After || last.checkpoint.Request.Limit != header.Limit {
		return errJournalCorrupt
	}
	runID := ""
	if header.RunID != nil {
		runID = *header.RunID
	}
	if runID != last.checkpoint.Progress.RunID {
		return errJournalCorrupt
	}
	return nil
}
