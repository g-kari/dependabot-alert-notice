package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// startGuardedFeedIngestRun is called with the Store mutex held. Only the two
// exact feed origin values use this branch; arbitrary other labels are not
// normalized. The guard and INSERT share a transaction. No clock is generated.
func startGuardedFeedIngestRun(ctx context.Context, db *sql.DB, connector, scope string, at time.Time) (model.IngestRun, error) {
	var run model.IngestRun
	if ctx == nil || db == nil {
		return run, reservationError(ctx, errReservationStorage)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return run, fmt.Errorf("ingest run開始失敗: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := guardLegacyEnrichmentWriteTx(ctx, tx, connector); err != nil {
		return run, err
	}
	if ctx.Err() != nil {
		return run, reservationError(ctx, errReservationStorage)
	}
	id, err := securityID()
	if err != nil {
		return run, err
	}
	run = model.IngestRun{ID: id, Connector: connector, Scope: scope, StartedAt: at.UTC(), Result: "running", Coverage: "unknown"}
	if err := insertIngestRun(ctx, tx, run); err != nil {
		return run, err
	}
	// After generation, preserve the old populated-run error return. A failed
	// Commit is uncertain, not permission to call Start again with a new UUID.
	if err := tx.Commit(); err != nil {
		return run, fmt.Errorf("ingest run開始確定失敗: %w", err)
	}
	return run, nil
}

// The SQL emits only four small flags per indexed exact-ID/finite-BLOB-alias
// candidate, never connector/id/body strings. Go JSON uses case-insensitive
// matching for these ASCII tags; s/K also have the long-s/Kelvin Unicode folds.
// json_each decodes escaped keys and retains duplicates. Unknown fields remain
// legal, but each recognized tag must occur exactly once with matching scalar
// identity. Values are never lowercased/trimmed into another connector origin.
// Healthy legacy bodies can be large: SQLite JSON parsing/work and their later
// Go body read are intentionally not advertised as globally byte/heap capped.
const legacyIngestFinishMetadataSQL = "WITH candidates AS (\n" +
	" SELECT id,connector,scope,started_at,finished_at,result,coverage,cursor,error,body_json\n" +
	" FROM ingest_runs WHERE id=? OR id=CAST(? AS BLOB) ORDER BY id LIMIT 3\n" +
	")\n" +
	"SELECT\n" +
	" CASE WHEN typeof(id)='text' AND typeof(connector)='text'\n" +
	" AND typeof(scope)='text' AND typeof(started_at)='text'\n" +
	" AND (finished_at IS NULL OR typeof(finished_at)='text')\n" +
	" AND typeof(result)='text' AND result IN ('running','success','partial','failed')\n" +
	" AND typeof(coverage)='text' AND coverage IN ('full','partial','unknown')\n" +
	" AND typeof(cursor)='text' AND typeof(error)='text' THEN 1 ELSE 0 END,\n" +
	" CASE WHEN result='running' THEN 1 ELSE 0 END,\n" +
	" CASE WHEN typeof(connector)='text' AND connector='epss_feed' THEN 1\n" +
	" WHEN typeof(connector)='text' AND connector='kev_feed' THEN 2 ELSE 0 END,\n" +
	" CASE WHEN typeof(body_json)='text' AND json_valid(body_json) THEN\n" +
	"  CASE WHEN json_type(body_json)='object' THEN (\n" +
	"   SELECT CASE WHEN\n" +
	"    SUM(CASE WHEN k IN ('id','connector','scope','started_at','finished_at','result','coverage','cursor','error') THEN 1 ELSE 0 END)=9\n" +
	"    AND COUNT(DISTINCT CASE WHEN k IN ('id','connector','scope','started_at','finished_at','result','coverage','cursor','error') THEN k END)=9\n" +
	"    AND SUM(CASE k\n" +
	"     WHEN 'id' THEN t='text' AND v IS candidates.id\n" +
	"     WHEN 'connector' THEN t='text' AND v IS candidates.connector\n" +
	"     WHEN 'scope' THEN t='text' AND v IS candidates.scope\n" +
	"     WHEN 'started_at' THEN t='text' AND v IS candidates.started_at\n" +
	"     WHEN 'finished_at' THEN t='null' AND candidates.finished_at IS NULL\n" +
	"     WHEN 'result' THEN t='text' AND v IS candidates.result\n" +
	"     WHEN 'coverage' THEN t='text' AND v IS candidates.coverage\n" +
	"     WHEN 'cursor' THEN t='text' AND v IS candidates.cursor\n" +
	"     WHEN 'error' THEN t='text' AND v IS candidates.error\n" +
	"     ELSE 0 END)=9\n" +
	"    THEN 1 ELSE 0 END\n" +
	"   FROM (\n" +
	"    SELECT lower(replace(replace(key,'ſ','s'),'K','k')) AS k,type AS t,value AS v\n" +
	"    FROM json_each(candidates.body_json)\n" +
	"   )\n" +
	"  ) ELSE 0 END\n" +
	" ELSE 0 END\n" +
	"FROM candidates"

// guardLegacyIngestFinishTx validates identity and any feed claims before Go body
// materialization, in the same transaction as the subsequent read and UPDATE.
// It grants neither execution ownership nor exact ambiguous-commit proof.
func guardLegacyIngestFinishTx(ctx context.Context, tx *sql.Tx, id string) error {
	if ctx == nil || tx == nil {
		return reservationError(ctx, errReservationConflict)
	}
	if ctx.Err() != nil {
		return reservationError(ctx, errReservationStorage)
	}
	rows, err := tx.QueryContext(ctx, legacyIngestFinishMetadataSQL, id, id)
	if err != nil {
		return reservationError(ctx, errReservationStorage)
	}
	defer func() { _ = rows.Close() }()
	type flags struct{ row, running, source, body int }
	candidates := make([]flags, 0, 2)
	for rows.Next() {
		if len(candidates) >= 2 {
			return reservationError(ctx, errReservationCorrupt)
		}
		var f flags
		if err := rows.Scan(&f.row, &f.running, &f.source, &f.body); err != nil {
			return reservationError(ctx, errReservationStorage)
		}
		if f.row < 0 || f.row > 1 || f.running < 0 || f.running > 1 || f.source < 0 || f.source > 2 || f.body < 0 || f.body > 1 {
			return reservationError(ctx, errReservationCorrupt)
		}
		candidates = append(candidates, f)
	}
	if err := rows.Err(); err != nil {
		return reservationError(ctx, errReservationStorage)
	}
	if err := rows.Close(); err != nil {
		return reservationError(ctx, errReservationStorage)
	}
	if ctx.Err() != nil {
		return reservationError(ctx, errReservationStorage)
	}
	if len(candidates) == 0 {
		return fmt.Errorf("ingest run読込失敗: %w", sql.ErrNoRows)
	}
	if len(candidates) != 1 || candidates[0].row != 1 {
		return reservationError(ctx, errReservationCorrupt)
	}
	f := candidates[0]
	if f.running == 0 {
		// Canonical existing non-running IDs retain the old SELECT predicate's
		// ErrNoRows behavior. No business write or acknowledgement follows.
		return fmt.Errorf("ingest run読込失敗: %w", sql.ErrNoRows)
	}
	if f.body != 1 {
		return reservationError(ctx, errReservationCorrupt)
	}
	switch f.source {
	case 1:
		return guardLegacyEnrichmentWriteTx(ctx, tx, "epss_feed")
	case 2:
		return guardLegacyEnrichmentWriteTx(ctx, tx, "kev_feed")
	default:
		return nil
	}
}
