-- Internal operation retention only; no existing ingest/enrichment row is changed.
CREATE TABLE IF NOT EXISTS security_enrichment_operations (
    operation_id TEXT PRIMARY KEY CHECK(typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36),
    format_version INTEGER NOT NULL CHECK(typeof(format_version)='integer' AND format_version=1),
    connector TEXT NOT NULL CHECK(typeof(connector)='text' AND connector IN ('epss_feed','kev_feed')),
    request_after TEXT NOT NULL CHECK(typeof(request_after)='text' AND length(CAST(request_after AS BLOB))<=128),
    request_limit INTEGER NOT NULL CHECK(typeof(request_limit)='integer' AND request_limit BETWEEN 1 AND 200),
    run_id TEXT UNIQUE CHECK(run_id IS NULL OR (typeof(run_id)='text' AND length(CAST(run_id AS BLOB))=36)),
    head_sequence INTEGER NOT NULL CHECK(typeof(head_sequence)='integer' AND head_sequence BETWEEN 1 AND 5),
    head_digest TEXT NOT NULL CHECK(typeof(head_digest)='text' AND length(CAST(head_digest AS BLOB))=71)
);
CREATE TABLE IF NOT EXISTS security_enrichment_checkpoints (
    operation_id TEXT NOT NULL REFERENCES security_enrichment_operations(operation_id)
        CHECK(typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36),
    sequence INTEGER NOT NULL CHECK(typeof(sequence)='integer' AND sequence BETWEEN 1 AND 5),
    stage TEXT NOT NULL CHECK(typeof(stage)='text' AND stage IN ('reserved','begin','fail','complete','returned')),
    previous_digest TEXT NOT NULL CHECK(typeof(previous_digest)='text' AND length(CAST(previous_digest AS BLOB)) IN (0,71)),
    payload_digest TEXT NOT NULL CHECK(typeof(payload_digest)='text' AND length(CAST(payload_digest AS BLOB))=71),
    payload_json TEXT NOT NULL CHECK(typeof(payload_json)='text' AND length(CAST(payload_json AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(payload_json)),
    PRIMARY KEY(operation_id,sequence)
);
INSERT OR IGNORE INTO app_migrations(version,applied_at) VALUES(4,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
