-- Experimental reservation storage only; existing journal/ingest rows are unchanged.
CREATE TABLE IF NOT EXISTS security_enrichment_reservations (
    operation_id TEXT PRIMARY KEY REFERENCES security_enrichment_operations(operation_id)
        CHECK(typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36),
    intent_id TEXT NOT NULL UNIQUE CHECK(typeof(intent_id)='text' AND length(CAST(intent_id AS BLOB))=36),
    connector TEXT NOT NULL CHECK(typeof(connector)='text' AND connector IN ('epss_feed','kev_feed')),
    expected_generation INTEGER NOT NULL CHECK(typeof(expected_generation)='integer' AND expected_generation BETWEEN 0 AND 9223372036854775806),
    generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation=expected_generation+1),
    reserved_digest TEXT NOT NULL CHECK(typeof(reserved_digest)='text' AND length(CAST(reserved_digest AS BLOB))=71),
    reserved_payload_json TEXT NOT NULL CHECK(typeof(reserved_payload_json)='text' AND length(CAST(reserved_payload_json AS BLOB)) BETWEEN 2 AND 1048576 AND json_valid(reserved_payload_json)),
    UNIQUE(connector,generation)
);
CREATE TABLE IF NOT EXISTS security_enrichment_source_generations (
    connector TEXT PRIMARY KEY CHECK(typeof(connector)='text' AND connector IN ('epss_feed','kev_feed')),
    generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation BETWEEN 0 AND 9223372036854775807),
    active_operation_id TEXT UNIQUE REFERENCES security_enrichment_operations(operation_id)
        CHECK(active_operation_id IS NULL OR (typeof(active_operation_id)='text' AND length(CAST(active_operation_id AS BLOB))=36)),
    active_intent_id TEXT UNIQUE REFERENCES security_enrichment_reservations(intent_id)
        CHECK(active_intent_id IS NULL OR (typeof(active_intent_id)='text' AND length(CAST(active_intent_id AS BLOB))=36)),
    CHECK((active_operation_id IS NULL)=(active_intent_id IS NULL)),
    CHECK(generation>0 OR active_operation_id IS NULL)
);
CREATE INDEX IF NOT EXISTS security_enrichment_operation_source ON security_enrichment_operations(connector,operation_id);
INSERT OR IGNORE INTO app_migrations(version,applied_at) VALUES(5,strftime('%Y-%m-%dT%H:%M:%fZ','now'));

