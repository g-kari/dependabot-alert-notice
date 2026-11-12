-- Dormant internal release storage. No live wiring or next-generation admission.
CREATE TABLE IF NOT EXISTS security_enrichment_release_certificates (
    operation_id TEXT NOT NULL PRIMARY KEY REFERENCES security_enrichment_reservations(operation_id)
        CHECK(typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36),
    intent_id TEXT NOT NULL UNIQUE REFERENCES security_enrichment_reservations(intent_id)
        CHECK(typeof(intent_id)='text' AND length(CAST(intent_id AS BLOB))=36),
    connector TEXT NOT NULL CHECK(typeof(connector)='text' AND connector IN ('epss_feed','kev_feed')),
    generation INTEGER NOT NULL CHECK(typeof(generation)='integer' AND generation BETWEEN 1 AND 9223372036854775807),
    format_version INTEGER NOT NULL CHECK(typeof(format_version)='integer' AND format_version=1),
    reserved_digest TEXT NOT NULL CHECK(typeof(reserved_digest)='text' AND length(CAST(reserved_digest AS BLOB))=71),
    terminal_sequence INTEGER NOT NULL CHECK(typeof(terminal_sequence)='integer' AND terminal_sequence IN (2,4,5)),
    terminal_previous_digest TEXT NOT NULL CHECK(typeof(terminal_previous_digest)='text' AND length(CAST(terminal_previous_digest AS BLOB))=71),
    terminal_digest TEXT NOT NULL CHECK(typeof(terminal_digest)='text' AND length(CAST(terminal_digest AS BLOB))=71),
    kind TEXT NOT NULL CHECK(typeof(kind)='text' AND kind IN ('success','failed','no_run')),
    run_id TEXT CHECK(run_id IS NULL OR (typeof(run_id)='text' AND length(CAST(run_id AS BLOB))=36)),
    receipt TEXT NOT NULL CHECK(typeof(receipt)='text' AND length(CAST(receipt AS BLOB))<=128),
    certificate_digest TEXT NOT NULL CHECK(typeof(certificate_digest)='text' AND length(CAST(certificate_digest AS BLOB))=71),
    certificate_json TEXT NOT NULL CHECK(typeof(certificate_json)='text' AND length(CAST(certificate_json AS BLOB)) BETWEEN 2 AND 4096 AND json_valid(certificate_json)),
    UNIQUE(connector,generation),
    FOREIGN KEY(operation_id,terminal_sequence) REFERENCES security_enrichment_checkpoints(operation_id,sequence)
) WITHOUT ROWID;
-- Reject all logical-key replacement paths before SQLite conflict resolution.
-- Finite TEXT/BLOB aliases are included, without relying on recursive_triggers.
CREATE TRIGGER IF NOT EXISTS security_enrichment_release_insert_once
BEFORE INSERT ON security_enrichment_release_certificates
WHEN EXISTS(SELECT 1 FROM security_enrichment_release_certificates
WHERE operation_id=NEW.operation_id OR operation_id=CAST(NEW.operation_id AS BLOB) OR operation_id=CAST(NEW.operation_id AS TEXT)
OR intent_id=NEW.intent_id OR intent_id=CAST(NEW.intent_id AS BLOB) OR intent_id=CAST(NEW.intent_id AS TEXT)
OR ((connector=NEW.connector OR connector=CAST(NEW.connector AS BLOB) OR connector=CAST(NEW.connector AS TEXT)) AND generation=NEW.generation) LIMIT 1)
BEGIN SELECT RAISE(ABORT,'release certificate immutable'); END;
CREATE TRIGGER IF NOT EXISTS security_enrichment_release_no_update
BEFORE UPDATE ON security_enrichment_release_certificates
BEGIN SELECT RAISE(ABORT,'release certificate immutable'); END;
CREATE TRIGGER IF NOT EXISTS security_enrichment_release_no_delete
BEFORE DELETE ON security_enrichment_release_certificates
BEGIN SELECT RAISE(ABORT,'release certificate immutable'); END;
INSERT OR IGNORE INTO app_migrations(version,applied_at) VALUES(6,strftime('%Y-%m-%dT%H:%M:%fZ','now'));
