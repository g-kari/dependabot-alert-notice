-- Offline enrichment is independent of the legacy threat/scoring workflow.
CREATE TABLE IF NOT EXISTS security_enrichment_observations (
    id TEXT PRIMARY KEY,
    ingest_run_id TEXT NOT NULL REFERENCES ingest_runs(id),
    source TEXT NOT NULL CHECK(source IN ('epss','kev')),
    cve_id TEXT NOT NULL,
    published_at TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    evidence_identity TEXT NOT NULL,
    body_json TEXT NOT NULL,
    UNIQUE(ingest_run_id, source, cve_id)
);
CREATE INDEX IF NOT EXISTS security_enrichment_lookup ON security_enrichment_observations(cve_id,source,published_at,observed_at);
INSERT OR IGNORE INTO app_migrations(version,applied_at) VALUES(3,strftime('%Y-%m-%dT%H:%M:%fZ','now'));

-- Even an empty selection result retains inspectable source provenance.
CREATE TABLE IF NOT EXISTS security_enrichment_runs (
    ingest_run_id TEXT PRIMARY KEY REFERENCES ingest_runs(id),
    source TEXT NOT NULL CHECK(source IN ('epss','kev')),
    version TEXT NOT NULL,
    published_at TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    selected_cves_json TEXT NOT NULL,
    entries INTEGER NOT NULL CHECK(entries >= 0 AND entries <= 200),
    original_digest TEXT NOT NULL
);
