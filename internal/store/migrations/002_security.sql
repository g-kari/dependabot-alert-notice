-- Phase 0 is additive: alert_records and its workflow remain authoritative.
CREATE TABLE IF NOT EXISTS assets (
 id TEXT PRIMARY KEY, type TEXT NOT NULL, provider TEXT NOT NULL,
 account TEXT NOT NULL, region TEXT NOT NULL, native_id TEXT NOT NULL,
 environment TEXT NOT NULL, criticality TEXT NOT NULL, body_json TEXT NOT NULL CHECK(json_valid(body_json)),
 UNIQUE(type,provider,account,region,native_id)
);
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, category TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES assets(id),
 canonical_key TEXT NOT NULL, severity TEXT NOT NULL,
 triage_status TEXT NOT NULL CHECK(triage_status IN ('new','triaged','in_progress','risk_accepted','closed')),
 source_status TEXT NOT NULL CHECK(source_status IN ('active','resolved','suppressed','unknown')),
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, fingerprint TEXT NOT NULL, body_json TEXT NOT NULL CHECK(json_valid(body_json))
);
CREATE INDEX IF NOT EXISTS findings_asset_lookup ON findings(asset_id,source_status);
CREATE INDEX IF NOT EXISTS findings_correlation_lookup ON findings(canonical_key);
CREATE TABLE IF NOT EXISTS ingest_runs (
 id TEXT PRIMARY KEY, connector TEXT NOT NULL, scope TEXT NOT NULL,
 started_at TEXT NOT NULL, finished_at TEXT,
 result TEXT NOT NULL CHECK(result IN ('running','success','partial','failed')),
 coverage TEXT NOT NULL CHECK(coverage IN ('full','partial','unknown')),
 cursor TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '', body_json TEXT NOT NULL CHECK(json_valid(body_json))
);
CREATE INDEX IF NOT EXISTS ingest_runs_scope_lookup ON ingest_runs(connector,scope,started_at);
CREATE TABLE IF NOT EXISTS observations (
 id TEXT PRIMARY KEY, source TEXT NOT NULL, account TEXT NOT NULL, source_finding_id TEXT NOT NULL,
 finding_id TEXT NOT NULL REFERENCES findings(id), ingest_run_id TEXT NOT NULL REFERENCES ingest_runs(id),
 raw_ref TEXT NOT NULL, observed_at TEXT NOT NULL, fingerprint TEXT NOT NULL,
 body_json TEXT NOT NULL CHECK(json_valid(body_json)),
 UNIQUE(source,account,source_finding_id,ingest_run_id,fingerprint)
);
CREATE INDEX IF NOT EXISTS observations_finding_lookup ON observations(finding_id,observed_at);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, entity_id TEXT NOT NULL, event_type TEXT NOT NULL,
 actor TEXT NOT NULL, timestamp TEXT NOT NULL, before_ref TEXT NOT NULL, after_ref TEXT NOT NULL,
 body_json TEXT NOT NULL CHECK(json_valid(body_json))
);
CREATE INDEX IF NOT EXISTS events_entity_lookup ON events(entity_id,timestamp);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
