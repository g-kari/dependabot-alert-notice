-- Risk/feeds additive migration. The runtime migration keeps this schema
-- idempotent and refuses to rewrite unknown legacy tables.
CREATE TABLE IF NOT EXISTS app_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rss_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT, feed_url TEXT NOT NULL, external_id TEXT NOT NULL,
  title TEXT NOT NULL, link TEXT NOT NULL, summary TEXT NOT NULL, published_at TEXT,
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, UNIQUE(feed_url, external_id)
);
CREATE TABLE IF NOT EXISTS rss_item_cves (
  item_id INTEGER NOT NULL REFERENCES rss_items(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL, PRIMARY KEY(item_id, cve_id)
);
CREATE INDEX IF NOT EXISTS rss_cve_lookup ON rss_item_cves(cve_id, item_id);
CREATE TABLE IF NOT EXISTS rss_feed_status (
  feed_url TEXT PRIMARY KEY, last_attempt_at TEXT, last_success_at TEXT,
  last_error TEXT NOT NULL DEFAULT '', item_count INTEGER NOT NULL DEFAULT 0,
  etag TEXT NOT NULL DEFAULT '', last_modified TEXT NOT NULL DEFAULT '', next_attempt_at TEXT
);
CREATE TABLE IF NOT EXISTS service_assessments (
  profile_id TEXT NOT NULL, advisory_key TEXT NOT NULL, config_revision INTEGER NOT NULL,
  body_json TEXT NOT NULL, PRIMARY KEY(profile_id, advisory_key)
);
CREATE TABLE IF NOT EXISTS threat_snapshots (
  source TEXT NOT NULL, advisory_key TEXT NOT NULL, fetched_at TEXT NOT NULL,
  source_date TEXT, body_json TEXT NOT NULL, PRIMARY KEY(source, advisory_key)
);
CREATE TABLE IF NOT EXISTS score_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id TEXT NOT NULL, repo TEXT NOT NULL,
  advisory_key TEXT NOT NULL, model_version TEXT NOT NULL, input_hash TEXT NOT NULL,
  computed_at TEXT NOT NULL, input_json TEXT NOT NULL, result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS score_history_lookup ON score_history(profile_id, advisory_key, id DESC);
CREATE INDEX IF NOT EXISTS score_history_repo_lookup ON score_history(repo COLLATE NOCASE, advisory_key, id DESC);
CREATE TABLE IF NOT EXISTS risk_deadlines (
  profile_id TEXT NOT NULL, advisory_key TEXT NOT NULL, episode INTEGER NOT NULL,
  opened_at TEXT NOT NULL, due_at TEXT NOT NULL, priority TEXT NOT NULL, closed_at TEXT,
  PRIMARY KEY(profile_id, advisory_key, episode)
);
