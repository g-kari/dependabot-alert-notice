# Phase 0: additive security data foundation

Phase 0 follows the [architecture roadmap](https://devsecops-architecture-ggg.mail590137.chatgpt.site/).
The implementation starts from `790d2b0438619533db70d82f7ef1eceaef3c8a54`, which includes PR #11 and the subsequent Renovate configuration merge.

## Compatibility boundary

`alert_records` remains the authority for Dependabot approval, evaluation, notification IDs, and merge handling. The existing Web UI, TUI, RSS, risk scoring, notification batching, and approval controls retain their current contracts. Normalized `Finding.triage_status` is a separate axis from both the native source lifecycle and the existing approval state. An approved alert is not automatically a closed finding.

The additive migration creates `assets`, `findings`, `observations`, `events`, and `ingest_runs`. Existing alert IDs, JSON, evaluations, notification references, resolution history, and ancillary tables are not rewritten or removed. Schema creation, backfill, and migration version 2 are committed in one transaction. Unknown legacy schema or malformed source identities stop migration rather than discarding data. The existing version 1 guard already rejects an `alert_records` table without its native `number` column.

## Identity and ingestion

- Asset identity is the normalized GitHub account and repository.
- Finding identity is `dependabot`, account, repository, and source-native alert number. Deterministic UUIDs do not depend on the local database ID, CVE, or approval state.
- Advisory, ecosystem, package, and manifest form a correlation hint only. Separate repositories and alert numbers remain separate findings, even for one CVE.
- Each observation links its source identity, ingest run, observation time, original GitHub URL, and source fingerprint. The fingerprint excludes the local database ID and approval/evaluation/notification fields. Source payloads remain in the existing alert table and at the source URL; observations do not create a second raw-payload archive.
- Source-state changes and evidence changes append audit events. Database triggers reject audit updates and deletes. Reopening preserves finding identity and previous observations/events.
- Explicit source reads record an ingest attempt and coverage. Filtered, skipped, legacy-client, and failed collection cannot be treated as a complete scan. Existing completeness and monitoring-policy gates still control source resolution.
- Replaying the same observation in the same run does not duplicate it. An older observation remains evidence but cannot roll current finding state backward.
- Legacy save/update/resolution and their normalized projection share one SQLite transaction. Projection failure rolls back the legacy mutation and does not publish a partially updated workflow.
- Ingest error fields accept bounded machine codes, not raw API responses, credentials, or tokens. An unfinished `running` attempt remains visible after interruption. A subsequent poll starts a new run; it does not infer resolution from the interrupted attempt.

## Upgrade and recovery procedure

No production migration is performed by the development tests. Starting the new binary against a production database would apply version 2 and must be part of the separately reviewed deployment.

1. Stop the application and all writers before copying its SQLite database. If SQLite sidecar files exist, use SQLite's supported backup mechanism or take a consistent backup of the complete stopped database state. Do not copy a live database file alone.
2. Keep the original database and binary. Verify the backup can be opened on an isolated copy.
3. Start the new binary against an isolated copy first. Confirm alert row counts, IDs, evaluations, approval states, notification IDs, RSS/risk data, and normalized findings. Then run the normal fetch/notification/approval regression checks with test services.
4. If backfill fails, do not delete or reset the database. The version 2 transaction is rolled back and the original rows remain available. Diagnose and repair the specific source/schema problem on a copy, then retry the migration on that copy.
5. If an application rollback is needed, stop all writers and restore the verified database/binary pair together. Older binaries ignore the additional tables, but writes by an old binary do not maintain the normalized projection. Do not mix versions against one live database or assume a binary-only rollback leaves the projection synchronized.

Automated tests reproduce a failed migration followed by repair/reopen, repeated migration without duplicate history, projection failure followed by a safe retry, resolution rollback, repeated observation replay, and out-of-order source evidence. Test fixtures use disposable databases and mocked integrations only.

## Phase boundary

This change does not add another scanner, external credentials, an HTTP Findings API, a new UI, PostgreSQL, new cloud permissions, production deployment, or a backfill against the user's real database. Those remain separate reviewable steps. Phase 1 can build source adapters and APIs on this storage contract without folding Dependabot-specific approval controls into generic finding state.
