# Phase 1: recorded connector status and coverage read API

This independent backend slice extends the [common read API](security-phase1.md) and the [Phase 0 ingest ledger](security-phase0.md). It does not complete Phase 1, add live collectors, or change the native Findings UI, GitHub authentication, scanner execution, deployment or production data.

## Request and access boundary

`GET /api/v1/connectors/status?as_of=2026-11-09T12:00:00Z`

- `as_of` is required, a nonzero RFC3339 timestamp with at most nine fractional digits and a valid numeric timezone. It evaluates the **current retained snapshot**, not a historical reconstruction. There is no implicit server clock, stale/stuck threshold or health check.
- Optional `source` is one of `dependabot`, `trivy`, `github_code_scanning`, `github_secret_scanning`, `epss_offline`, `kev_offline`.
- Optional `scope` is an exact, case-sensitive retained scope, 1–256 UTF-8 bytes without surrounding whitespace, control or format characters. It is an opaque source-specific identity, not an asset ID or a scope-type enum. The same scope text under different sources remains a different group. Owner-wide and repository scopes, different accounts, and CVE-selection hashes are never merged.
- Existing pagination applies: `limit` defaults to 50, range 1–200; `offset` defaults to zero, range 0–1,000,000. Unknown/duplicate parameters, invalid source/pagination/times and empty supplied filters return fixed JSON `400 invalid_query`. The raw query has the existing 4096-byte limit.
- Collection order is source then scope, binary ascending. `total` counts matching **recorded source/scope pairs before pagination**, not configured sources, assets or all possible scopes. An empty page has `items:[]`.

GET and HEAD use the existing handler/access boundary and `Cache-Control: no-store`. Standard write/OPTIONS/TRACE/CONNECT methods return JSON `405 method_not_allowed` and `Allow: GET, HEAD`; unknown API subpaths retain JSON 404. Existing CSRF, listener, loopback bind and CORS are unchanged. There is no write, ingest, admin or collection-trigger endpoint. Keep the Web listener private behind the separately reviewed access boundary.

## Response semantics

Each item includes `source`, `scope`, `status`, `coverage`, `liveness`, `recorded_runs`, `latest_attempt` and nullable `last_success`.

- `latest_attempt` is the latest **recorded run/receipt**, ordered by start time descending and then run ID descending. It is not proof that every actual attempt was recorded. `status` and `coverage` come only from this latest run. A current recorded failure/partial/running run cannot be hidden by an earlier success.
- `last_success` is the latest retained completed `result=success` receipt, ordered by finish time, then start time, then run ID, all descending. It may have `coverage=partial`. No successful receipt means null, not a synthesized zero or success. It does not override latest status or coverage.
- Both summaries contain only run ID, start/finish times, recorded result/coverage, `future` and nullable `age_seconds`. All persisted timestamps are canonical UTC RFC3339Nano. Ordering pads fractional seconds, so whole seconds and nanoseconds compare correctly; exact ties use ID. Invalid selected identities, source/scope metadata or timestamp/lifecycle combinations return fixed `422 invalid_snapshot`, never the offending data.
- `age_seconds` is whole elapsed seconds since finish, or start for a running row, at the explicit `as_of`. It describes ledger age, not scanner freshness, service availability, time since source publication or SLA compliance. No receipt clock is refreshed by reading.
- A run whose start/completion anchor is after `as_of` is retained with `future:true` and `age_seconds:null`. Its recorded result remains visible in the summary, but item `status` and `coverage` are `unknown`. `last_success` can itself be future; consumers must inspect its flag and must not treat it as current usable evidence. Moving `as_of` does not replay or filter historical rows.
- `liveness` is always `unknown`: a saved running row is neither proof of a live process nor proof that it is stuck. No failure cause, permission state or missing scan is inferred from age or absence.
- `recorded_runs` gives total/running/success/partial/failed counts across retained runs in that exact pair, including any future-dated records. Counts are not actual request/failure-rate statistics because ledger completeness is unknown.

`coverage_boundary.basis` is `recorded_source_scope_pairs`. `attempt_history` is `unknown`; `configured_scopes`, `unscanned_scopes` and `asset_denominator` are explicitly null. This store query does not read configuration or an authoritative asset/scan inventory. An unobserved scope might be unconfigured, never attempted, excluded, or missing records. Zero returned pairs does **not** mean zero configured assets, successful scanning, or complete coverage. Per-run `full` means only what that collector explicitly proved for its selected scope, not full configured inventory coverage or all security categories.

Status output never includes `cursor`, stored error codes/bodies, receipt hashes, `body_json`, raw reports, observations, source references or credentials. Unexpected storage errors use fixed `500 internal_error`. Existing Findings APIs and persisted entities are unchanged.

## What current writers actually record

- The Dependabot `FetchAlerts` handler starts a run before source collection and finishes it independently of caller cancellation. It can record success, partial, failed and an unfinished running attempt. Known errors include fetch/rate-limit/skip/cancellation/processing outcomes, but this API deliberately does not expose their internal code. Repository `full` requires positive complete-repository evidence, unfiltered severity and no skipped scope. Owner-wide collection remains partial because it does not prove an exhaustive repository inventory. Failure before ledger creation or failure to finalize can still leave incomplete evidence; no full attempt-history guarantee is claimed.
- Legacy Dependabot save/update/backfill projections create successful partial receipts. They are not proof of a complete collection attempt or live-source health.
- Offline Trivy, Code Scanning, Secret Scanning and EPSS/KEV imports commit **successful partial receipts only**, including empty imports. Validation fails before opening the selected DB; an import/storage failure rolls its transaction back. Failed offline attempts therefore do not appear, and an old successful receipt cannot establish the outcome of a later failed import. Exact replays do not add runs.
- No current receipt provides a configured-scope denominator, comprehensive asset inventory or unscanned list. EPSS/KEV scopes identify explicit CVE selections, not source asset coverage.

The existing Start/Finish ledger contract is enough to display recorded Dependabot attempts. Comprehensive offline failure/attempt reporting needs a separate, explicitly specified recording lifecycle: record an attempt outside the atomic successful-import transaction after safe source/scope validation, close it on all outcomes with bounded machine state, and link successful receipts to that attempt without reusing an import UUID already reserved by an existing running row. That writer/linkage and a versioned configured-scope inventory contract are **not implemented here**. They must preserve offline validation-before-DB guarantees and atomic rollback. This API does not create missing failure records during reads.

## Boundedness and verification

Count, SQL grouping, page metadata, latest run and last success are read in one read-only transaction under the existing store read lock. SQL returns at most the requested number of groups and two scalar run summaries per group. Historical receipt bodies are never loaded or decoded. The DB must still aggregate matching retained history to produce exact counts; this is bounded application materialization, not a constant-time history query. No schema migration or dependency is added; the existing connector/scope/time index remains in use.

Go tests use HTTP recorders and disposable synthetic SQLite databases. They cover exact source/scope isolation, retained counts/paging, success-versus-current-failure separation, partial/running/empty/future/unknown outcomes, nanosecond and ID ties, latest completion ordering, query/method validation, sanitized errors and output, canceled contexts, malformed selected metadata, receipt-body exclusion and every stored table unchanged after reads. These tests must pass in full CI before merge. Local setup limits, independent review and full CI results are reported separately; static checks are not integration/race/vet/build passes. No real provider, scanner, network, production database, user PC or running deployment is exercised.
