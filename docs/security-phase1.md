# Phase 1, first slice: offline Trivy ingestion and common read API

This is the first incremental Phase 1 change in the [architecture roadmap](https://devsecops-architecture-ggg.mail590137.chatgpt.site/), built on Phase 0 (PR #17). It is not completion of the whole phase. The [second slice](security-code-scanning.md) adds offline GitHub Code Scanning ingestion. The [third slice](security-secret-scanning.md) adds secret-free offline Secret Scanning metadata. The [fourth slice](security-enrichment.md) adds offline EPSS/KEV evidence to common findings without changing legacy risk decisions. The [fifth slice](security-correlation.md) adds read-only provenance, native-ID search and same-CVE associations. The separate correlation/search UI wiring remains independent work. No running deployment or operational database is assumed or created by this development change.

## Offline input

The standalone `cmd/import-trivy` command reads an explicitly selected local Trivy SchemaVersion 2 JSON report. It does not run Trivy, load application credentials/configuration, send notifications, contact a service, or start the application. It supports vulnerability results for `filesystem` and `container_image`. Container images require an immutable `sha256` or `sha512` ImageID or repository digest. A filesystem report requires both ArtifactName and a trusted explicit scope.

The projected format follows [Trivy reporting](https://trivy.dev/docs/latest/configuration/reporting/#json), [v0.68.1 report.go](https://github.com/aquasecurity/trivy/blob/v0.68.1/pkg/types/report.go), and [v0.68.1 vulnerability.go](https://github.com/aquasecurity/trivy/blob/v0.68.1/pkg/types/vulnerability.go). Unsupported schema/artifact types fail closed. Input is bounded to 10 MiB, 2,048 results, 20,000 vulnerability entries, and bounded metadata fields. Raw reports, secret matches, configuration snippets, licenses, arbitrary metadata, and descriptions are not persisted. Only credential-free HTTP(S) evidence URLs without query strings or fragments are retained.

Validate without opening any database:

```sh
go run ./cmd/import-trivy --input internal/adapter/testdata/trivy-v2-synthetic.json \
  --scope example-project --observed-at 2026-11-05T12:00:00Z --dry-run
```

To import, explicitly select a disposable development database first. Protect any existing database with the consistent-backup and isolated-copy procedure in [Phase 0](security-phase0.md) before selecting it. Opening an existing database applies the same additive Phase 0 migration; this change introduces no new schema migration.

```sh
go run ./cmd/import-trivy --input report.json --scope example-project \
  --observed-at 2026-11-05T12:00:00Z --db ./scratch-security.db
```

`--input -` reads stdin. `--observed-at` is required and is the explicit trusted observation time, not an untrusted report timestamp. The default run UUID binds the scope and original report bytes. Optional `--run-id UUID` lets callers select their own identity. Preserve the original timestamp when replaying a run. The receipt binds the raw SHA-256 digest, normalized entities, scope and timestamps. Changed bytes (even ignored fields/whitespace), metadata, or times under an existing ID are conflicts. Changing timestamps requires a new run ID. Exact replays write no duplicate history; complete input validation occurs before opening the selected DB.

### Retry after an uncertain import result

For a non-dry-run import, a nonzero exit does not prove that the batch was rolled back. The CLI can return exit code 1 after a committed import if closing the database or writing the JSON summary fails. In that mode, `import committed, but database close failed; verify the run ID before retrying` and `cannot write result summary; verify the run ID before retrying an import` require checking the run before another import attempt. A summary-output failure in `--dry-run` does not imply any database write; dry-run never opens the database.

1. Preserve the run ID, scope, `--observed-at`, original JSON bytes, selected database, and any summary/error output.
2. If the outcome is uncertain, do not resend until the destination's run ledger and receipt have been checked through an existing authorized read-only method. This CLI has no status-lookup flag. If inspection is unavailable, pause and request verification.
3. When replay is appropriate after checking the recorded state, keep the same run ID, scope, observation time, original bytes and destination database. A successful exact replay returns `replay: true` without duplicate history. Do not generate a new UUID to bypass an uncertain result or a conflict.

A fresh scan is a separate observation, not a retry. The default run ID excludes the observation time, so a fresh scan with identical report bytes and scope needs a new explicit `--run-id UUID` when its observation time changes. A successful `--dry-run` neither reserves a run ID nor verifies a database import.

Source: [post-import CLI error paths](https://github.com/g-kari/devsecops-console/blob/bddeaf68747a974fdd932cc0fa8a56f7f27ce42b/cmd/import-trivy/main.go#L113-L135), [receipt/replay checks](https://github.com/g-kari/devsecops-console/blob/bddeaf68747a974fdd932cc0fa8a56f7f27ce42b/internal/store/security_import.go#L45-L148), and [default run ID](https://github.com/g-kari/devsecops-console/blob/bddeaf68747a974fdd932cc0fa8a56f7f27ce42b/cmd/import-trivy/main.go#L278-L290).

## Preservation and lifecycle

- Every imported batch commits its run, assets, findings, observations and audit events atomically. A failure within the import transaction rolls back the complete batch.
- Assets and source-native findings use stable scoped identities. Same-CVE findings from different sources, artifacts, packages, versions or targets remain distinct. Canonical advisory/ecosystem/package/path keys are correlation hints, not merge keys.
- Each new run retains its observation. Older observations cannot overwrite the latest finding. Local triage and first-seen values survive updates.
- Every offline import has partial coverage, including an empty report. It cannot resolve findings that are absent. Trivy's `Status: fixed` denotes availability of a fix, not evidence that the detected installation was fixed; detected findings stay active.
- Dependabot approval, evaluation, notification IDs, legacy rows and resolution controls remain authoritative and unchanged. Optional common finding title/advisory/package/fix metadata is populated for new Dependabot observations. Old JSON remains readable without rewriting historical rows.

## Common read API

The normal Web handler adds GET-only routes:

- `/api/v1/findings`: `q`, `cve`, `source`, `severity`, `source_status`, `asset_id`, `limit`, `offset`.
- `/api/v1/findings/{id}`: finding, affected asset, latest 200 observations and events. Explicit truncation flags indicate omitted older history; retained histories are returned chronologically.
- `/api/v1/findings/{id}/related`: exact same-CVE association, existing candidate filters and pagination; anchor scope cannot be overridden.
- `/api/v1/assets`: `limit`, `offset`.
- [`/api/v1/connectors/status`](security-connector-status.md): required `as_of`; optional exact `source`, `scope`, `limit`, `offset`. Reports recorded attempts/receipts, not configured inventory coverage.

Collections return `items`, `total`, `limit` and `offset`; limit defaults to 50 and is restricted to 1–200, offset to 0–1,000,000. Search is a literal substring across title, advisory, package/ecosystem/version, correlation key and asset identity; SQL wildcard characters are literal. Duplicate/unknown query parameters and invalid values are rejected. Unknown API paths return JSON 404; writes are not supported. Responses use `Cache-Control: no-store`, with bounded JSON errors rather than source or DB error text.

These routes share the application's existing Web access boundary; they do not add authentication. Keep the default loopback bind. Do not expose the Web listener publicly without a separately reviewed authenticated reverse proxy/access layer. Existing CSRF controls for old mutating routes are unchanged. No new ingest or triage HTTP write endpoint is introduced.

## Verification boundary

Tests use synthetic reports, disposable SQLite databases, and HTTP recorders. They cover input bounds, ignored sensitive categories, identity isolation, replay/conflicts, atomic rollback, stale evidence, no false closure, literal search, pagination, history caps, API errors/methods and legacy workflow regressions. A passing Linux cloud test suite is not a production migration, deployment, live scanner validation or Mac runtime verification.
