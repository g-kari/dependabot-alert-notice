# Phase 1, third slice: secret-free offline Secret Scanning metadata

This extends the [Trivy/API](security-phase1.md) and [Code Scanning](security-code-scanning.md) slices. It does not complete Phase 1 or change the separate dashboard UI. Authenticated collection, correlation UI and EPSS/KEV enrichment remain separate work.

## Secret-free input only

`cmd/import-secret-scanning` accepts an explicitly selected local flat JSON array using a **secret-free subset** of GitHub.com's [repository Secret Scanning alert list](https://docs.github.com/en/rest/secret-scanning/secret-scanning#list-secret-scanning-alerts-for-a-repository). An unfiltered API response may contain literal credentials and is not a suitable input. The `secret` member must be absent, `null`, or the empty string. Any nonempty value, including a masked placeholder, is rejected before opening a database. A later duplicate `secret: null` cannot overwrite an earlier forbidden literal. Do not provide real secrets to this tool or put them in other metadata fields. This is not a general-purpose redaction or secret-detection tool.

Use the synthetic fixture for development. A separately authorized export process must suppress literal secrets upstream (the documented repository list has `hide_secret=true`) and verify that `secret` is absent/null/empty. If its response contains a masking string, remove that member in a trusted process before selecting the resulting secret-free file. This command does not perform that export, request additional permissions, fetch alerts/locations, read credentials/configuration, verify or revoke credentials, start a scanner/server, or send notifications. No live secret-scanning endpoint was accessed during this development.

```sh
go run ./cmd/import-secret-scanning \
  --input internal/adapter/testdata/secret-scanning-synthetic.json \
  --repository example/repo --observed-at 2026-11-07T20:00:00Z --dry-run
```

For an explicitly selected disposable development database:

```sh
go run ./cmd/import-secret-scanning \
  --input internal/adapter/testdata/secret-scanning-synthetic.json \
  --repository example/repo --observed-at 2026-11-07T20:00:00Z \
  --db ./scratch-security.db
```

`--input -` reads stdin. Require an explicit repository and observation time; the file never establishes trusted scope. Verify it belongs to the selected repository. When present, `html_url` must match that repository/positive alert number without query, fragment or credentials. Stored evidence URLs are constructed, not copied. URLs, nested response pages, organization lists, single alert objects and location lists are unsupported. Input is bounded to 10 MiB and 20,000 entries including duplicates. Invalid input returns sanitized errors and no partial results. Dry-run does not create a DB or its parent. Opening a selected existing DB may apply the additive [Phase 0 migration](security-phase0.md); back it up and validate an isolated copy first. This slice adds no migration.

## Metadata, identity and lifecycle

- Only the numeric alert identity, bounded lowercase type identifier, explicit source state/resolution and trusted observation context are projected. Findings expose optional `secret_type` and `secret_resolution`, a generated title and grouping key. Secret values, type display names, locations/paths/blobs, snippets, actors/assignees, comments, provider/owner metadata, validity claims and raw payloads are not persisted. No secret-value model field is added. The raw input digest is used for replay only, so supply secret-free input, not a credential-bearing report.
- Severity remains `unknown`. A source validity claim is not a verified active credential, and importing metadata never tests one.
- `open` with no resolution maps to `active`. `resolved/revoked` maps to `resolved`, reflecting only the source's explicit claim. `resolved/false_positive`, `wont_fix`, `used_in_tests`, `pattern_edited` or `pattern_deleted` map to `suppressed`, without claiming revocation. Missing/unsupported resolution or contradictory open/resolution fails closed. No source state changes local triage or Dependabot approval.
- Repository assets share the existing GitHub identity. Findings use the separate `github_secret_scanning` source plus repository/native alert number. Same-number Dependabot and Code Scanning alerts remain distinct; matching secret type is only a grouping hint, never a merge key.
- Every snapshot has partial coverage, even empty exports. Missing findings never close. Stale observations append evidence without overwriting newer state; first-seen and local triage survive updates.
- Run/assets/findings/observations/events commit atomically. The source-namespaced default UUID binds repository and original secret-free input bytes; optional `--run-id UUID` is supported. Exact replays with the original time are unchanged. Reusing an ID after byte/metadata/scope/time changes is a conflict. Use a new ID for a new observation.

## Read API and verification boundary

The existing GET-only Findings API accepts `source=github_secret_scanning`, lifecycle/severity/asset filters and literal `q` searches including secret type and resolution. Detail returns selected metadata and bounded history, never literal secrets. No new write route, listener, authentication, permissions, credential storage, deployment or UI is introduced. Keep the existing loopback boundary.

Tests use synthetic markers and disposable SQLite databases only. They cover literal-secret rejection (including duplicate/escaped/case variants), sanitized errors, bounds, metadata exclusion, lifecycle, source isolation/shared assets, replay/conflicts, rollback, stale updates, no false closure, legacy receipt compatibility and import-to-read-API behavior. Linux checks are not production deployment/migration, live collection, actual credential verification, PowerShell/just availability or native Mac validation.
