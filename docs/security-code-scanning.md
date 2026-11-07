# Phase 1, second slice: offline GitHub Code Scanning ingestion

This extends the [Phase 1 Trivy/API slice](security-phase1.md). It does not complete Phase 1 or change the separate dashboard design/UI. The [third slice](security-secret-scanning.md) adds secret-free offline Secret Scanning metadata. The [fourth slice](security-enrichment.md) adds offline EPSS/KEV evidence for explicit CVE findings. Authenticated live collection and correlation UI remain future work.

## Input and scope

`cmd/import-code-scanning` reads a local flat JSON array in the format of GitHub.com's [repository Code Scanning alert list](https://docs.github.com/en/rest/code-scanning/code-scanning#list-code-scanning-alerts-for-a-repository). This is not SARIF, an organization alert list, a wrapper object, or a nested array of response pages. The caller explicitly supplies `--repository OWNER/REPO`, a trusted observation timestamp and a destination database (or `--dry-run`). Repository spelling is normalized to lowercase. The selected repository is authoritative. When `html_url` is present it must agree with that repository and native alert number; a URL never establishes or changes scope. Verify the export belongs to the selected repository before importing it.

This command never invokes `gh`, a scanner, application configuration, credentials, network requests, notifications or the application server. It does not collect/export alerts on the user's behalf. An existing local export or the synthetic fixture is enough to validate the development flow.

```sh
go run ./cmd/import-code-scanning \
  --input internal/adapter/testdata/code-scanning-synthetic.json \
  --repository example/repo --observed-at 2026-11-07T18:00:00Z --dry-run
```

To import into an explicitly selected disposable development database:

```sh
go run ./cmd/import-code-scanning --input alerts.json \
  --repository example/repo --observed-at 2026-11-07T18:00:00Z \
  --db ./scratch-security.db
```

Use `--input -` for stdin. File input must be a regular local file, not a URL/DSN. Input is limited to 10 MiB and 20,000 entries, including duplicates; metadata fields and locations are bounded. Unsupported states/severities, malformed identities, conflicting duplicates and invalid input fail before opening a database. Opening an existing selected database may apply the additive [Phase 0 migration](security-phase0.md); back it up and validate an isolated copy before using anything other than a disposable development database. No new migration is introduced.

## Selected metadata and lifecycle

- Repository assets reuse Dependabot's GitHub repository identity. Code Scanning finding identity is the repository and native alert number under a separate `github_code_scanning` source. It never merges with a Dependabot alert that happens to have the same number, advisory or repository.
- Findings retain rule ID, tool name, optional repository-relative file path/start line, security severity and a generated title. A canonical rule/tool tuple is a grouping hint only. Location/tool/rule changes update evidence without replacing native finding identity.
- Source snippets, instance messages, descriptions, tags, tool versions, refs, dismissal actors/comments, raw JSON and report-provided URLs are not persisted. Evidence URLs are derived from the selected repository and positive alert number. The raw input SHA-256 is retained only as part of the replay receipt.
- Native `open`, `fixed`, and `dismissed` map to `active`, `resolved`, and `suppressed`. These explicit source states do not change local triage or Dependabot approval. An `error`/`warning` diagnostic without `security_severity_level` remains `unknown` security severity.
- Every offline import has **partial coverage**, including empty or apparently complete exports. Missing alerts never close existing findings. Explicit states affect only included native alert identities. Observation time is supplied by the caller, not taken from untrusted input timestamps. Stale imports retain evidence without overwriting newer state.
- As with Trivy, run/assets/findings/observations/events commit atomically. Exact same-run replays are unchanged. Changed original bytes, repository, normalized data or timestamps under an existing run UUID are conflicts. Optional `--run-id UUID` is supported; the default is source-namespaced and derived from repository plus original input bytes. Preserve the original timestamp for a replay and use a new run ID for a new observation.

## Read API and verification

The existing GET-only `/api/v1/findings` accepts `source=github_code_scanning` and existing lifecycle, severity, asset and pagination filters. Literal `q` search now also includes `rule_id`, `tool_name` and `file_path`. Detail responses expose the selected metadata and bounded observations/events. No write route, new authentication, public listener, credential, permission or deployment change is added. Keep the existing loopback access boundary.

Synthetic tests cover bounds, sanitized errors, metadata exclusion, stable/source-isolated identity, explicit source lifecycle, replay/conflicts, rollback, stale evidence, no false closure, local triage preservation, shared repository assets and offline import-to-API integration. The normal full Go race/vet/build and Mac helper checks are separate from production deployment, live GitHub collection, scanner execution, PowerShell/just availability or native Mac runtime validation.
