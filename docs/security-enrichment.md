# Phase 1, fourth slice: offline EPSS/KEV evidence

This adds selected CVE evidence to the [common Findings read API](security-phase1.md), after [Code Scanning](security-code-scanning.md) and [secret-free Secret Scanning](security-secret-scanning.md). It is independent of the separate dashboard UI and the existing legacy threat/risk workflow. It does not complete the whole phase, fetch feeds, recalculate priorities, or change source severity, triage, approvals, notifications or deadlines.

## Explicit local inputs

`cmd/import-threat-enrichment` reads one uncompressed local EPSS daily CSV or CISA KEV JSON. Require `--input`, `--source epss|kev`, `--cves` (1–200 explicit CVE identifiers), trusted `--observed-at`, and a database or `--dry-run`. CVE selections are trimmed, uppercased, sorted and deduplicated. Only selected CVEs are persisted, but the whole bounded feed is validated. There is no title/GHSA/package/subsequence inference or network lookup. A CVE is an identifier here, not proof that it is assigned or that the finding is exploitable.

The supported formats follow [FIRST daily EPSS data](https://www.first.org/epss/data) and the [official CISA KEV JSON schema](https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json). EPSS requires the first metadata comment to contain `model_version` and `score_date`, plus `cve,epss,percentile` columns (column order may vary). An optional `date` column must match the publication's UTC calendar day. A probability/percentile must be finite and between zero and one. Literal zero is evidence; a missing CVE is unknown. Historical EPSS v1 CSV without publication metadata, API response objects, compressed input and arbitrary columns are unsupported. Date-only and supported date-time metadata are normalized to UTC; timezone-free date-times are interpreted as UTC.

KEV requires `catalogVersion`, `dateReleased`, a count matching the raw vulnerabilities list, and `cveID`/`dateAdded` for each entry. Only positive membership is projected. Free-text descriptions, vendors/products, notes, required actions, URLs and arbitrary fields are not persisted. Duplicate JSON object keys, invalid dates/types, conflicting duplicate CVEs and unsupported identifiers fail closed. A missing selected CVE never becomes a negative membership claim. Source publication cannot be after the explicitly supplied observation time; a KEV added date cannot be after publication.

Input is UTF-8, limited to 32 MiB, 1,000,000 CSV rows or 20,000 KEV entries including duplicates. Identical duplicate entries are retained once. Invalid input returns sanitized errors, no partial projection, and never opens a database. This CLI does not load application configuration/credentials, fetch feeds, transmit an inventory, run scanners, or start services.

```sh
go run ./cmd/import-threat-enrichment \
  --input internal/threat/testdata/offline-epss-synthetic.csv --source epss \
  --cves CVE-2026-0001,CVE-2026-0002 --observed-at 2026-11-07T20:00:00Z --dry-run
```

For an explicitly selected disposable development database:

```sh
go run ./cmd/import-threat-enrichment \
  --input internal/threat/testdata/offline-kev-synthetic.json --source kev \
  --cves CVE-2026-0001,CVE-2026-0002 --observed-at 2026-11-07T20:00:00Z \
  --db ./scratch-security.db
```

`--input -` accepts stdin. Local files must be regular files, not URLs/DSNs. All four offline import CLIs reject UNC/device paths (including mixed slash forms) before filesystem access to avoid implicit SMB access on Windows. The caller must still ensure the selected ordinary path is on a trusted local filesystem, not a network-mounted drive. Dry-run does not create the selected database or its parent. Opening a selected existing DB applies an additive schema migration; follow the [consistent backup and isolated-copy procedure](security-phase0.md) before selecting anything other than a disposable DB. No production database or deployment is assumed or changed by this development.

## Provenance, replay and missing data

Migration 003 adds independent enrichment observations and run manifests, plus indexes/version metadata. It does not rewrite existing findings, native alert rows, legacy threat snapshots, scores or histories. The existing ingest ledger records `epss_offline`/`kev_offline` imports. A manifest preserves source/version, publication/observation clocks, selected CVEs, included-entry count and original digest even when none of the selected CVEs are present. Raw CSV/JSON is not stored. Provenance URLs are constructed from fixed official source locations.

Each run and its manifest/observations commit atomically. The source-specific receipt binds the original bytes, selected CVEs, normalized metadata and timestamps. The default UUID binds source, canonical selection and original bytes; optional `--run-id UUID` is supported. Exact replays with original timestamps are unchanged. Reusing a run ID after bytes/selection/version/time changes is a conflict. Contradictory evidence for the same source/CVE/publication (including version changes) is also rejected across different run IDs; it must not silently replace an existing publication. An identical publication may be observed again using a new run ID.

Every offline import is partial coverage. Missing selected CVEs and empty results do not erase prior evidence, refresh its clock, close findings, or set EPSS to zero/KEV to false. Newest publication wins, then newest observation for that publication; a newly imported older feed remains history and cannot overwrite a newer publication. EPSS and KEV clocks are independent. These records remain separate from legacy threat/risk inputs, so importing offline evidence does not alter an existing priority decision.

## Read API and freshness

The existing collection response adds optional `enrichments`, keyed by the returned finding ID. Detail adds optional `enrichment`. The original `items` and persisted Finding shape remain unchanged. Only category `vulnerability` with a canonical CVE in `vulnerability_id` joins evidence. A GHSA, title containing a CVE, Code Scanning rule ID, Secret Scanning type or a similar-looking substring does not match. Multiple source-native findings may reference the same CVE evidence without merging their identities.

Each source evidence includes version, publication time, observation time, ingest run, source reference and `fresh`. Fresh is true only when both clocks are nonzero, not in the future and no more than 72 hours old at query time. Stale evidence remains visible with `fresh:false`; it must not be interpreted as a current probability or a safe negative. A historical KEV positive stays positive even if stale. Absence of source evidence means unknown, never zero probability or not-exploited. This is a conservative display freshness rule, not a change to an organizational priority/SLA policy. Collection/detail read evidence within the same database snapshot as their findings. No new HTTP write route, UI, listener, access or authentication changes are introduced; keep the existing loopback boundary.

## Verification boundary

Tests use synthetic feeds, disposable databases and HTTP recorders. They cover explicit identity/selection, size/entry bounds, dates and source independence, duplicates/conflicts, zero versus missing, old-feed ordering, stale/future clocks, atomic rollback/replay, empty manifests, additive migration/legacy preservation and CLI-to-API behavior. Live feed authenticity/collection, production migration/deployment, actual risk-priority recomputation and native Mac runtime are not verified by these Linux tests. PowerShell/just tool availability is reported separately.
