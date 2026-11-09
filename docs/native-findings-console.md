# Native Findings Console

## Design plan

The primary object is a source-native Finding, linked to an Asset and optional
same-CVE findings. Collection filters operate on findings. Source lifecycle,
local triage, and the legacy Dependabot approval flow are separate concepts.

Reproduce the approved visual reference with a dark navy navigation rail, a mint
selected state, and a quiet list/detail workspace. Keep shared `.card`, `.btn`,
`.badge`, `.field`, `.nav-link`, and `.interactive-scale` components. Scope token
overrides to the shared app shell. Existing approval/settings behavior remains intact.
The Overview/Assets integration extends this shell to legacy pages; see
[native Overview and Assets](native-overview-assets.md).

- Base: `#0b111a`; sidebar: `#0e1520`; surface: `#141e29`.
- Text: `#e6edf5`; muted: `#a4b2c4`; accent: `#78ddc2`.
- Typography: the existing `var(--font)` system/Japanese-capable fallback stack,
  with no font downloads on native or legacy pages.
- Layout: left-aligned rail + content; a bounded page summary, filters, list and
  detail sections. On small screens the rail becomes a compact navigation strip
  and field/detail grids collapse. Dense evidence tables scroll within cards.
- Intent: meaningful source identity and explicit uncertainty, not a fabricated
  risk dashboard. Do not reproduce the reference's synthetic score or demo counts.

The reference's source-mix idea is adapted to **the displayed page**, explicitly
labelled so it cannot be mistaken for a global aggregate. Active/resolved counts
are also page-only. Backend matching total stays separate.

## Read-only contract

`GET /findings` and `GET /findings/{id}` reuse the existing API query validator and
store read methods without an HTTP self-request. IDs are normalized UUIDs; source
native IDs remain separate and never become legacy approval IDs.

The list accepts `q`, `source`, `severity`, `source_status`, `asset_id`, `cve`,
`limit`, `offset`. Empty form filters mean no filter. Unknown or duplicated keys,
invalid enums/CVEs/IDs, controls, oversized input, and out-of-bounds pagination
are rejected. `q` is a literal substring, including `%` and `_`.

The detail accepts only `limit` and `offset` for same-CVE related paging. Latest
200 observations/events are shown with independent truncation notices. EPSS and
KEV are rendered independently, preserving source publication/observation times,
known zero EPSS, and unknown KEV (never interpreted as not listed). Related
findings are associations, not merged findings or deduplicated source identity.

API links target same-origin GET routes. The optional priority preview is an
explicit RFC3339 `as_of` GET form to the existing JSON endpoint, labelled as a
preview of the current snapshot, not historical reconstruction or a deadline.
No custom risk score is calculated. Raw evidence references are displayed as
escaped text, not navigable arbitrary URLs.

Native pages send `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
No auth, listener, CSRF, ingestion, triage or approval route is changed. Legacy
Alerts remains available via a clearly separate navigation item.

## Verification

See the implementation handoff for actual executed tests and environment limits.
Synthetic tests use httptest and temporary SQLite stores, not production data.

### Snapshot and navigation limits

The detail and related lists are two independent read snapshots. An ingestion
between those reads may change their relative contents; the full HTML page is
not an atomic historical snapshot. Each underlying store read keeps its own
existing consistent-read guarantees.

No-CVE findings retain their native identity and have no same-CVE association.
This screen does not add ingestion or network collection. API JSON and preview
forms are same-origin and use the application's existing deployment access
boundary; this change does not add authentication or make public exposure safe.

### Checks for this change

- Added eight `TestNativeConsole*` tests using httptest and temporary stores for
  filters/paging, source identity, related links, independent EPSS/KEV evidence,
  unknown/no-CVE states, escaping, 200-entry history truncation, safe errors,
  method/HEAD handling, no mutation, and legacy route/CSRF preservation.
- Parsed and executed the actual list/detail/error templates against populated
  and empty synthetic fixtures using only the Go standard library. This is a
  template check, not an execution of the application or database tests.
- Static HTML checks confirmed unique IDs, associated labels, same-origin GET
  forms and no script/external font resource in the native pages. Desktop/mobile
  CSS breakpoints, focus and reduced-motion styles were inspected statically.
- Package tests could not compile in the offline environment because the
  required SQLite, goldmark and go-isatty module versions were not cached.
  `scripts/check.ps1` could not start because PowerShell was unavailable.
  Full package tests, vet, race/build checks and rendered desktop/mobile visual
  verification remain required before claiming complete validation.
