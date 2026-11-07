# Phase 1, fifth slice: provenance, native-ID search and same-CVE associations

This extends the [common Findings read API](security-phase1.md) and [offline enrichment](security-enrichment.md). It addresses the existing Findings Console adapter's two workarounds: fetching sources separately to preserve source labels, and reading detail observations to obtain the native alert ID. It adds backend read contracts only. The separate Sites UI, its audience, real API connectivity and authentication are unchanged.

## Additive source provenance

Collection `items` and detail `finding` retain every existing flat Finding field and add optional `source` and `source_finding_id`. They are read-only projections from retained observations, not new persisted Finding fields. Finding IDs, source-native identity, first/last seen, source status, local triage, severity, approval and notification remain authoritative and unchanged.

The latest observation by observation time, then observation ID, supplies provenance. For a collection or related query with a `source` filter, the latest observation matching that source supplies its label/native ID. Detail uses the latest observation overall and retains its bounded observation history. If no observation exists, the optional provenance fields are omitted rather than guessed. Requesting a source does not merge or relabel persisted entities.

Existing adapters may continue issuing source-specific requests and decoding the original flat fields. They can now make a unified collection request and use item provenance for source labels. Existing `enrichments` and detail `enrichment` keep their previous meaning. No update to a stored Finding body or old replay receipt is needed.

## Search and exact CVE filter

`GET /api/v1/findings` additionally accepts `cve=CVE-YYYY-NNNN`. A single explicit identifier is validated and canonicalized to uppercase. A supplied empty, malformed, duplicate or multiple-CVE value is rejected. A match requires category `vulnerability` and an already-canonical, exact `vulnerability_id`. A GHSA, title mentioning a CVE, rule ID, secret type, package/correlation string or similar substring is not a match. This is identifier matching, not confirmation that a CVE is assigned or that a specific installation is exploitable.

`q` remains a literal substring search across the previous fields and now also searches retained observation `source_finding_id` and `source`. SQL wildcard characters `%` and `_` remain literal. Historical native-ID matches can be found even when the displayed provenance comes from a newer retained observation. Detail returns only the latest 200 observations, so an older matching observation may not be included; its truncation flag signals omitted retained history. All other filters continue to compose with search/CVE selection, count and pagination.

```text
GET /api/v1/findings?cve=CVE-2099-0001&limit=50&offset=0
GET /api/v1/findings?q=example%2Frepo%3A42
GET /api/v1/findings?source=trivy&q=synthetic-package
```

The CVE above is a synthetic example, not a live vulnerability claim.

## Related findings

`GET /api/v1/findings/{id}/related` returns a paginated read-only association:

- Original `items`, `total`, `limit`, `offset` and optional returned-ID `enrichments`.
- `anchor_id` identifies the selected existing Finding.
- `cve_id` is present when the anchor is a vulnerability with an exact canonical CVE.
- `relationship` is `same_cve` for that CVE scope, or `none` when the anchor has no canonical CVE. A canonical anchor can legitimately have zero related items.

The anchor is excluded from candidates. Different repositories/assets/packages/sources keep separate finding IDs and records even when they share a CVE. This is an investigation hint, not deduplication, common exploitability, shared remediation or a claim that an alert was resolved.

The endpoint accepts existing `q`, `source`, `severity`, `source_status`, `asset_id`, `limit`, and `offset` filters for candidates. It rejects `cve`, including an empty value, because a client must not override the anchor's scope. A non-CVE anchor returns an empty page and never falls back to all findings. Unknown anchors return JSON 404. Unknown/duplicate/invalid parameters return JSON 400. Missing pages have `items:[]` rather than null. Both the anchor and candidate count/page, provenance and enrichments are read in one database snapshot.

Page size remains 1–200 (default 50), offset 0–1,000,000, and query length/text bounds are unchanged. Ordering remains last-seen descending then Finding ID, with nanosecond-safe timestamp ordering. GET routes retain `Cache-Control: no-store`, bounded JSON errors and existing middleware/method behavior. There is no new write route, listener, CORS exception, credential or access change. Keep the existing loopback boundary.

## Verification and limits

Synthetic tests cover the old Console contract and the new additive fields, native-ID literal search/escaping, exact CVE/category matching, cross-source associations without merging IDs, filtering/pagination, source-specific/latest provenance, missing observations, enrichment consistency, non-CVE/unknown anchors, invalid scope overrides and unchanged stored Finding bodies/receipts/legacy workflow. Existing imports and schemas are unchanged; this slice adds no migration.

Passing Linux tests does not verify the private Sites UI against a real deployment, network/CORS reachability, production data, live collection, Windows/PowerShell or native Mac runtime. UI wiring and any protected real-data connection remain separate tasks.
