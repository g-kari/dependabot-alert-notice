# Read-only finding priority preview

`GET /api/v1/findings/{id}/priority-preview?as_of=2026-11-09T00%3A00%3A00Z`
connects a selected current common Finding to the existing base preview model.
It does not persist scores, change triage or risk, create deadlines, or notify.
This is product code tested with synthetic data, not a production rollout.

## Explicit snapshot contract

`as_of` is required exactly once. It uses strict RFC3339 with seconds, an explicit
zone, and at most nine fractional digits. URL-encode a positive zone's plus sign.
No other query parameters are accepted. There is no hidden evaluation clock.
The response schema is `finding-priority-preview-api-v0.1`, with:

- `warning`: fixed preview-only and unverified-evidence interpretation warning.
- `input_snapshot`: the complete closed `finding-preview-base-v0.1` JSON input.
- `result`: the full unchanged preview Result, including missing inputs, origins,
  evidence clocks, mapping warnings, confidence and ScoreResult.

The selected current finding, exact asset, latest provenance and latest retained
EPSS/KEV evidence are read in one transaction. `as_of` evaluates that snapshot;
it does **not** reconstruct the database at a historical time. Future evidence
fails closed. The endpoint never silently selects an older feed to make an old
`as_of` succeed. Repeating a request is deterministic while stored inputs remain
unchanged; retain the returned snapshot when reproducibility across DB updates
is required. Read-time freshness is calculated at explicit `as_of`.

Profiles, assessments and CVSS are absent, never selected or inferred from
severity, asset criticality or related findings. Absent provenance stays absent.
The same-CVE relationship remains an investigation hint, not a merge or an
assessment binding. Missing evidence is unknown, not zero or safe. A real EPSS
zero survives, and stale KEV retains the existing historical-positive behavior.
Valid unsupported findings return `AdapterState=unsupported` and no score.

## Offline replay

Extract only `input_snapshot` from the JSON response and pass it unchanged to:

```sh
preview-finding --schema base < snapshot.json
```

The CLI's `result` equals the API's full `result`; their response envelopes have
separate versions. The CLI remains stdin-only/offline. This endpoint never runs
it or spawns a process. The integration test builds/runs the existing command
against a synthetic HTTP-recorder response, without starting the application.

## Boundaries and errors

Stored JSON rejects invalid Unicode and duplicate keys, including case aliases,
before model decoding. Enrichment SQL run/source/clocks must match its JSON.
Stored values are projected to the existing closed wire schema and revalidated
without truncating strings, replacing invalid UTF-8, coercing unknown enums,
repairing bindings, or substituting zero. Existing 64 KiB and field limits apply.
Unexpected source/type mixtures in enrichment fail rather than dropping evidence.
No raw observation/event history, RawRef, credentials, profiles or assessments
are returned. Allowed identifiers/context are not secret-detected or redacted;
use synthetic/non-secret data for testing and protect responses like other
Findings API data. Do not publish snapshots blindly.

Errors contain fixed codes only: 400 `invalid_query`, 404 `not_found`, 422
`invalid_snapshot`, or 500 `internal_error`. Standard non-GET methods receive
405 `method_not_allowed`, with `Allow: GET, HEAD`; HEAD follows the existing Go
GET route semantics. Other unsupported methods use the existing router's 405.
The endpoint does not accept request bodies or create a write operation.

The existing listener, middleware, loopback default, and access boundary remain
unchanged. Responses use `Cache-Control: no-store`; no CORS or authentication
exception is added. Keep the existing private access boundary. Public exposure,
authentication changes, production startup/migration, real-data connection,
notifications and the separate Sites UI are not part of this change.

Synthetic acceptance covers wire/typed parity, compiled CLI replay, explicit
clock freshness, EPSS zero/missing, stale KEV, unsupported cases, invalid evidence
and bindings, bounds, fixed query/errors/methods, and unchanged stored state.
