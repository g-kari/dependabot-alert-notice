# Assessment core preview input

`internal/findingpreviewwire.DecodeAssessment([]byte)` is a separately opted-in,
in-memory JSON boundary using `finding-preview-assessment-core-v0.1`. It returns
the entire existing preview adapter result. It is not an HTTP API, CLI, runtime
integration, database write, notification, operational deadline, close decision,
or risk acceptance. It does not fetch, authenticate, or verify evidence claims.

## Closed schema

The root has all fields and rules from [profile input](finding-priority-preview-profile-input.md),
with the new exact `schema_version` and one additional required `assessment` object.
`profile` and `binding` remain required. There is no inheritance or profile selection.
`Decode` and `DecodeProfile` still reject assessment fields and this version;
`DecodeAssessment` rejects both older versions. No automatic upgrading occurs.

Every assessment field below is required, including explicitly empty axes:

- `profile_id`, `repo`: nonblank strings, at most 256 decoded UTF-8 bytes each,
  exactly matching `profile.id` and `profile.repo`.
- `advisory_key`: at most 68 decoded UTF-8 bytes, exactly `"cve:" + finding.vulnerability_id`.
  No trimming, case conversion, identifier lookup, or GHSA-to-CVE inference occurs.
  This binding alone does not prove a canonical CVE.
- `applicability`: exactly `""`, `unknown`, `affected`, or `not_affected`.
- `reachability`: exactly `""`, `unknown`, `reachable`, or `unreachable`.
- `evidence`: one object, never an array, with all four fields required:
  - `id`, `source`: nonblank, non-secret identifiers, at most 256 decoded UTF-8 bytes.
  - `observed_at`, `expires_at`: strict RFC3339 timestamps under the existing
    [base input rules](finding-priority-preview-input.md).

The axis vocabulary is intentionally narrower than the existing config validator.
`mitigated` and the other axis's values are rejected. Existing config semantics
are unchanged. Unknown fields, null, arrays, duplicate decoded keys, case variants,
control characters, invalid Unicode, oversized input and excessive depth are rejected.
The inclusive whole-document limit remains 64 KiB and container depth remains 8.
All errors are fixed sanitized codes and return a zero result, without input text.

## Clock and binding rules

`observed_at <= as_of` and `observed_at < expires_at` are mandatory. Already-expired
evidence is accepted. At `expires_at == as_of`, the existing scorer treats it as
expired, as it does afterward. These input constraints do not change scoring.
All schema, binding, and evidence checks precede the adapter's unsupported-finding
classification. A structurally valid non-CVE/non-vulnerability input remains
unsupported with no score; malformed evidence or mismatched bindings still fail.

The existing binding ties the finding, asset, CVE, profile and repository together;
the three assessment identity fields must match that same target. Every value is
copied as supplied, and the single evidence becomes a one-element slice. Facts
are an empty map; fact-specific evidence is nil. Mitigation, local activity,
deployment revision and evidence reference/reviewer/revision remain empty. CVSS
is absent. Severity, lifecycle, asset context and feeds never fill these gaps.

There is exactly one shared adapter call site, after successful conversion. No
new scoring formula, normalizer, implicit clock, I/O, or inference is introduced.
EPSS and KEV retain their independent clocks, warnings and historical-positive behavior.

## Interpretation warning

A caller-supplied `not_affected` claim with unexpired evidence can cause the existing
model to return status `not_affected`, confidence `verified`, and priority `planned`,
even with missing CVSS, facts, and local activity. These labels are **model results
based on supplied claims**, not validation of their truth, provenance, authority,
or actual non-applicability. Expired evidence instead preserves the model's
`provisional` / `insufficient` result. MissingInputs and InputOrigins are returned
unchanged. Do not use this preview to suppress notifications, close a finding,
accept risk, or set actual deadlines.

## Synthetic example

All identities and evidence below are fictional; no real findings are requested.

```json
{
  "schema_version": "finding-preview-assessment-core-v0.1",
  "as_of": "2026-11-08T00:00:00Z",
  "finding": {"id":"finding-a","asset_id":"asset-a","category":"vulnerability","vulnerability_id":"CVE-2099-0001"},
  "asset": {"id":"asset-a"},
  "profile": {
    "id":"profile-a","repo":"synthetic/repo","environment":"production",
    "exposure":"internet","authentication":"customer","business_criticality":"critical",
    "max_outage_minutes":60,"data_classification":"restricted",
    "integrity_impact":"high","privilege_scope":"service_only"
  },
  "binding": {"finding_id":"finding-a","asset_id":"asset-a","cve":"CVE-2099-0001","profile_id":"profile-a","repo":"synthetic/repo"},
  "assessment": {
    "profile_id":"profile-a","repo":"synthetic/repo","advisory_key":"cve:CVE-2099-0001",
    "applicability":"affected","reachability":"reachable",
    "evidence": {"id":"claim-a","source":"synthetic-source","observed_at":"2026-11-07T00:00:00Z","expires_at":"2026-11-09T00:00:00Z"}
  }
}
```

## Deliberately deferred

Arbitrary facts, evidence arrays, fact-specific evidence, mitigation, local activity,
CVSS, metadata, reviewer/reference, revision checks and profile inheritance are not
accepted. In particular arbitrary facts must not be exposed without a separate
contract: the existing scorer can treat any nonempty facts map as known. Broader
validation and runtime integration require separate review and authorization.

Synthetic acceptance tests A01–A12 cover full typed-adapter parity; required fields;
closed vocabularies; exact bindings; clock ordering and expiry equality; supplied
not-affected interpretation; missing inputs; unsupported precedence; forbidden
extensions; version isolation; independent clocks/non-inference; and parser,
privacy, bounds and returned-result isolation. Existing P/W/R regressions and the
single-call/no-I/O architecture test remain in place. Fuzz seeds exercise the new
entry point without real data or services.
