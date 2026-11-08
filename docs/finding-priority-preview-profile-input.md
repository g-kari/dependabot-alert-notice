# Explicit bound profile preview input

`internal/findingpreviewwire.DecodeProfile([]byte)` is a separate, opt-in pure
input boundary for wire version `finding-preview-profile-v0.1`. The existing
`Decode` and `finding-preview-base-v0.1` contract remain unchanged: they reject
profile/binding fields and the new version. DecodeProfile rejects the base
version; neither entry point silently upgrades inputs.

This adds only caller-supplied, already-resolved profile attributes and explicit
bindings to the [base JSON input](finding-priority-preview-input.md). It does not
resolve inheritance, select a profile, load configuration, check real repository
existence, authenticate a claim, or assign ownership. No transport, database,
CLI, UI, scanner, notification, output JSON, or runtime hook is introduced.
The existing model, adapter, scoring formulas, thresholds and deadlines remain
unchanged. K218's limited completion and K234's separate UI scope remain separate.

## Closed schema

The root contains the base fields (`schema_version`, `as_of`, `finding`, `asset`,
optional `provenance` and `enrichment`), plus mandatory `profile` and `binding`
objects. All base byte, depth, Unicode, duplicate-key, exact-case, null, unknown
field, timestamp, evidence and privacy rules apply without expansion.

Every profile field below is required. Missing attributes are rejected, not
filled from the asset, severity, or an ambient configuration:

- `id`, `repo`: nonempty strings, not all whitespace, at most 256 decoded UTF-8
  bytes. Repo is an opaque comparison identifier, not a URL or authorization.
- `environment`: production, staging, development, ci, unknown, or empty string.
- `exposure`: internet, partner, internal, isolated, unknown, or empty string.
- `authentication`: none, customer, employee, privileged, unknown, or empty string.
- `business_criticality`, `data_classification`, `integrity_impact`: unknown, low,
  standard, high, critical, restricted, confidential, internal, public, or empty
  string. This intentionally preserves the existing shared RiskLevel vocabulary
  used by the model/config validator, rather than narrowing it per column.
- `privilege_scope`: shared_control, production_write, service_only, sandbox,
  unknown, or empty string.
- `max_outage_minutes`: a canonical JSON decimal integer from 0 through
  2147483647 inclusive. Negative values (including -0), fractions, numeric strings,
  exponent notation, and alternate encodings are rejected. The upper bound is a
  32-bit input compatibility limit, not a new scoring threshold. Zero is the
  existing unknown representation, not a safe score or a zero-tolerance promise.

All profile strings are limited to 256 decoded UTF-8 bytes and reject control
characters. Explicit empty/unknown enum values are preserved. They are distinct
from omitted fields, and do not imply low risk.

Every binding field is also required:

- `finding_id`: matches finding.id.
- `asset_id`: matches asset.id and finding.asset_id.
- `cve`: matches finding.vulnerability_id; maximum 64 decoded UTF-8 bytes. Empty
  is permitted only as an explicit matching identifier for an unsupported input.
- `profile_id`: matches profile.id.
- `repo`: matches profile.repo.

Except for cve, binding strings are nonempty, not all whitespace, and at most
256 decoded UTF-8 bytes. All reject control characters. No trimming, case
conversion, advisory completion, cross-asset reuse, or implicit selection occurs.
Binding proves **consistency within the supplied input only**, not the truth of
the claims, actual permission, or authorization to access the named resource.

`extends`, `owner`, `owner_team`, `reviewed_by`, `reviewed_at`, `review_due_at`,
assessment, CVSS, raw references, secrets, and every unlisted field are rejected.
The model's unexposed metadata stays empty/nil. The caller supplies resolved
attributes; this boundary does not certify resolution or review provenance.

## Validation, results and limits

All supplied profile vocabulary, bindings and base/enrichment evidence are
validated before the adapter's unsupported classification. Valid non-vulnerability
findings, GHSA identifiers, noncanonical CVEs, and explicitly empty CVEs retain
the existing unsupported/no-score result. Adding malformed profile or evidence
to an unsupported finding still returns an error and zero Result.

The shared decoder calls the existing pure adapter once after successful
validation. Assessment and CVSS remain absent. Unknown technical intervals,
MissingInputs, InputOrigins, warnings, and the complete ScoreResult are retained.
The `bound_resolved_profile` origin is an input-path label, not authenticated
provenance. A supplied profile with unknown attributes is not an absent profile;
unknown attributes and missing assessment/CVSS remain visible.

EPSS zero versus absent, independent source clocks, the inclusive 72-hour
freshness boundary, and stale KEV's historical-positive warning are unchanged.
A stale positive may still receive high priority under the existing model. No
current-compromise determination or actual deadline is made here.

The complete input remains capped at 64 KiB, container depth at eight, with
root depth one. The same fixed error code set and zero Result on failure apply.
Errors contain no input values, unknown field names, raw parser errors, or
partial projections. Successful and valid-unsupported typed results retain the
allowed identity/context projection. Arbitrary secrets embedded in permitted
identity strings cannot be automatically detected; callers must supply suitable
non-secret identifiers. There are no external sinks.

## Synthetic acceptance

R01–R12 in `profile_test.go` cover full direct-adapter parity, explicit unknowns,
all allowed vocabulary and required fields, exact integer bounds, every binding,
unsupported precedence, base compatibility, context-only changes, enrichment
clocks, structure/privacy/resource limits, mutation isolation, and fuzzed fixed
diagnostics. The existing P01–P36 and W01–W09 remain applicable. The production
AST guard applies across all package files and preserves one adapter call site.

Fixtures use fictional identities and fixed clocks. Tests do not establish real
feed data, service ownership, authorized access, or production deployment.
Broader profile metadata, Assessment/CVSS schemas and runtime integration remain
separate future contracts.
