# Bounded finding preview input

`internal/findingpreviewwire.Decode([]byte)` accepts one in-memory UTF-8 JSON
object and returns the existing typed `findingpreview.Result`. It does not read
files, stdin, the network, configuration, or a database. No CLI, HTTP endpoint,
UI, scanner, runtime hook, persistence, notifications, or deadlines are added.
K218's limited ingestion/API completion and the separate K234 UI remain separate.

The wire schema is `finding-preview-base-v0.1`, independent of the adapter's
`v0.1`. It supports base finding context and EPSS/positive KEV enrichment only.
Profile, assessment, binding, CVSS, raw references, secrets, and all unlisted
fields are rejected, never silently discarded. The existing scoring model,
formulas, missing-input rules and adapter remain unchanged.

## Closed schema

Field names are exact, case-sensitive, and snake_case. Objects have no additional
properties. The following list is exhaustive; required fields are marked `*`.

- Root: `schema_version`*, `as_of`*, `finding`*, `asset`*, optional `provenance`,
  optional `enrichment`.
- Finding: `id`*, `asset_id`*, `category`*, `vulnerability_id`*; optional `severity`,
  `source_status`, `triage_status`.
- Asset: `id`*; optional `environment`, `criticality`.
- Provenance, if supplied: `finding_id`*, `source`*, `source_native_id`*.
- Enrichment, if supplied: `cve_id`*; optional `epss`, `kev`.
- EPSS, if supplied: `version`*, `run_id`*, `published_at`*, `observed_at`*,
  `probability`*; optional `percentile`, `reported_fresh`.
- KEV, if supplied: `version`*, `run_id`*, `published_at`*, `observed_at`*,
  `positive`* (must be true), `date_added`*; optional `reported_fresh`.

All fields are strings except objects, JSON-number probability/percentile, and
boolean positive/reported_fresh. The EPSS/KEV source is fixed by its object name;
there is no caller-controlled `source` field inside enrichment evidence.
Omitted reported_fresh means false and does not control calculated freshness.
Optional context strings default to empty, preserving missing context. Required
identities, category, provenance, version, and run ID cannot be empty or all
whitespace. Vulnerability ID may be empty to represent an unsupported finding.
No trimming, case conversion, alias inference, or identifier completion occurs.

Severity is empty, critical, high, medium, or low. Source status is empty, active,
resolved, suppressed, or unknown. Triage status is empty, new, triaged,
in_progress, risk_accepted, or closed. Asset environment/criticality remain
context strings, not inferred profile attributes.

The finding's asset ID must match the asset. Provenance finding ID and enrichment
CVE must match the finding. These bindings and all supplied evidence are checked
even when the finding category/CVE would be unsupported by the adapter.

## Resource and validation limits

- Complete input, including whitespace: at most 65,536 bytes, checked before
  parsing. UTF-8 must be valid; escaped lone UTF-16 surrogates are rejected rather
  than replaced. A literal replacement character remains valid Unicode.
- Container nesting: at most eight, root counted as one, checked during parsing.
  Arrays are unsupported everywhere. This schema's actual valid nesting is
  shallower; the depth limit is a parser safeguard, not permission for extra fields.
- Decoded strings: at most 256 UTF-8 bytes; vulnerability/enrichment CVE and asset
  environment/criticality: at most 64. Control characters (including NUL and DEL)
  are rejected. Limits apply after escape decoding.
- Duplicate keys, including escaped equivalent keys, unknown fields, case aliases,
  null at any location, trailing JSON, trailing non-whitespace, wrong types, and
  malformed syntax are rejected.
- Probability and percentile must be finite JSON numbers in the exact decimal
  range [0,1]. Values just above one are rejected even if float64 would round them
  to one. Positive values too small to represent as nonzero float64 are rejected.
  Accepted values are converted to the adapter's float64 representation. Explicit
  zero remains non-nil; absence remains unknown.
- Times require the RFC3339 form with seconds, an explicit Z or numeric timezone,
  and optional one-to-nine fractional second digits. Year and UTC year are 1–9999;
  zero time is rejected. Published <= observed <= explicit as_of; KEV added <=
  published. as_of is supplied by the caller, not compared with a hidden wall clock.

## Results and privacy

After validation, Decode calls the existing pure adapter exactly once. Eligible
results match independently constructed adapter inputs, including the unchanged
ScoreResult. Profile/assessment/CVSS stay absent; unknown intervals and
missing_inputs stay visible. EPSS and KEV have independent clocks and preserve
the inclusive 72-hour freshness rule. Stale KEV remains a historical positive
with the existing warning; the model can still assign high priority. This is
not evidence of current compromise and does not create a deadline.

A valid but unsupported category or noncanonical CVE returns the adapter's
unsupported result and no score. Syntax/schema/binding/evidence failures return
an error and the **zero Result**, never partial identity or evidence. Error text
is `finding preview input: <code>`, with fixed codes: size, encoding, syntax,
null, type, depth, duplicate, required, string, time, number, field, version,
enum, binding, positive, adapter. Errors expose neither raw decoder messages nor
input values, unknown key names, fragments, or offsets. Callers must check error
before interpreting any result.

Successful and valid-unsupported results intentionally preserve the adapter's
allowed identity/context projection. The interface does not classify arbitrary
text placed in allowed identity fields as a secret. Callers must select suitable
non-secret identities. Rejected payloads and unlisted fields are never returned.
There is no output JSON schema, logger, standard output, file, or external sink.
Results from separate calls do not share mutable state.

## Synthetic checks

`decode_test.go` names W01–W08: direct-adapter parity, known zero versus missing,
independent/stale clocks, unsupported results, invalid semantics, structural and
privacy rejection, inclusive byte/depth/string bounds, determinism and mutation
isolation. W09 in `boundary_test.go` guards production imports, clock operations,
init/goroutines, output calls, and the single adapter call site. The fuzz target
requires fixed errors and zero results for every rejected input.

Fixtures use fixed clocks and fictional identifiers (`CVE-2099-0001`); these
checks do not assert actual feed data, real vulnerabilities, production access,
or operational deployment. Runtime integration and broader schemas are future
work requiring their own contracts and validation.
