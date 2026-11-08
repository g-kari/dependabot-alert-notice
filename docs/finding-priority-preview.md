# Common finding priority preview

`internal/findingpreview.Calculate` is an internal, pure adapter to the existing
`urgency-v1` model. It is not connected to HTTP, CLI, UI, a database, notifications,
triage, approval, or deadline creation. No application or service is started.

Contract version: `v0.1`. Reviewed model/schema basis:
`84fee44ff5447bac1f4233da0095e597455ed9b6`. This is a compatibility basis, not a
claim that the adapter itself existed at that commit.

## Selection and binding

The caller supplies a finding, its exact asset, and an explicit evaluation time.
Only `vulnerability` findings with an already canonical CVE are eligible.
Unsupported inputs have no score. Invalid identities, bindings, evidence, or
clocks return a contextual error with `AdapterState=invalid`, and no score.
Neither path substitutes zero or `planned` for missing knowledge.

An optional resolved profile is bound to the finding ID, asset ID, CVE, profile
ID and repository. Assessments require that profile and must match its ID,
repository and canonical advisory key. The adapter does not select profiles,
resolve inheritance, or carry assessments across assets with the same CVE.
Optional CVSS evidence has its own explicit finding/asset/CVE binding. It must
be previously validated by the caller; this adapter only validates finite range
and the known/value combination, not the full CVSS specification.

A common Finding has no source or source-native ID. An optional Observation
provides those two fields only after its FindingID matches. Its RawRef and all
other payload/reference fields are deliberately omitted. Source/native ID
absence remains visible in MissingInputs. Finding severity and lifecycle, and
asset environment/criticality are preserved as context, never converted into
technical impact, profile attributes, applicability, mitigation, or actions.

## Evidence and missing information

EPSS and KEV retain independent publication and observation times, source,
version and run identity. Mandatory times must be nonzero, ordered and not in
the future. Freshness is recalculated at the supplied time using the existing
inclusive 72-hour boundary. Caller-reported freshness is separately labeled.
A real EPSS zero remains a non-nil zero; absence is not zero. Absent KEV is
unknown, never a negative. Common KEV evidence must be a positive with a valid
added date no later than feed publication.

Stale KEV remains a historical positive and is explicitly labeled, with
Fresh=false and a warning. **The existing model does not suppress stale KEV.**
It may still return confirmed/immediate, which is preserved unchanged. This is
not verification of current compromise. Only explicit bound assessment data
can provide confirmed_compromise. Stale EPSS remains visible even if KEV takes
precedence in the model.

Missing profile/assessment fields remain unknown. Missing CVSS uses the existing
normalizer's unknown intervals, not a zero-valued TechnicalImpact. MissingInputs
is a separate input inventory; it does not replace ScoreResult.MissingFacts.
MappingWarnings describes mapping/freshness caveats. ScoreResult is the exact
existing Calculate result, including its status, reasons, confidence, intervals,
rules and priority. Priority names are categories, not scheduled deadlines.

## Scope and resource boundaries

Inputs and returned snapshots do not share mutable maps, slices or pointers.
CVSS vectors are limited to 2048 bytes and versions to 32 bytes. Assessment facts,
aggregate evidence and fact keys are each limited to 128 entries, with at most
128 evidence entries per fact. This is an internal function, not an untrusted
wire schema. Introducing arbitrary external input needs its own validation and
resource review.

The 36 named P01–P36 synthetic acceptance cases in `preview_test.go` cover the
contract, with additional invalid-value variants. Every eligible case compares
the full result to the existing scoring function. No actual CVE, finding, feed,
compromise, production connection, or successful execution is implied by the
fictional fixtures. `CVE-2099-0001` is only a fixture identifier.

Model formulas, thresholds, normalizer behavior, legacy risk paths and SLAs are
unchanged. Runtime adoption, real data connections, UI, feeds, notifications,
production, permissions and billing are separate work.

`InputOrigins` records each logical ScoreInput field's source and any missing
reason, including bound inputs, missing-input defaults, and existing CVSS
normalization. It distinguishes absent snapshots from explicit unknown values.
Profiles and assessments are internal, previously validated snapshots. Their
enum and fact vocabulary validation remains the caller's responsibility, just
like complete CVSS specification validation; this package is not a general
external-input validation boundary.

A separate [bounded base-enrichment JSON input](finding-priority-preview-input.md)
now validates an in-memory subset before calling this adapter. It does not
expose the full internal Input or connect preview to an application runtime.
