# Pure release candidates and certificate data (K293 stage 1)

This package is an unwired leaf: internal/enrichmentrelease imports only the
standard library and the existing enrichmentjournal package. No Store, migration,
source registry, controller, HTTP/CLI DTO, main/config or scheduler is changed.
It cannot release a source, permit Reserve, restore ownership or enable a feed.

## Retained request and terminal eligibility

ReleaseRequest contains the exact retained reservation (intent, expected
generation, reserved AppendRequest/digest) and complete terminal
AppendRequest/digest. It adds no separate Attempt/Completion input. Intent and
operation IDs are correlation values, not authentication/execution credentials.

InspectTerminal checks field/collection bounds before canonical journal
marshaling, validates the existing journal version/shape/digests and exact
operation/request binding, and returns an independently owned candidate:

- Prepared success/failed: nonpending returned, sequence 4 or 5.
- No prepared run: nonpending returned at sequence 2, previous digest exactly
  the retained reserved digest, empty run ID. Existing legal outcomes are
  no_targets, exhausted, invalid, error and canceled.
- Begin, Complete, pending, mismatched binding/digests and impossible branch
  sequences are not eligible.

A sequence-five candidate is not proof that the missing stored intermediates
exist. Test fixtures validate write -> returned-pending -> terminal using the
existing journal transition code; the public request still supplies only root
and terminal. Neither inspection nor its expected proof class is SQL historical
business proof, a release acknowledgement, a current fence/owner or liveness.

The existing journal encoder defines canonical UTC payload bytes for hashing.
The returned request copy preserves the original time values/offsets, exact
instants, nil versus nonnil empty partial entries, known-zero pointers, and
nested target/feed/date pointer values. It fills no missing clock, score,
negative KEV observation, run UUID or metadata. As with ordinary Go inputs, the
caller must synchronize concurrent mutation during a call. Independent owned
copies protect later caller/returned-value mutations.

## Independent closed certificate syntax

CertificateVersion is independently 1; journal checkpoint Version remains 1.
MaxCertificateBytes is 4 KiB for certificate JSON, not the existing 1 MiB
checkpoint cap, a raw-feed cap, or a total heap/CPU budget.

The exact twelve keys are required: version, operation_id, intent_id, connector,
generation, reserved_digest, terminal_sequence, terminal_previous_digest,
terminal_digest, kind, run_id and receipt. Unknown/case-alias/escaped-duplicate
keys, missing keys, wrong scalar/null types, trailing input, invalid UTF-8/lone
surrogates and oversize data are rejected.

- kind success/failed requires a valid run UUID and sequence 4 or 5.
- kind no_run requires sequence 2, previous digest equal to reserved digest,
  required explicit run_id:null, and receipt as a required empty string.
- Success receipt is only refresh-success-v1:sha256: plus 64 lowercase hex
  digits, matching security_enrichment_refresh.go's SHA256/hex.EncodeToString
  construction. Failed/no_run receipts must be empty.
- Generation is positive; maximum int64 certificate data is representable.
  The retained reservation's expected generation must still leave room for +1.

Shape validation precedes marshaling. Decode is bounded, exact-key and typed,
and owns decoded pointer values. A syntactically valid Certificate can be
assembled as ordinary data; encoding/decoding it does not attest that a Store
verified or persisted it. The future issuer must bind it to the full retained
request and exact historical business proof inside its release transaction.
Certificate data, canonical journal SHA, OriginalDigest and business receipt
remain different things.

## Verification and later gates

Pure synthetic tests cover legal terminal branches, partial/nil/empty evidence,
sequence-five resolution, strict certificate syntax/receipt rules, independent
nested copies, clock representation, invalid/oversized shapes, the existing
200-target maximum escaped checkpoint, and separate certificate byte bounds.
No SQL, socket, live feed or runtime integration is exercised by this package.
Static/gofmt is not a Go compile/test/race result; formal exact-head CI is required.

Stage 2 remains unimplemented: additive immutable certificate storage, historical
business proof plus atomic active-source CAS, same-request read-only proof,
certificate-aware idle validation, and an explicit Reserve positive-idle stop.
The shared two-source checker and the Reserve stop must change together so that
a release neither blocks the other source nor implicitly admits no-run next work.
Old reservation-reader stale/conflict classification and cert-only residual
adoption guards also belong there.

Stage 3 remains unimplemented: explicit positive-idle/next-generation admission
with an independent finite per-source H, H+1 pre-payload overflow detection,
generation continuity and sequential full proof of every closed generation.
Certificate attestation alone must not replace validation of old mutable
observations. H is not the controller's 16-record capacity; no reset, eviction or
archive is inferred on overflow.

Controller/privateunknown/restore/capacity handling is K294 work. Operational
database application, stopped/mixed-old-binary safety, backup/restore drills,
retention and runbooks remain K286 concerns. No real HTTP/feed/authentication,
credentials/persistent access, permissions, billing, public exposure, user PC
or live activation is included.
