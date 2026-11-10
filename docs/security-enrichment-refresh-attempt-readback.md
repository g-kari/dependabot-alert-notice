# Attempt-only enrichment refresh readback

This unconnected B2a store reader handles a reservation before a validated feed
or full completion is available. It adds no RefreshOnce, fetch interface, HTTP
adapter, scheduler, main/config change, credential, dependency or migration.

ReadSecurityEnrichmentRefreshAttempt takes the original caller-generated UUID,
source/scope/start/target manifest and an optional expected failure code/finish.
It does not accept or fabricate source publication/version/observation metadata.

- missing requires absence of both the exact UUID row and any manifest or
  observation referring to it. It does not authorize a replacement UUID.
- running requires exact equality with the original reservation, including its
  target-manifest cursor, and no enrichment manifest/observations.
- failed requires a structurally valid, exactly bound failed reservation, no
  enrichment manifest/observations, and the explicitly expected closed code and
  finish instant. No expected failure means unknown. A different expected code
  or even a one-nanosecond finish difference is a conflict. Equivalent timezone
  representations of the same instant are normalized to UTC.
- success is never returned. A completed row remains unknown without its full
  completion, even when a caller supplied an expected failure. Use the existing
  full-completion Reconcile method to prove the successful receipt and evidence.
- corrupt/oversize run rows, evidence attached to missing/running/failed runs,
  and identity collisions return unknown with an error. Database/cancellation
  errors also remain unknown. Completed evidence is not validated here. Receipt is
  always empty, including for unknown completed rows.

The request is validated before database access. Reads use one read-only SQL
snapshot under the store read lock. A first exact-ID query checks SQLite storage
types and byte bounds before the existing scalar reader can load its fields:
UUID must be TEXT with 36 bytes;
connector 64, scope 256, timestamps 40 each, result/coverage 16 each, cursor 128,
error 64 and body 4096 bytes. The owned receipt body must match its canonical
stored encoding, without unknown/duplicate fields or silently repaired content.
No raw source error, receipt cursor, manifest or evidence payload is returned.

Missing/running/failed checks use the existing single-row manifest count and
observation count capped at 201. Separate indexed exact-byte BLOB lookups reject
corrupt UUID storage aliases, shadow rows and BLOB-typed orphan references rather
than treating them as an unused text UUID. This reader does not decode observation/feed
bodies, consult current mutable finding rows, fetch data or change a failed run.
The target manifest confirms the historical reservation only; first completion
still separately validates current targets through the existing B1 API.

The caller must keep the same UUID and manifest while an outcome is unknown.
This reader performs no retry, failure write, cursor advancement or new-UUID
allocation. A canceled read can be repeated with a fresh context and the same
attempt. Success still requires the retained full completion and its existing
bounded reconciliation, never a fake feed assembled to satisfy that method.

Synthetic tests compare every database table's SHA256 before/after available
reads, including error cases. They cover last-good evidence, query-only SQLite,
exact failure clocks/codes, UUID/source/scope/start/target collisions, corrupted
and oversized receipts, missing/running/failed evidence orphans, cancellation,
read errors, closed databases and same-UUID recovery. The original Red contract
tests remain byte-identical. Formal Go compile/test/race/vet/build must run in CI;
local gofmt/SQL smoke checks are not Go test passes or live integration proof.
