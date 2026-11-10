# Read-only enrichment operation inspection

InspectSecurityEnrichmentOperation accepts a canonical OperationID and reads one
operation in a single read-only SQL snapshot. This is candidate inspection, not
run-ready controller restoration, fresh reserved ownership, source fencing or
permission to repeat a fetch/write. Existing constructors, the 16-record manual
non-evicting policy, public DTOs, schema and old read APIs remain unchanged.

## Two independent classifications

State valid means the complete bounded journal history, canonical payloads,
digests, immutable binding and head agree. Only then are OperationID/head and an
independently allocated checkpoint candidate returned. A returned pending v1
checkpoint is readable without treating it as an executable restored operation.
A valid missing operation returns State missing and no checkpoint/head. Unknown,
corrupt/type-alias/oversize/orphan history returns no candidate or head.

Business is separate from journal State and Progress.Outcome. With a full retained
Completion, success requires the existing exact same-UUID receipt, manifest,
OriginalDigest and every observation proof. With an ExpectedFailure, failed
requires the exact fixed code, finish instant and attempt binding, with no stray
manifest/observations. Journal acknowledgement, returned-success and a success
receipt row without the full Completion cannot establish business success.

Begin-only, running, missing, absent expected-failure proof and unknown/conflicting
business rows stay unresolved. A valid journal can be returned alongside Business
unknown and a sanitized proof error. No journal acknowledgement or error text is
substituted for a business receipt. Unprepared describes a reserved checkpoint
without a business UUID. No_run describes a returned pre-Begin result without a
business UUID/receipt, including rejection/cancellation; it does not mean a
successful enrichment. Zero UUIDs and missing metadata are never filled in.

## Snapshot, bounds and history

The inspection shares the existing bounded attempt-proof transaction helper and
exact completion-proof helpers inside its one read-only transaction. It never
calls the public Reconcile/ReadAttempt APIs from inside a transaction. The old
ReadAttempt public validation, transaction and error/context flow are unchanged;
Reconcile is unchanged. Journal materialization remains at most five checkpoints,
one MiB each, with at most 200 targets/entries per checkpoint. SQL storage-type/
byte guards and finite indexed TEXT/BLOB UUID alias checks precede proof reads.
Observation identity counts stop at201 and at most200 exact observations are
checked. These are materialization bounds, not bounds on all SQLite page work.

The leaf-to-Store conversion explicitly copies targets, selected CVEs, probability/
date pointers and prepared values. It preserves nil/empty/known-zero evidence,
clock instants and OriginalDigest; existing Store receipt normalization remains
the receipt contract. No current Finding revision is revalidated as part of
historical proof. Later Finding/common fact changes neither rewrite the original
receipt nor turn historical inspection into a current-evidence/liveness claim.
Caller mutation of returned candidates cannot change later reads or DB contents.

Canceled/expired inspections and failed read-only transaction completion expose no
candidate or proof. The implementation creates no UUID, clock, metadata, ingest
run or observation, and performs no repair/write, controller injection, private
unknown/source-gate release, fetch retry or ownership transfer.

## Verification and remaining gates

Synthetic owned SQLite tests cover historical EPSS/KEV proofs after distinct
current updates, journal/business disagreement, exact failure and finish mismatch,
partial empty evidence, independent copies, corruption/oversize/type aliases,
orphans, cancel/read-error/closed DB and before/after hashes of every owned table.
No real HTTP/socket/feed, operational DB migration/restore, live startup,
credentials/access/billing, controller restore, reserved-intent proof, source
fence or terminal eviction/archive is included. K286's wider backup/restore drill,
stopped-writer checks, release compatibility, retention and runbook remain
separate. Static/gofmt checks do not constitute Go/runtime test success.

