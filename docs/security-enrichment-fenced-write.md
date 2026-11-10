# Explicit fenced checkpoint and business-write operations

This slice adds unconnected Store APIs, not a new controller or a live collector.
They fence their own checkpoint/Begin/Fail/Complete transactions. Existing generic
Append, business APIs and StartIngestRun/FinishIngestRun still bypass this new
boundary. New-binary enforcement is NOT complete. Existing constructors, manual
16-record retention, schema, public HTTP/CLI DTOs and main/config are unchanged.

## One retained request and two proof meanings

SecurityEnrichmentFencedRequest contains the complete retained reservation, full
post-reserved checkpoint AppendRequest and canonical CP digest. No independent
Attempt/Completion is accepted. Intent is a non-authentication correlation value,
not a secret or an execution/restoration credential.

Shape is checked before leaf marshaling/SQL. Both reserved and current payloads
are independently decoded into owned values before I/O. CP OperationID/version/
connector/after/limit must match the reserved request. The original reserved
payload/digest, intent, expected and current generation, active source operation
and complete journal chain are checked in the operation's transaction. This
private helper works with advanced heads; it never calls the public reservation
reader, whose proof intentionally remains still-reserved-only, inside another Tx.

AppendSecurityEnrichmentFencedCheckpoint accepts only an exact current replay or
a legal next CP. Older historical phases, sequence gaps, wrong previous head,
different preparation, source or generation are refused. Acknowledgement binds
operation/intent/source/generation/sequence/digest. It is CP storage evidence only.

ApplySecurityEnrichmentFencedRefresh derives Begin/Fail/Complete solely from the
owned CP preparation. It requires that exact CP to be the current stored head.
Fence checking, the shared existing business write and post-write exact proof
share one SQL transaction. Begin/Fail/Complete clocks, metadata and target rules
remain those of the existing Store. No clock, business UUID, source publication,
missing score or negative KEV observation is invented.

ReadSecurityEnrichmentFencedCheckpoint is read-only CP/fence proof. Its matched
result deliberately leaves Business unknown, even if the CP says success.
ReadSecurityEnrichmentFencedRefresh separately requires the exact phase's business
proof: running for a retained attempt, exact failed code/finish for Failure, or
full receipt/manifest/every observation for Completion. A stored Complete CP with
a running/missing run does not return a business acknowledgement or head. Failed
without the expected Failure and success without the full Completion stay unknown.

Both read APIs use a single read-only snapshot. Mismatches/missing have no Ack/head.
Unresolved business evidence may describe running/missing but has no Ack/head.
Errors/cancellation expose unknown and no acknowledgement, head or receipt.
A matched read is not fresh fetch ownership, auth, liveness or restart adoption.

## Atomic work, bounds and old API compatibility

Fresh Begin/Complete retain current Finding identity/revision validation. Historical
read/replay proof does not revalidate later Finding revisions or current common
facts: its evidence is the original same-UUID receipt/manifest/observations.
OriginalDigest and independent start/publication/observation/finish clocks remain
distinct. Domain Source remains epss/kev, not connector origin in a public wire
schema. Nil/empty partial evidence and known-zero pointers are retained in CPs;
existing business-receipt normalization remains unchanged.

Before calling shared business work, existing strict attempt body and evidence
checks protect stored scalar/body materialization. Current fence/head and exact
business evidence are verified again after the work, before acknowledgement.
In-Tx corruption/trigger failures roll back all new CP/business/source mutations.
This is not a general defense against arbitrary hostile database modification.

Existing journal/registry/binding SQL storage-type/byte/finite-alias guards are
reused: source registry LIMIT3, operation/intent binding selectors LIMIT3,
checkpoint payload cap1MiB and at most five per-operation CPs, target/selection/
entry cap200, and bounded receipt/manifest/observation reads. No new dependency or
index/schema is added. Bounds describe materialization, not all SQLite work,
total heap or a measured concurrency/latency budget.

The shared write helpers contain exactly the former transaction work. Original
public validation and context/error behavior are preserved. Their replay control
flow matters: Begin/Complete/Fail replay returns without Commit and the deferred
Rollback ends the read; Append replay commits its transaction. Reconstructing the
original wrappers and exact extracted helper bodies reproduces both complete
baseline files byte-for-byte. New fenced business replay is also rollback-only.
There are no nested public Store calls/transactions.

Commit errors return zero Ack. The caller retains the same complete request and
may use only the matching read-only proof. APIs do not automatically retry writes,
reserve again, generate another UUID/intent, repair data, replace deadlines or
perform TTL takeover. The context/deadline supplied by the caller is used directly.
No new WithoutCancel context, timer or cleanup budget is created.

## Verification scope and remaining gates

Synthetic owned SQLite tests cover both feed domains, exact Begin/Complete/Fail,
current replay, phase/identity/digest mismatch, independent connections, triggers
and rollback, full table equality around reads/refusals, exact failure code/finish,
before-Scan corrupt scalar/BLOB/oversize/alias/orphan cases, cancellation, nil/closed
DB/read errors, independent prepared copies, partial/known-zero evidence and
historical proof after newer facts. A source-generation change injected by a
fixture trigger is an in-Tx fault test, not a real release/generation handoff.

Lost-return tests perform a real successful Store commit then synthesize an outer
error. They are not an actual SQLite-driver ambiguous-Commit injection. Separate
connection contention permits at most one fresh write and does not promise
progress after locks/commit errors. Gofmt/static is not a Go/SQL/runtime pass.

The next legacy-guard slice must inventory all feed-origin write entrances,
including generic import/receipt/upsert paths, not assume the known Start/Finish
bypasses are the only ones. Offline enrichment already uses *_offline origins;
legacy threat snapshot upserts are a separate data path. This slice does not
close any old bypass or revise the prior unfenced characterization.

Source release/certificate, positive-idle acceptance, stopped-old-writer proof,
controller wiring/privateunknown release, restart restore, terminal eviction/
archive, main/config/API/UI/scheduler/live and mixed-old-binary safety remain
unimplemented. Real feed/socket/HTTP, operational migration, auth/credentials/
persistent access/rights/billing/public changes are excluded. K286 owns the wider
backup/restore, release/mixed-writer operation, retention and runbook acceptance.

