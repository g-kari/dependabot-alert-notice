# Explicit fenced checkpoint and business-write operations

The explicit unconnected Store APIs fence their own checkpoint/Begin/Fail/Complete
transactions; they do not create a controller or a live collector. The four public
generic Append/Begin/Fail/Complete entrypoints now refuse an adopted feed source,
including exact replay. StartIngestRun/FinishIngestRun still bypass this boundary.
K292 and new-binary enforcement are NOT complete until those remaining entrances
are closed and verified. Existing constructors, manual 16-record retention, schema,
public HTTP/CLI DTOs and main/config are unchanged.

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

The shared write helpers contain exactly the former transaction work. The four
public wrappers retain their original validation before opening the transaction;
they then perform the conditional legacy guard described below. For genuinely
unadopted sources, the old work, return/context checks, errors, SQL and Commit
control flow are unchanged after those added reads. Guard reads introduce new
failure/cancellation points and adopted/corrupt sources are intentionally refused.
Their replay control flow matters: Begin/Complete/Fail replay returns without Commit and the deferred
Rollback ends the read; Append replay commits its transaction. Reconstructing the
original wrappers and exact extracted helper bodies reproduces both complete
pre-extraction baseline files byte-for-byte. In this guard slice, removing only
the four guard insertions reproduces both complete immediate-baseline production
files byte-for-byte; shared private helpers are unchanged. New fenced business replay is also rollback-only.
There are no nested public Store calls/transactions.

Commit errors return zero Ack. The caller retains the same complete request and
may use only the matching read-only proof. APIs do not automatically retry writes,
reserve again, generate another UUID/intent, repair data, replace deadlines or
perform TTL takeover. The context/deadline supplied by the caller is used directly.
No new WithoutCancel context, timer or cleanup budget is created.

## Conditional legacy guard: four of six operation/receipt entrances

Only the public AppendSecurityEnrichmentCheckpoint, BeginSecurityEnrichmentRefresh,
FailSecurityEnrichmentRefresh and CompleteSecurityEnrichmentRefresh wrappers call
guardLegacyEnrichmentWriteTx. The call is in their existing write transaction,
before replay or mutation. Fenced and reservation APIs continue to use shared
private helpers without that legacy guard. No precheck or cached constructor flag
can authorize a later write: even a Store opened before adoption reads the current
registry in its write transaction. SQLite contention may fail; no retry or progress
guarantee is added.

A positive source generation is adopted even when active operation/intent is NULL;
this is refusal, not proof of release or positive-idle reservation eligibility.
An empty registry is unadopted only without any residual reservation. An intact
zero-generation source also must have no indexed reservation for its connector or
finite BLOB alias, and no journal-linked reservation claiming that source. A
mislabeled reservation connector or finite operation-ID alias cannot hide that
link. Partial/malformed/aliased/oversized registry rows, invalid generations and
residual bindings fail closed, without acknowledgement or repair. The existing
reader returns at most three type/byte-guarded scalar rows. Other lookups return
only EXISTS booleans using existing source and operation-ID indexes; they do not
materialize arbitrary reservation payloads or all journal history. These bounds
are not a total SQLite CPU/latency limit or general hostile-DB protection.

A genuinely unadopted source, including the other feed at idle generation zero,
keeps its generic fresh/replay behavior. Old unbound running attempts or v1 pending
journals are neither adopted nor rewritten into failures. Initial reservation
admission remains independently conservative about such old data. Guard failure
returns no Ack/replay/import result and does not generate UUIDs or clocks. Error
text is fixed; cancellation identity is retained. The new helper rejects nil
private dependencies; existing public nil-receiver/context behavior is not widened.

The inventory distinguished six feed-origin operation/receipt entrypoints from
other writers. ImportSecurityFindings only accepts its existing scanner origins;
Dependabot projection remains dependabot. ImportSecurityEnrichment requires honest
*_offline origin. It may independently change the latest common EPSS/KEV fact by
publication/observation order and retains its own history/last-good behavior. This
is not an exclusive lock on all common-fact writers. UpsertThreat only changes the
separate legacy threat table. Those paths are not feed-operation ownership bypasses
and are not blocked by this slice. Read-only historical inspection/proof is unchanged.

The former unfenced characterization is updated only for adopted-source generic
calls. Explicit fenced replay still succeeds after later Finding changes; genuinely
unadopted generic replay remains read-only. The prior unfenced implementation and
characterization remain in Git history rather than being claimed retroactively
fenced.

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

This slice adds synthetic adopted fresh/replay rejection for all four guarded
public APIs, explicit fenced positive controls, zero acknowledgements/all-table
preservation, corrupt/aliased/overflow/oversized registry and residual-binding
fixtures, cancellation/read/closed-DB errors, indexed lookups, independent Store
connections, and trigger rollback. Offline/latest evidence history and last-good
remain independent while exact historical feed completion proof still matches.
Owned corruption fixtures are not release or actual generation-handoff tests.

The next K292 slice must close StartIngestRun and FinishIngestRun in their write
transactions while characterizing their existing arbitrary-ID/non-feed/missing/
RowsAffected/time/context/Commit behavior. Until then even the current binary has
known bypasses. Mixed older binaries that ignore the registry are not made safe
by these four guards. Erasing all adoption evidence or restoring a pre-adoption DB
cannot be distinguished from never-enrolled state by this guard alone.

Source release/certificate, positive-idle acceptance, stopped-old-writer proof,
controller wiring/privateunknown release, restart restore, terminal eviction/
archive, main/config/API/UI/scheduler/live and mixed-old-binary safety remain
unimplemented. Real feed/socket/HTTP, operational migration, auth/credentials/
persistent access/rights/billing/public changes are excluded. K286 owns the wider
backup/restore, release/mixed-writer operation, retention and runbook acceptance.

