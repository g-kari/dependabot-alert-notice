# Explicit fenced checkpoint and business-write operations

The explicit unconnected Store APIs fence their own checkpoint/Begin/Fail/Complete
transactions; they do not create a controller or a live collector. The four public
generic Append/Begin/Fail/Complete entrypoints now refuse an adopted feed source,
including exact replay. StartIngestRun/FinishIngestRun now also guard adopted feed
origins in their write transactions. These six operation/receipt entrances are
covered in the current binary; this is not exclusive fencing of all fact writers,
execution ownership, or proof that an older binary stopped. Existing constructors, manual 16-record retention, schema,
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

## Conditional legacy guard: initial four operation/receipt entrances

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

## Generic ingest Start/Finish: remaining two entrances

StartIngestRun preserves its existing source/scope/time input validation. Only the
exact connector values epss_feed and kev_feed take the new private branch: begin
writeTx, existing adopted-source guard, context check, UUID generation, at.UTC,
INSERT and Commit. Adopted refusal exposes no run and reaches no UUID factory.
There is no new clock generator. A missing/invalid/corrupt adoption state does not
become a fetch or restart grant. Arbitrary other nonempty labels are not trimmed
or lowercased into a feed value, and keep their entire former Start path.

For unadopted feed Start, Begin failure now precedes UUID generation and returns a
zero run. This differs deliberately from the old UUID-before-Begin error result.
Once generation succeeds, INSERT/Commit errors retain the old ID-bearing run plus
error; a commit error is uncertain, not proof of rollback or a reason to call Start
again with a new UUID. Nonfeed Start retains its UUID-before-Begin order/error
result. Gofmt/static reconstruction removes only the feed dispatch branch and the
explicit Finish additions to reproduce the whole prior security.go source.

FinishIngestRun retains its result/coverage/time and machine-code validation order,
then uses one writeTx for metadata classification, feed guard, body SELECT, old
model decode/time comparison/update, UPDATE and Commit. All paths, including
nonfeed, now have additional Begin/Commit errors and different cross-connection
contention boundaries. This is an intentional change, not a byte-identical overall
control flow. No precheck outside the transaction authorizes the update.

The metadata query selects indexed exact ID plus its finite BLOB alias (LIMIT3),
and emits only four small flags per candidate. It returns no raw identifier,
connector or body strings to Go. TEXT/BLOB aliases, unknown types, inconsistent
row/body identity and ambiguous recognized attributes fail closed. json_each
preserves duplicate/escaped keys; attribute-name folding accounts for Go JSON's
ASCII case matching and long-s/Kelvin folds. Each of the nine IngestRun attributes
must appear exactly once, with a scalar value consistent with the stored running
row. Unknown extra attributes remain allowed. Attribute VALUE strings are never
folded/trimmed into another origin. A healthy nonfeed label, or a truly unadopted
feed, keeps its original arbitrary ID, large scope/body, empty generic cursor and
valid legacy calendar range. The refresh-specific UUID/manifest/4KiB decoder is
not reused for this generic ledger.

Only rejected-candidate Go metadata materialization is small. SQL JSON parsing,
index/page work and the later healthy-body Go allocation are not globally
byte/heap/time capped. Malformed legacy rows can now be rejected earlier; no
repair, metadata default or synthesized failure is written. Canonical absent or
non-running IDs preserve wrapped sql.ErrNoRows. Corrupt finite aliases are not
silently classified as missing. The old UPDATE predicate id plus running, supplied
UTC finish time and deliberately unchecked RowsAffected remain unchanged; a
trigger returning zero affected rows still gives the historical nil result.

There is no new public exact-proof API for generic Start/Finish. Unknown callers
must stop; they must not invent a target manifest/Completion for ReadAttempt or
reconcile by generating another UUID/clock. Synthetic tests inspect owned SQLite
after a successful real Store call followed by an outer lost-return error for
Start and Finish. That is not an actual driver ambiguous-Commit injection, restart
adoption, or execution ownership. Reserve-versus-Start contention permits at most
one stored path, can make no progress, and never retries automatically.

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

The Start/Finish follow-up adds owned synthetic controls for arbitrary IDs, large
healthy nonfeed and unadopted-feed bodies, literal connector labels, attribute
aliases, validation order, zero affected rows, missing IDs, cancellation/read/closed
DB errors, indexed flags, rollback and independent connections. No operational
DB or live collector is exercised. K292 integration acceptance still requires the
candidate's own formal CI, independent review, merge and post-merge verification.
Mixed older binaries that ignore the registry are not made safe by these six
guards. Erasing all adoption evidence or restoring a pre-adoption DB
cannot be distinguished from never-enrolled state by this guard alone.

Source release/certificate, positive-idle acceptance, stopped-old-writer proof,
controller wiring/privateunknown release, restart restore, terminal eviction/
archive, main/config/API/UI/scheduler/live and mixed-old-binary safety remain
unimplemented. Real feed/socket/HTTP, operational migration, auth/credentials/
persistent access/rights/billing/public changes are excluded. K286 owns the wider
backup/restore, release/mixed-writer operation, retention and runbook acceptance.

