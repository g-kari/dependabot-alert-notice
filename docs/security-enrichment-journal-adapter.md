# Explicit journal-backed manual controller

NewJournalManualController requires Service and JournalRepository explicitly.
It constructs an unexported adapter for exactly one controller lifetime and
passes it to NewPreservingManualController. It does not return an exported,
reusable Sink. Existing constructors, public HTTP/CLI DTOs, main/config, schema
and schedulers are unchanged. No live provider is enabled.

## Lossless conversion before aggregation

convertJournalCheckpoint bounds every source target/selection/entry list and
string before copying or serializing. It compares Completion.Attempt with the
outer Prepared.Attempt and compares every nonnil Result.Pending with Prepared
before removing redundant representations. Nil versus empty slices, pointer
presence/value, clock values, OriginalDigest and signed-zero float bits cannot
be silently discarded. A mismatch is rejected before journal I/O.

The converter then explicitly maps the bounded source to enrichmentjournal v1,
using its existing Encode/Decode for validation, canonical UTC representation
and independently owned pointers/slices. Clock instants are retained; no missing
metadata is filled. Partial/empty selected observations remain legal, missing
evidence does not become zero/negative, and OriginalDigest is not replaced by
the journal payload digest.

## Private sequence and acknowledgement ownership

The adapter retains at most16 operation records, without eviction or reset.
Each record keeps its current full canonical payload, independent AppendRequest,
sequence/digest and acknowledgement/unknown state. It does not retain raw errors,
raw feed bodies or arbitrary per-operation closures. Canonical payload retention
is at most16MiB, plus bounded typed DTOs and transient copies; this is not a total
heap-allocation or global database-capacity guarantee.

Before I/O it reserves one busy slot under a metadata mutex, then releases the
mutex. Reentry/concurrent I/O is refused, not queued. Repository calls receive
fresh independent copies. Expected identity after a call comes from the private
request/payload, never from a mutable argument returned by the dependency.

A fresh reserved callback continues only after Append returns nil error with
the complete expected acknowledgement and Replay=false while context is active.
Replay, wrong acknowledgement, or a lost/failed reserved return stops without
Service query/clock/UUID/fetch. Even a matching durable reservation cannot prove
that this factory created it. There is no automatic reserved readback/adoption.
A second reserved callback is rejected with zero I/O, even when its payload is
identical; legitimate same-ID controller calls replay the controller's own cache.

Only an adapter with a confirmed fresh reserved acknowledgement can advance to
a later stage. It uses the existing branched transition validator, increments
sequence once, and retains the exact new request before Append. A repeated
identical current non-reserved checkpoint uses cached acknowledgement or cached
unknown state; no new sequence, clock, UUID, Append or recovery loop is created.
Stale/changed stages and later checkpoints after unknown are rejected.

For a known-owner later-stage Append error, the adapter makes at most one
read-only acknowledgement check with the exact retained request. Only matched,
complete expected Ack with Replay=true, identical expected current head and an
active context can acknowledge the checkpoint. Missing/conflict/unknown,
corruption, read error, wrong Ack/head and cancellation remain fixed unknown.
There is never an Append retry. Confirming a journal record is not business
success; Service still uses the original atomic enrichment Store contracts.

## Context and read-only Store boundary

Append and acknowledgement read use the same context supplied by the preserving
seam. The adapter creates no WithoutCancel context, timeout, timer or goroutine.
Fail and returned after cleanup has begun consume the remaining existing shared
two-second cleanup deadline. Ordinary returned can use the original context;
deadline-free/noncooperative calls are not claimed to finish within two seconds.

ReadSecurityEnrichmentCheckpointAcknowledgement validates the expected bounded
payload, opens a read-only snapshot and reuses readJournalHeader, readJournalRows
and checkJournalHistory. Only matched returns Ack plus verified current head.
Historical matching exposes the newer head rather than implying it is still
current. Missing/conflict have no Ack/head proof; corrupt/read/cancel outcomes
are unknown. It performs no Append, repair, receipt rewrite or business decision.

The controller's private preservationUnknown flag remains authoritative,
including before Begin with nil Pending. Same-ID pending replay and same-source
gates remain closed under the original constructors and ordinary Reconcile.
Those paths do not clear that flag, restore a controller,
transfer ownership, add DB source fencing, evict terminal operations or coordinate
multiple processes/controllers. A fresh factory does not resume old journals.
The trusted dependency may still panic or fail to return; no forced-stop or
crash/restart durability guarantee is added.

## Synthetic verification limits

Tests use owned SQLite and fake repository/fetch dependencies only. They cover
duplicate-representation rejection, actual later Append commit followed by a
synthetic lost return, exact readonly matching versus wrong proof, fresh reserved
replay/uncertainty, retained argument mutation, reentry/capacity, shared cleanup
context and whole-owned-table equality around acknowledgement reads.

No local Go/SQL/runtime pass is inferred from gofmt/static checks. No real HTTP,
socket/listener, provider data, operational DB migration, new credentials/access,
billing, public exposure, main/config/API/UI or scheduler activation is included.

## Opt-in same-lifetime terminal acknowledgement recovery

NewRecoverableJournalManualController adds only the explicit
ReconcileJournalTerminal method capability. Existing constructors and Reconcile
remain unchanged. The new repository embeds JournalRepository plus the existing
InspectSecurityEnrichmentOperation read-only inspection. No route, scheduler,
automatic loop, restart restoration or runtime wiring is added.

The only eligible candidate is the privately retained returned, nonpending
success or failed checkpoint from this exact controller/adapter lifetime, with a
confirmed fresh reservation acknowledgement. Success requires the full retained
Completion; failure requires the exact ExpectedFailure. Reserved, begin, fail,
complete, returned-pending, no-run, new and foreign controllers remain blocked.
A controller-unknown terminal whose adapter already acknowledged is also eligible:
cancellation can occur between adapter acknowledgement and seam publication.

The method reserves both busy slots with controller-then-adapter lock order and
holds neither lock during the single inspection. The caller's context receives
the existing two-second maximum; cancellation or expiration is checked again at
publication. A valid inspection with nil error must match operation, exact head
sequence/digest and canonical checkpoint bytes. It must independently prove
business success with a nonempty receipt, or exact failure with an empty receipt.
Missing/newer heads, corruption, errors and mismatches leave the original pending
result and evidence untouched. A later explicit read may try again.

On proof, both private unknown gates clear together and the original privately
retained terminal Result is published. Checkpoint/payload/prepared evidence stays
retained and all outward snapshots remain independent. Cached replay needs no
inspection. There is no Append, business retry, UUID/clock generation, fetch,
replacement failure record, eviction or additional retained slot.

This releases only the in-process pending-source gate. It neither calls nor
integrates the separate durable generation-fenced Store admission/release APIs.
The controller still uses generic business/journal APIs, not generation-fenced
execution; the 16-record cap and Store source H4 limit are unchanged. No guarantee
of cross-controller/process exclusion or restart ownership is added.
