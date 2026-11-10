# Experimental operation reservation storage

ReserveSecurityEnrichmentOperation stores a caller-prepared reservation intent,
source generation and journal reserved checkpoint atomically. The feature remains
unconnected. The initial reservation-storage checkpoint left generic APIs unfenced;
subsequent explicit fenced APIs now validate their own write transactions, and the
four public generic Append/Begin/Fail/Complete APIs refuse adopted sources (positive
generation, including active NULL) while preserving genuinely unadopted behavior.
StartIngestRun/FinishIngestRun remain unguarded pending K292's next slice. See
[the current fenced-write and legacy-guard contract](security-enrichment-fenced-write.md).
This is not complete enforcement, controller restore, fresh fetch ownership,
continuous scheduling or live startup. Independent offline common-fact updates
remain non-exclusive; the separate legacy threat path is unchanged.

## Exact retained intent, not an authentication credential

Before calling Reserve the caller retains one complete request: a canonical
non-authentication IntentID, OperationID/request/source, expected idle generation,
full sequence-one reserved AppendRequest with empty previous digest, and the
canonical reserved payload SHA256. No business UUID or clock generator is needed.
IntentID is a correlation value, not a secret, credential, authorization token or
permission to execute. Neither a fresh acknowledgement nor matching an old DB
record restores restart/different-caller ownership.

The request is validated before SQL and before full leaf marshaling. Reserved
checkpoint shape remains closed journal v1; targets/preparation/business UUID are
absent. The exact canonical payload is retained independently. Storage binds every
request value, expected and next generation, intent and reserved digest. Journal
SHA256, OriginalDigest and business receipt remain different identifiers.

## Atomic source reservation and conservative admission

005 adds immutable security_enrichment_reservations and current
security_enrichment_source_generations. It adds one connector/operation index;
the existing ingest_runs_scope_lookup connector prefix is reused for feed receipt
existence checks. No old journal/ingest/enrichment column, receipt or cursor changes.
Migration creates tables/index only. It does not enroll sources, create a run,
adopt existing attempts or mark them failed.

On the first successful reservation, one transaction checks admission, creates
both initially idle source rows, inserts journal reserved header/checkpoint and
the immutable intent, and CAS-updates the selected idle source generation to +1.
Both source rows and all reservation/journal changes roll back together.
The nullable active operation/intent references do not require an ingest_runs
row, because no business run exists before Begin.

Initial enrollment refuses any pre-existing journal/receipt from the two feed
origins, including finite BLOB aliases, regardless of terminal result. Existing
offline/legacy evidence is preserved. Old unbound running or v1-pending records
get no synthesized intent, metadata, failed state or adoption. Once enrolled,
unbound journal/feed activity for the requested source still blocks new requests.

A source's active binding refuses another operation. Expected generation is a
bounded int64 and +1 never wraps. This slice has no release API: positive idle
generations are not accepted as proof that an earlier writer stopped. The public
path creates idle0 -> active only. A future generation-handoff/release protocol
needs its own terminal proof and transaction rules.

Exact same-request replay returns the stored acknowledgement with Replay true,
without advancing generation or appending another checkpoint. Changed intent,
operation, request, source, expected generation, sequence, previous head or payload
is refused. A replay is storage proof only. Commit/context errors return zero Ack;
no automatic Reserve/Append retry, new intent, business UUID or correction clock
is generated.

## Read-only exact proof

ReadSecurityEnrichmentReservation uses one read-only snapshot and the complete
retained request. Only matched returns Ack and a verified still-reserved current
head. Missing/conflict return no Ack/head; corruption/storage/cancel errors return
unknown with sanitized errors. Advancing the journal past reserved makes
this specific proof conflict rather than manufacturing a new execution grant.
The reader never initializes missing storage, repairs, reserves, releases or
adopts another caller's intent.

Scalar SQL storage types/byte lengths are checked before Scan. The two-source
registry is read with LIMIT3 to detect extra/corrupt rows. Exact operation/intent
selectors and finite TEXT/BLOB aliases return at most three binding rows; only
two canonical selectors can legitimately match. Payloads are capped at1MiB before
Decode and must be exact canonical journal v1 reserved bytes/digest. Current source
bindings use indexed latest-generation lookup and the existing bounded journal
history proof, at most five checkpoints each. Existence/orphan checks return only
booleans, not all history bodies. These bound materialized data, not all SQLite
page/index work or global DB size. No general DB integrity or old-writer stop
certificate is claimed.

The two generic journal INSERT blocks are shared through private transaction
helpers. Historically, inlining that extraction reproduced the original method's
SQL, validation, context/error branches and both Commit locations. The later guard
adds same-write-Tx reads before the public generic work/replay; removing those guard
insertions reproduces the immediate pre-guard production source exactly. No nested public
Append or transaction is called inside the reservation transaction.

## Synthetic verification and remaining work

Tests use owned SQLite only: binding/replay, independent Store/connection
contention with at most one atomic binding, trigger rollback, actual successful
Store commit followed by a synthetic lost return, exact readonly proof, old
history refusal, all-table equality around rejected/read paths, maximum escaped
reserved cursor, type/alias/oversize/orphan/overflow/cancel/read errors and upgrade.
The lost-return wrapper is not injection into an actual driver Commit outcome.
Contention does not promise progress after locks/commit errors.

Upgrade tests reconstruct the pre-005 schema with nonempty legacy threat,
Finding/receipt and journal data, reopen with current code and compare every old
table row. This is not an old binary invocation, operational migration, backup or
restore drill. Store startup's existing migration framework runs this additive
DDL when the new code is deployed; no operational database was opened/applied here.
Old-binary/new-DB and concurrent mixed-binary safety remain unverified.

Explicit fenced CP/business write-Tx checks and the adopted-source guard for four
generic APIs have been added in follow-up slices; StartIngestRun/FinishIngestRun
still require their separate old-API guard. Terminal proof/release CAS, positive-idle
admission, reserved ownership recovery in a controller, privateunknown/source-gate
release, restart restoration and terminal retention/archive remain later work. K286 owns wider stopped-writer,
backup/restore, mixed-release operation, retention and runbook acceptance.
No main/config/API/UI/scheduler/live, HTTP/socket/feed, authentication/credential/
persistent-access/rights/billing/public changes are included. Local static/gofmt
checks are not Go/SQL/runtime passes.

