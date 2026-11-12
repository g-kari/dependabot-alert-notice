# Internal enrichment operation journal v1

This slice adds a closed codec and SQLite journal Store, not a live collector.
It does not connect PreservationSink, restore a controller, recover an uncertain
acknowledgement, fence multiple sources/processes, evict retained records, archive
history, or wire main/config/API/UI/scheduler. Existing constructors, the manual
16-record non-evicting policy, closed public DTOs and legacy collectors are unchanged.

## Format and evidence boundaries

internal/enrichmentjournal imports only the standard library. Store imports that
leaf; the leaf never imports Store or enrichmentrefresh. The durable DTO has
explicit JSON names, required fields, and explicit null for optional values.
Progress.Pending refers to Prepared rather than serializing another envelope.
Completion shares Prepared.Attempt rather than serializing another target list.
A future adapter must verify that duplicated source Attempt/Result.Pending values
agree before aggregation. It must reject inconsistent originals, not silently
normalize or discard them. That adapter is not implemented here.

Encode checks bounded shape before full JSON marshaling. Decode checks the total
byte cap and raw UTF-8/surrogate encoding before typed allocation, requires exact
case-sensitive field names, rejects unknown/duplicate/escaped-duplicate keys,
missing fields, wrong types and trailing data, and bounds arrays before item201.
The cap is 1MiB per checkpoint. Targets, selected CVEs and entries are at most200;
Finding IDs/cursors at most128 UTF-8 bytes, canonical CVEs at most28 ASCII bytes,
source versions at most64 allowed ASCII bytes. The maximum escaped200-target/
entry fixture is a synthetic codec test, not real-provider format validation.

Canonical JSON expresses clocks in UTC without changing their instants, filling
missing values or modifying caller-owned pointers. OriginalDigest is retained
unchanged. Empty or partial Feed.Entries is legal; nil and nonnil empty entries
remain distinguishable as null and []. Selected CVEs remain the exact canonical
selection. Missing selected entries create no false/zero observations. Known-zero
EPSS/percentile pointers remain known zero; a missing required EPSS percentile is
rejected rather than supplied as zero. KEV remains positive-only, and a legal
non-midnight dateAdded instant is not narrowed to a new date-only rule.

The journal payload SHA256, decoded-input OriginalDigest and existing enrichment
run receipt are different identifiers. Journal acknowledgement establishes only
checkpoint storage, not a verified enrichment commit, authenticity or liveness.
No raw input document, provider error body, credentials or secret is a DTO field.

## Stages and immutable binding

OperationID binds the exact connector/after/limit. A reservation has no run UUID;
a subsequent Begin fixes one UUID, source/scope/start and checked target manifest.
All later checkpoints retain that attempt and the original scan/last-scan cursor.
Failure and full Completion are mutually exclusive prepared writes.

Allowed distinct-stage paths are reserved -> begin -> fail|complete -> returned,
and reserved -> returned for no-target/exhausted or pre-Begin rejection/cancel.
A pre-Begin clock/UUID rejection may have scanned targets without a prepared
attempt or valid run UUID; it grants no fetch ownership. Returned pending may
advance once to the corresponding terminal returned result with unchanged full
preparation. Terminal state cannot rewind or acquire another write. The longest
v1 path has five distinct checkpoints. Repetition uses the original sequence
and payload, not another stage or sequence.

## Additive storage and transaction

004_security_enrichment_journal.sql adds security_enrichment_operations and
security_enrichment_checkpoints, plus app_migrations version4. It changes no
existing ingest/enrichment column or receipt/cursor. A prepared run UUID has no
mandatory ingest_runs FK, because checkpoint preservation precedes Begin.
The nullable UUID becomes fixed once, with a unique journal binding.

AppendSecurityEnrichmentCheckpoint validates/encodes before opening the SQL
transaction. It reads one operation's head and at most six checkpoint rows to
detect overflow beyond the five-stage protocol. Scalar storage types and byte
lengths are guarded in SQL before values reach Scan; payloads are independently
capped before Decode. It verifies the complete per-operation chain, canonical
payload bytes, digests, column/JSON binding and head consistency. Indexed exact
TEXT/BLOB aliases of operation/run UUIDs are rejected without repair or global
table scans. This bounds returned materialization, not all SQLite page work.

A new checkpoint insert and exact sequence/head-digest CAS update occur in the
same transaction. Existing operation/request/source and UUID cannot be changed.
Historical same-sequence retries require the same previous digest and complete
canonical payload; they return the original journal acknowledgement without
rewinding the current head. Any other sequence/payload, invalid state transition,
or corrupt/orphan record is refused. The API never updates/deletes checkpoint
rows, creates an ingest run, writes common observations, or grants fetch rights.

Commit failure returns no acknowledgement and triggers no automatic retry or
readback. The caller must keep the exact AppendRequest. Ack recovery and its
bounded shared-context adapter are the next slice. SQL/trigger errors are
classified without exposing their underlying text; cancellation stays explicit.
The existing old receipt/running rows are not adopted into journal ownership.
Source fences and handling of old unbound attempts remain a separate gate before
continuous/restarted use.

## Migration and verification limits

Store.NewWithPath already runs the migration framework during initialization.
The new additive DDL joins migrateSecurity's transaction after migration003.
Synthetic upgrade tests reconstruct the pre-journal schema in an owned database
by removing only the new tables/marker, retain non-empty legacy Finding/receipt/
threat data, reopen with the new code, and compare every old table's rows and
existing migration records. The only excluded addition is migration record4.
This is not an old binary invocation or an operational database restore drill.

The inspected migration framework has no general newer-version refusal. Old
binary/new-database compatibility and concurrent mixed binaries are not promised.
No real operational database has been migrated or restored by this work. Applying
a release/migration to an operational DB needs its own backup, environment and
authorization checks; K286 owns the wider backup/restore, release compatibility,
retention/archive, metrics/SLO and runbook work.

Tests use synthetic owned SQLite only: exact persistent/historical replay,
branched transitions and legal partial evidence, maximum escaped payload,
CAS conflicts, UUID binding, trigger rollback, corruption/type aliases and
cancellation. Gofmt/static checks are not Go/runtime/upgrade test passes.
No real HTTP/socket/feed, live startup, credential/access/billing or operational
migration is part of this slice.
