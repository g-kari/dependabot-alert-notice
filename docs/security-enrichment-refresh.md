# Unconnected common Finding enrichment store bridge

This Phase B1 slice adds store-only contracts for synthetic or already validated
EPSS/KEV enrichment. It does not fetch feeds, implement RefreshOnce, start a
scheduler, change main/config, configure credentials or enable a live collector.
The existing legacy fetchers and offline import command remain available and
unchanged. No migration or dependency is added.

## Target selection

QuerySecurityEnrichmentRefreshTargets uses a binary finding-ID keyset with a
caller-supplied limit of 1–200 scanned rows. Scanned includes ineligible rows;
After is the last scanned row, not the last accepted target. Continue while a
full scan page was returned, even if Targets is empty. An exhausted page has
Scanned=0, After empty and a non-null empty Targets slice.

Only vulnerability rows with matching row/body ID, category, asset binding and
canonical key are eligible. The vulnerability ID must already be a canonical
CVE accepted unchanged by the existing strict selection validator. Lowercase,
whitespace, GHSA, titles and arbitrary substrings never become CVEs. Invalid or
oversized finding bodies are ineligible; materialized bodies are capped at
64 KiB. Each target includes an opaque SHA256 revision over the row identities
and exact stored body. A target is a snapshot binding, not an authorization.

Begin and first completion validate these exact current target bindings inside
their transaction. A changed/missing row, invalid target, duplicate finding ID or
selection mismatch aborts without partial writes. Multiple distinct findings
may share a CVE; the source selection is their sorted unique CVE set. A page is
not a configured inventory, complete scan or coverage denominator.

## Same-UUID lifecycle

The caller generates and retains one UUID before Begin. The attempt explicitly
contains epss_feed or kev_feed, its CVE-selection scope, start clock and 1–200
target bindings. Begin persists running/unknown with a versioned target-manifest
receipt in the existing ingest_runs cursor. An identical running Begin retry
only reads the existing binding. It does not create another UUID or overwrite a
run. Reusing an ID with a different source, scope, start or target manifest is a
conflict. A completed ID is not restarted.

Complete takes the same attempt plus a validated SecurityEnrichmentFeed, an
explicit SHA256 original-input digest and an explicit finish clock. Source
publication and observation clocks stay independent: publication must not be
after observation, observation must not precede attempt start, and finish must
not precede observation. Missing source versions or clocks are rejected, never
filled from the current time. Equivalent timezone representations are normalized
to UTC. The evidence domain Source remains epss/kev, distinct from feed origins.

The existing offline manifest/observation SQL and positive-evidence encoding are
shared privately. Complete validates the running attempt, rechecks current
targets, inserts manifest/provenance and observations, and changes the same run
to success/partial in one SQL transaction. The successful receipt hashes the
entire normalized completion, including target bindings, source metadata,
selected entries, input digest and clocks. A write failure rolls all completion
writes back, leaving the original attempt and last-good evidence intact.
Offline import validation, receipt bytes and transaction semantics are preserved;
calling the offline importer with a precreated running ID is not used.

Publication identity conflicts use the existing source/CVE/publication boundary:
a different version or value at the same publication clock is rejected. Reads
still prefer publication, then observation, then stable evidence ID. Later
observation of an old publication does not replace newer evidence. Missing EPSS
is not zero. KEV entries are positive-only; an absent CVE never creates false or
removes a prior positive. Empty results retain a manifest, not fabricated values.

Fail accepts only fetch_failed, parse_failed, invalid_metadata, target_changed,
store_failed or canceled. It records failed/unknown on the same running attempt
without deleting observations. An exact failure retry is read-only. Success
cannot be downgraded or replaced with a failure. Arbitrary error text is rejected.

## Ambiguous outcomes and readback

After a write error the caller must retain the same UUID and completion. Do not
infer failure from an error, generate a replacement UUID or call Fail blindly.
Reconcile reads that UUID in one read-only snapshot and reports missing, running,
failed, success or unknown. Success requires an exact successful run receipt,
the expected manifest and every expected observation, including identities and
encoded evidence. Observation count materialization is capped at 201, followed
by at most 200 indexed exact-row checks. Stored run/evidence bodies are capped
at 4096 bytes and selection JSON at 8192 bytes on readback.

Missing/running/failed do not establish success. Unknown, a read error, collision
or corrupt provenance must not be converted to success or failure. First
reconcile; only a confirmed running attempt is eligible for a same-ID completion
retry. An exact successful retry validates stored provenance and returns Replay
without revalidating today's mutable finding state or overwriting past evidence.
The historical receipt remains bound to the original checked target revision.
External collection, cancellation-independent timed failure/reconciliation and
HTTP outcome handling belong to Phase B2 and are not implemented here.

## Compatibility and verification

The Phase A v2 reader exposes these feed origins without changing v1's six-source
filter. Domain enrichment, priority-preview, input_snapshot and the CLI base
schema are unchanged. Synthetic web tests exercise new feed receipts through
common reads, explicit-clock preview, strict snapshot decode and the existing
CLI, comparing the full Result. Finding/triage/history, legacy alerts and legacy
threat snapshots remain unchanged. These are runner tests, not claims of a live
feed integration.

Other synthetic tests cover last-scanned keysets, exact identities, mutation and
duplicate rejection, three transactional failure stages, last-good retention,
closed failure codes, same-ID concurrent/replay protection, publication order,
observation ties, zero/missing/positive-only semantics and bounded readback with
corrupt receipts. Formal Go compile/test/race/vet/build and CLI execution must
pass CI. Local gofmt and synthetic SQL checks are not integration-test passes.
