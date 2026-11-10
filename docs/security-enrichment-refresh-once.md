# Unconnected one-page synthetic enrichment orchestrator

This B2b package is a library with no application wiring, default live fetcher,
HTTP implementation, scheduler, main/config change, dependency or migration.
The existing legacy threat fetchers and offline importer remain unchanged.

## Input and dependency boundary

Service requires an injected Repository, business Clock, UUID factory and
Fetcher. Typed-nil or missing dependencies are rejected. Repository is defined
by the consumer in internal/enrichmentrefresh and uses existing store DTOs/APIs.
Store already imports threat; neither store nor threat imports this new package,
so the dependency graph remains acyclic.

A request selects exactly one epss_feed or kev_feed connector and one scan page
with limit 1–200. The injected Fetcher receives only the epss/kev domain label,
not finding IDs or the target selection. Its data in this slice is explicitly
synthetic, complete, uncompressed input in the existing strict offline envelope
format. It is not proof of interoperability with actual EPSS/CISA wire formats.

The returned byte slice length is checked against 32 MiB before hashing or
parsing. This matches the existing offline parser's input-byte limit; the parser
also retains its existing CSV-row/KEV-entry limits and source validation. The
digest is SHA256 of exactly the returned uncompressed parser-input bytes.
No compressed-wire byte count, transport allocation bound, HTTP behavior, CRC,
automatic decompression or real-source digest adapter is implemented or claimed.
A future transport must establish those separate contracts before live use.

Source publication/version and positive values are read only by the existing
threat.ParseOfflineThreat with OfflineOptions CVEs/ObservedAt. Missing metadata
is rejected; no wrapper creates an envelope or fills source fields from clocks,
legacy ThreatSnapshots or guessed dates. The existing strict parser is reused,
not replaced.

## One page and cursor rules

The service makes one target-page query and never loops to find eligible rows.
Before creating an ID it checks scan count 0..limit, targets<=scanned, target
identity/revision/canonical CVE bounds and strictly progressing binary IDs.
A nonempty scan requires a valid last-scanned ID greater than the input cursor;
an exhausted scan requires no returned targets/last ID. Invalid/nonprogressing
pages are rejected before UUID, Begin or Fetch.

Scanned=0 returns exhausted and retains the input cursor rather than resetting
it to empty. A page with scanned rows but no eligible targets creates no UUID,
run or fetch and may advance to the last scanned row. A nonempty target page may
advance only after verified success. Failure, pending and cancellation retain
the original cursor. The original context is checked immediately after the page
query, again before empty-page advancement, and at subsequent work boundaries.
No configured inventory, denominator, completeness or SLO is inferred.

## Ownership, clocks and persistence

The same bounded target manifest, source/scope/start and caller-factory UUID are
placed into an in-memory Pending envelope before Begin. Only err=nil plus
Replay=false on a fresh Begin establishes this invocation's fetch eligibility.
Replay or an uncertain Begin uses attempt-only readback and then stops, even if
a running row is confirmed. It does not fetch, Fail, allocate another UUID or
advance the cursor. Existing running is neither a liveness nor ownership grant.
Automatic external resume/refetch and ownership transfer are outside this slice.

Start is captured before Begin, observation after complete fixture bytes return,
and finish after parsing or a known collection failure. Source publication comes
only from metadata and may predate start. Publication<=observation and
start<=observation<=finish are validated. Invalid/backward clocks are not fixed
with current time, start time, a maximum, or any other synthesized timestamp.
If a valid explicit failure finish cannot be established, the reservation stays
pending without Fail. Fetch always receives the original context. Observed
cancellation prevents fetch/advancement, and cancellation after parse is checked
before Complete. A success already committed during cancellation is not undone;
the existing full-completion readback may establish that committed success.

Before Fail, the envelope retains the exact fixed code and finish. Before
Complete, it retains the full selected feed, digest, clocks and attempt.
Uncertain Fail uses only the attempt reader with that same expected failure.
Uncertain Complete uses only the existing full-completion Reconcile with the
retained completion. It does not Fail, retry, refetch or regenerate values.
Confirmed success/failure is returned as such; unknown/read errors retain Pending.

Cleanup lazily creates one context.WithTimeout(context.WithoutCancel(original),
2 seconds) and reuses that exact context/deadline across Fail and all readback.
It is never used for Fetch and is canceled on exit. An exhausted cleanup budget
is not renewed.

Retention is in-process ambiguous-return recovery only. The orchestrator is
the B1 store API caller and holds prepared values before each write. No durable
outbox, persistence callback, outer-caller pre-return retention, recovery from
a call that never returns, or process-crash/restart guarantee is implemented.
Those are separate requirements before live/scheduled use. Pending is not an
ownership grant or authorization to create a replacement attempt.

## Verification scope

Synthetic tests use owned SQLite databases and per-test Repository wrappers that
delegate real Begin/Fail/Complete and then return a synthetic post-commit error.
They check exact retained arguments, UUID/fetch/write counts, replay and cancel
barriers, common cleanup deadline, clocks, metadata rejection, byte/page bounds
and no SQL transaction held over Fetch. Known zero EPSS and positive KEV from
explicit synthetic envelopes are asserted through v2 receipts, common reads,
priority-preview, strict input_snapshot decode and the existing base CLI with
full Result comparison. Authoritative finding/triage/history, legacy alerts and
legacy threat snapshots must remain unchanged.

The four original Red contract test bytes remain unchanged. Formal Go
compile/test/race/vet/build and CLI execution must pass CI. Local gofmt/source
checks are not runtime/Go-test passes or real transport integration proof.
