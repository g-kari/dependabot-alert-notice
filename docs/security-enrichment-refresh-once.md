# Unconnected one-page synthetic enrichment orchestrator

This B2b package is a library with no application wiring, default live fetcher,
real HTTP execution, scheduler, main/config change, dependency or migration.
The optional transport capability below remains explicitly injected and unwired.
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
synthetic, complete, uncompressed metadata-bearing EPSS CSV or projection-minimal
KEV catalog JSON accepted by the existing offline projection parser. There is no
outer envelope format or conversion step. This is not proof of interoperability
with all actual EPSS/CISA wire formats or full provider-schema validation.

The returned byte slice length is checked against 32 MiB before hashing or
parsing. This matches the existing offline parser's input-byte limit; the parser
also retains its existing CSV-row/KEV-entry limits and source validation. The
digest is SHA256 of exactly the returned uncompressed parser-input bytes.
The optional fake-tested transport below bounds encoded entity-body/decoded
payload bytes and gzip completeness separately. No transport allocation/total
wire bound, real-provider interoperability or real-source digest is claimed.

Source publication/version and positive values are read only by the existing
threat.ParseOfflineThreat with OfflineOptions CVEs/ObservedAt. Missing metadata
is rejected; no wrapper constructs source metadata or fills source fields from
clocks, legacy ThreatSnapshots or guessed dates. The existing bounded offline
projection parser is reused, not replaced.


## Bounded transport capability: fake-only verification

An optional BoundedHTTPFetcher now implements the existing Fetcher interface.
It requires an explicit RoundTripper and copied epss/kev source profiles, each
with a fixed HTTPS URL and explicit identity or gzip payload representation.
There is no default transport or endpoint and no application/main/config or
scheduler wiring. Tests use only .invalid URLs and fake RoundTrippers: no HTTP
server, socket, real endpoint or feed retrieval is exercised.

The adapter makes exactly one RoundTrip call with GET and Accept-Encoding:
identity. Profiles reject URL userinfo, query and fragment; callers supply no
CVE selection, credential headers or cookies. It does not use http.Client,
follow redirects or implement retry; only status 200 is accepted. The injected
transport is a trusted capability boundary: it must return raw entity bytes and
must not add credentials, transparently decode, retry or change destinations.
A future live transport must explicitly disable automatic decompression
(DisableCompression=true) and separately establish its retry, timeout and other
network policies. Arbitrary transport internals are not verified by these fakes.

HTTP Content-Encoding must be absent/empty/identity. Response.Uncompressed,
other or stacked HTTP codings are rejected, even for the gzip source profile.
The configured gzip representation is a compressed object within that identity
HTTP body, not negotiated HTTP gzip. Real provider header/profile compatibility
has not been established. No automatic encoding fallback or recursive decoding
is performed; a nested gzip payload is rejected.

Encoded entity-body input is limited to 16 MiB using a 16 MiB+1 sentinel read.
Decoded payload is limited to 32 MiB with a 32 MiB+1 sentinel. Known ContentLength
must be nonnegative, within the encoded limit and equal the actual body length;
-1 alone denotes unknown length. Any supplied Content-Length header must agree
unambiguously. Successful reads consume the supplied Body through EOF. Rejected
oversize/error responses are closed without adapter-level unbounded draining.
These are body/payload limits, not total TLS/network bytes, HTTP framing,
headers, transport allocation or work performed internally by Body.Close.

A gzip payload is read through a single member with Multistream(false), using
a byte reader to preserve the exact trailing boundary. Full decoded EOF checks
CRC and ISIZE before success; gzip.Close alone is not validation. Truncation,
trailing bytes (including whitespace), concatenated/empty second members and
nested gzip fail without returning partial bytes. The adapter does not create
metadata, parse records or reserialize: the existing orchestrator hashes the
exact returned decoded CSV/catalog JSON bytes and reuses ParseOfflineThreat.
OriginalDigest remains decoded parser-input SHA256, not compressed-body SHA256.

Fetch uses the original context for request/read/decode and checks it again
before returning. A synchronized close-once helper and context.AfterFunc close
a cooperative response Body on cancellation; cleanup stops/joins that callback.
Every obtained nonnil Body is closed, including response-plus-error cases.
Close failure or cancellation returns no bytes. Cancellation after EOF or
during Close cannot be reported as successful data. Noncooperative RoundTrip,
Read or Close implementations cannot be forcibly stopped or given a universal
wall-time bound here.

Errors expose only fixed adapter messages or standard context cancellation.
Synthetic SQLite tests verify known facts and decoded digest/receipt retention;
read errors and invalid source metadata record only existing closed failure
codes, never raw response bytes or underlying error text. Existing full
read/preview/input_snapshot/CLI parity tests still cover the unchanged upper
layers; this fake transport test is not additional live/full-wire proof.

## Supported synthetic source subset

The existing EPSS local subset requires a first-line comment containing exactly
model_version and score_date keys, followed by cve/epss/percentile CSV columns
(and an optional date column). The fixtures are authored examples of that
existing grammar. [FIRST's public format description](https://www.first.org/epss/data)
documents three columns and a model-version/publication-date comment for v2 and
later, but does not settle the literal metadata-key grammar or timestamp
precision relied on here. No complete provider-wire compatibility is inferred;
older metadata-free input is not supplemented from a filename or current clock.

The authored positive KEV fixture includes every required field from the
[official schema at blob ec422845b354f58250d2e99cdfcce17a18659423](https://github.com/cisagov/kev-data/blob/d98075f22b11ca60ede428f4397966d3523dc692/known_exploited_vulnerabilities_schema.json).
The parser projects catalogVersion/dateReleased/count and cveID/dateAdded. It
does not enforce the schema-required vendorProject, product, vulnerabilityName,
shortDescription, requiredAction or dueDate fields. Existing projection-minimal
fixtures deliberately omit those fields; their acceptance is not full-schema
validation. dateReleased uses the shared offline date parser, accepting RFC3339
with optional fractional seconds, offsets without a colon, date-only input,
space-separated date/time and timezone-free T-separated date/time. This is wider
than the schema's date-time format and is characterized without changing the
offline importer.

Source version/publication, selected canonical records, count/duplicate rules
and whole-input bounds remain the existing offline parser's contract. Publication
and observation clocks stay independent. A selected CVE absent from input adds
no observation; zero EPSS remains known zero and KEV remains positive-only.
No source-profile decoder, metadata generator or new public API is added.

Equivalent parsed feeds do not imply identical input bytes. CSV LF versus CRLF
and JSON whitespace variants retain different exact input SHA256 values in the
prepared Completion. Reconciliation binds that digest to the stored manifest
and success receipt; swapping only the digest for the other variant is rejected.
The digest identifies the supplied uncompressed document, not a normalized
serialization, compressed wire stream or proof of transport EOF/CRC.

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


## Manual caller ownership controller: no write route

ManualController is an explicitly injected Go caller boundary around the existing
Service. It adds no HTTP write route, UI, CLI, main/config wiring or default
dependencies. Construction copies the Service value and requires its Store,
Clock, UUID factory and Fetcher, but never opens or closes caller-owned storage.

A canonical lowercase operation ID is distinct from the Service's run UUID and
binds the exact connector/after/limit request without normalization. Before retention,
IDs use the existing 36-byte lowercase UUID format, connector is closed to the two
feed kinds, limit is 1..200 and cursor is at most 128 UTF-8 bytes without control
or format characters. Records contain projected bounded DTOs and fixed error
classifications, never raw response bodies, arbitrary errors or per-call closures.
The explicitly injected dependency capabilities remain caller-trusted; copying
the Service value does not freeze arbitrary state captured inside a dependency.
The controller
reserves a calling slot before invoking Service. It never holds its metadata
mutex across Service or Store I/O, and allows only one in-flight service or
explicit recovery call per controller. Reentrant/concurrent fresh work is refused,
not queued or retried. Snapshot remains available while a call is in flight.

Service owns its prepared attempt/failure/full Completion before each write and
until return. Immediately after return, the controller takes its own deep copy
of the complete Result/Pending, including both target manifests, selected CVEs,
entry slices, probability/percentile/date pointers and exact clocks/digest. Every
outer Call/Snapshot/Reconcile result is another deep copy. A run ID alone is not
an adequate replacement for that envelope. The private original is retained even
after verified resolution.

Same-ID/same-content calls replay retained state with zero dependency I/O, so a
lost outer response does not cause a new UUID, clock, fetch or write. Same ID
with different content conflicts. A calling slot reports busy. An unresolved
pending operation blocks fresh IDs for that connector, including other cursors;
it does not grant fetch ownership from recorded running or missing state.
An independent connector may proceed when no call is in flight.

Retention is at most 16 operation records per controller, with no eviction,
expiration or automatic reset. Full retention rejects new operations before I/O;
existing matching operations can still replay, and mismatched reuse still
conflicts. Invalid/context/busy/source/capacity refusals never call Service,
Store, business Clock, UUID factory or Fetcher. This is not an unbounded job queue.

Recovery is an explicit read-only Reconcile call, not a side effect of replay.
A retained full Completion uses existing full Store reconciliation. A retained
expected failure uses the attempt reader with exactly the same code/finish.
Begin-only readback can observe running/missing but cannot obtain ownership,
fetch or allocate a replacement UUID. Unknown/read-error/canceled recovery keeps
the complete original envelope. Readback receives the original caller context
with at most two seconds; it does not use WithoutCancel or perform cleanup writes.
Verified success alone applies the existing Service success/cursor rule to the
saved ScanAfter; exact verified failure retains the input cursor. No clocks,
metadata, HTTP/parse or writes are regenerated. Already resolved operations use
cached state instead of reading external storage again. A cached operation outcome
is not a fresh liveness or current-database-health assertion.

This ownership chain is in-process only. Controller replacement, process
crash/restart, an unreturned/panicking call, durable acknowledgment/outbox and
multi-controller shared ownership are not solved. A non-returning call keeps
its reserved in-flight slot; clearing it is not permission to retry. No user
principal, HTTP authentication, CSRF/origin enforcement or public write API is
claimed. Any later app route must separately provide those guards while retaining
this controller; existing read-only v1/v2 APIs remain unchanged.

## Verification scope

Synthetic tests use owned SQLite databases and per-test Repository wrappers that
delegate real Begin/Fail/Complete and then return a synthetic post-commit error.
They check exact retained arguments, UUID/fetch/write counts, replay and cancel
barriers, common cleanup deadline, clocks, metadata rejection, byte/page bounds
and no SQL transaction held over Fetch. Known zero EPSS and positive KEV from
explicit synthetic CSV/catalog JSON inputs are asserted through v2 receipts,
common reads, priority-preview, strict input_snapshot decode and the existing base CLI with
full Result comparison. Authoritative finding/triage/history, legacy alerts and
legacy threat snapshots must remain unchanged.

The four original Red contract test bytes remain unchanged. Formal Go
compile/test/race/vet/build and CLI execution must pass CI. Local gofmt/source
checks are not runtime/Go-test passes or real transport integration proof.
