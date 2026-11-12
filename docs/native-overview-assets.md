# Native Overview, Assets and recorded integrations

This is the first coherent read-only Overview/Assets slice in the main app.
It reuses the approved Findings Console's navy navigation, mint selection,
Japanese-capable local system fonts and existing component roles. It creates no
separate Site, listener, credential setup, collection trigger or new approval flow.

## Routes and objects

- `/security`: global retained common Finding/Asset counts, latest-source
  breakdown, up to eight active critical/high findings and up to five recorded
  source/scope summaries. It does not replace `/` or its legacy Alert semantics.
- `/assets`: stable ID order, literal substring search and exact saved-value
  filters for provider/account/region/environment/criticality and recorded
  finding source. Counts are matching retained assets before pagination.
- `/assets/{id}`: one saved identity, bounded filtered common Findings, and links
  to the common Finding collection/detail. An encoded, validated `assets_query`
  preserves the asset collection's filters and page on the return link. A selected
  source also carries through to the Asset's Finding collection using the existing
  Finding source validator (64-byte lowercase identifier syntax). Finding
  filters and the AssetID binding remain in the common Findings link and detail
  pagination. Browser Back/Forward uses ordinary GET navigation, with no script
  or client-side state added.
- `/integrations`: an explicit RFC3339 `as_of` evaluates the K269 recorded-status
  store contract directly, with exact source/scope filters and bounded paging.
  The initial screen requires a clock rather than selecting one silently.

Every new native route accepts GET/HEAD only and uses no-store/nosniff headers,
buffered escaped templates, same-origin links and sanitized errors. Raw Native
IDs, scopes, source IDs and evidence references remain text, not executable URLs.
The pagination-only Assets API and all existing API response contracts are
unchanged. Collection filters match retained observations, not configured scopes.

Asset detail's nested return query has a separate outer budget of 16,398 bytes:
`assets_query=` (13), up to 3 × 4,096 bytes for percent-encoding the inner query,
one separator and up to 4,096 canonical bytes of Finding filters. Strict key and
duplicate checks apply to both layers. Each decoded query still passes its
unchanged 4,096-byte guard and original semantic validators; no API query limit
is raised. Asset list input also checks canonical return-query size and reserves
the maximum limit/offset widths, so accepted raw Unicode cannot generate an
oversized detail, pagination or Back link. Back-list source and current Finding
source are independent: clearing the latter never rebinds it to the former.

## Truthful aggregates and uncertainty

Overview scalar counts, source breakdown and severe queue share one read-only
SQLite transaction. SQL aggregates all retained rows, while Go materializes at
most 64 source groups (with a truncation notice) and eight severe findings.
Severe ordering is source severity first, then latest detection, never a guessed
priority score. Source mix assigns each Finding to its latest observation's
source; it is not the historical source-membership filter used by Findings API.

Overview's collection summary is a **separate** consistent store snapshot, not an
atomic snapshot of the entire page. Both components use the displayed evaluation
clock. The UI default is current UTC at request start, injected by a fixed-clock
test; its Integrations link carries that exact `as_of`. This is an evaluation of
current retained data, not historical DB reconstruction. A collection-summary
failure is a visible partial error and cannot replace the independently read
Finding/Asset counts with zeroes.

Asset count, page, saved facts, finding counts, latest observation and bounded
source memberships share one read transaction. Asset detail and its finding page
also share one read transaction. The linked individual Finding page keeps its
existing independent detail/related snapshot boundaries. No reader writes data.

The UI distinguishes latest recorded attempt, last successful receipt, failure,
partial, running and future records. Future evidence cannot establish current
status or coverage. Liveness, configured/unscanned inventory and the asset
coverage denominator remain unknown. Offline paths are receipt-only: a successful
receipt cannot prove no later failure occurred. Retained run counts are not all
requests or all failures. Record age is not source/feed freshness or an SLA.

A saved Asset with no retained Finding may be unobserved, outside collection scope
or have no recorded detection. It is not labelled safe, scanned or unmanaged.
Empty saved attributes remain unknown. No environment/criticality editing is
exposed before the Web-auth/RBAC work. Common KEV/overdue global aggregates,
saved common priorities/deadlines and a global recent-event view remain future
work and are not simulated with demo numbers.

## Legacy behavior and validation boundaries

All native and legacy pages now share navigation and theme. Legacy Alert,
dashboard, reports, settings, RSS/TUI, approval and log handlers keep their routes,
POST semantics, CSRF checks and SSE behavior. Native pages still open no SSE
stream. Alerts and common Finding IDs remain explicitly different objects.
The theme corrects primary-button hover precedence and danger-button/focus
contrast for legacy screens as well as new views.

Synthetic tests cover bounded/global aggregates, duplicate observations, source
identity, exact/literal asset filters, unknown observations, AssetID binding,
explicit/fixed clocks, failure/future/running records, escaping, methods, safe
errors and persistent-read invariance. Existing legacy CSRF/SSE tests remain.
Standard-library template execution and static accessibility checks are separate
from application/database tests and actual browser rendering.

Local package tests and `scripts/check.ps1` remain environment-blocked by the
uncached required SQLite/goldmark/go-isatty versions and unavailable PowerShell.
No dependency downloads, versions, runtime services or browser workaround were
introduced. Official CI must validate the exact integrated branch. Desktop/mobile
browser rendering, contrast in rendered states, keyboard interaction and full
visual acceptance remain unverified; static CSS/template checks do not complete
those acceptance criteria.
