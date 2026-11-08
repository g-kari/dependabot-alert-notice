# Offline finding priority preview

`cmd/preview-finding` makes the existing bounded preview available locally, without
starting the application. It reads one explicit snapshot from stdin. It has no
file-path option, database, configuration loading, environment-based settings,
network, notification, persistence, automatic clock, or background process.

From the repository root with its required Go toolchain:

```sh
go run ./cmd/preview-finding --schema base < cmd/preview-finding/testdata/base.json
go run ./cmd/preview-finding --schema profile < cmd/preview-finding/testdata/profile.json
go run ./cmd/preview-finding --schema assessment < cmd/preview-finding/testdata/assessment.json
```

These fixtures contain fictional identities and fixed dates, not live findings.
The command never substitutes today's time for `as_of`. Go may need to obtain its
build dependencies; that is separate from the compiled command's offline behavior.
Build with `go build -o preview-finding ./cmd/preview-finding` to invoke the command
directly. `--help` is the only other accepted argument form.

## Input

The exact two arguments `--schema base`, `--schema profile`, or `--schema assessment`
select the [base](finding-priority-preview-input.md),
[profile](finding-priority-preview-profile-input.md), or
[assessment](finding-priority-preview-assessment-input.md) decoder respectively.
The document's version must match; no inference or automatic upgrade is performed.
The existing closed schemas, required explicit clocks/bindings, unknown values,
64 KiB inclusive limit, depth limit, Unicode and duplicate-key validation remain
unchanged. The command reads at most 64 KiB plus one byte to detect oversize input.
EOF terminates the single snapshot; interactive stdin waits for EOF. Arrays,
batches, a second JSON document, new facts or CVSS fields are not accepted.

## Output and interpretation

On success, stdout contains one JSON object followed by a newline:

- `schema_version`: `finding-preview-output-v0.1`, independent of input versions.
- `warning`: a fixed preview-only interpretation warning.
- `result`: the complete existing adapter Result using Go's existing JSON field
  names/tags, including nulls, context, snapshots, origins, missing inputs,
  evidence clocks, mapping warnings and the unchanged ScoreResult.

This is a diagnostic snapshot, not an application API or a notification policy.
`PreviewOnly` remains true. Check `AdapterState` before interpreting `ScoreResult`;
valid unsupported inputs have no score. Read `MissingInputs`, `InputOrigins`,
`MappingWarnings` and model confidence alongside any priority. Unknown is not zero
or safe. Stale KEV retains the existing historical-positive model behavior.
A supplied unexpired `not_affected` claim can yield verified/planned labels, but
this command does not verify that claim's truth, authority or provenance. Expiry
at exactly `as_of` is expired. Priorities are not scheduled operational deadlines.
Do not close findings, accept risk, or suppress notifications based on this preview.

Output includes the identifiers and context the caller supplied. This is not a
secret detector or redactor. Use synthetic/non-secret snapshots and treat stdout
according to the sensitivity of the input; do not publish it blindly.

## Errors and exit status

The compiled command exits 0 on successful output (including unsupported findings)
or help, 2 for invalid arguments, and 1 for input, processing or I/O failures.
Priority is never an exit-status threshold. `go run` can wrap nonzero exit statuses;
use the compiled command when exact status values matter.

Errors use fixed stderr diagnostics: `preview-finding: arguments`, `read`, `size`,
`input`, `encode`, or `output`. They never echo raw input, arguments or system errors.
An unsuccessful diagnostic write returns 1. Validation and encoding finish before
stdout is touched, but an output failure can leave partial JSON. Discard output
unless the command exits 0; there is no automatic retry or output-file creation.

Tests use synthetic fixtures and injected readers/writers, compare the complete
result with each existing decoder, and cover limits, failures, schema isolation
and assessment expiry. Existing pure-package guards and scoring semantics remain
unchanged. Real data integration, UI, public HTTP, scanners, production and database
connections are separate work.
