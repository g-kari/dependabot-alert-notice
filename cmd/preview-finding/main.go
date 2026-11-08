// Command preview-finding previews one explicitly supplied offline JSON snapshot.
// It reads stdin only and never loads configuration or starts application services.
package main

import (
	"encoding/json"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreview"
	"github.com/g-kari/dependabot-alert-notice/internal/findingpreviewwire"
	"io"
	"os"
)

const outputVersion = "finding-preview-output-v0.1"
const warning = "Preview only: supplied claims are not verified; priorities are not operational deadlines. Do not use this output to close findings, accept risk, or suppress notifications."
const usage = "Usage: preview-finding --schema base|profile|assessment < snapshot.json\nReads one JSON snapshot from stdin (maximum 64 KiB); no database or network access.\n"

type output struct {
	SchemaVersion string                `json:"schema_version"`
	Warning       string                `json:"warning"`
	Result        findingpreview.Result `json:"result"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--help" {
		if !write(stdout, []byte(usage)) {
			return fail(stderr, "output", 1)
		}
		return 0
	}
	// An exact grammar avoids flag-package diagnostics echoing untrusted arguments.
	if len(args) != 2 || args[0] != "--schema" {
		return fail(stderr, "arguments", 2)
	}
	var decode func([]byte) (findingpreview.Result, error)
	switch args[1] {
	case "base":
		decode = findingpreviewwire.Decode
	case "profile":
		decode = findingpreviewwire.DecodeProfile
	case "assessment":
		decode = findingpreviewwire.DecodeAssessment
	default:
		return fail(stderr, "arguments", 2)
	}
	data, err := io.ReadAll(io.LimitReader(stdin, findingpreviewwire.MaxBytes+1))
	if err != nil {
		return fail(stderr, "read", 1)
	}
	if len(data) > findingpreviewwire.MaxBytes {
		return fail(stderr, "size", 1)
	}
	result, err := decode(data)
	if err != nil {
		return fail(stderr, "input", 1)
	}
	// Marshal completely before writing so validation/encoding errors emit no result.
	encoded, err := json.Marshal(output{SchemaVersion: outputVersion, Warning: warning, Result: result})
	if err != nil {
		return fail(stderr, "encode", 1)
	}
	if !write(stdout, append(encoded, '\n')) {
		return fail(stderr, "output", 1)
	}
	return 0
}

func write(w io.Writer, data []byte) bool {
	n, err := w.Write(data)
	return err == nil && n == len(data)
}
func fail(stderr io.Writer, code string, status int) int {
	if !write(stderr, []byte("preview-finding: "+code+"\n")) {
		return 1
	}
	return status
}
