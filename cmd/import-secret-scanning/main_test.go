package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

const testObservedAt = "2026-11-05T12:00:00Z"

const testReport = `[{"number":42,"state":"open","secret_type":"synthetic_example","secret":null}]`

type commandOutput struct {
	RunID        string `json:"run_id"`
	Findings     int    `json:"findings"`
	Observations int    `json:"observations"`
	Replay       bool   `json:"replay"`
	DryRun       bool   `json:"dry_run"`
}

func requiredArgs() []string {
	return []string{"--input", "-", "--repository", "example/repo", "--observed-at", testObservedAt}
}

func execute(t *testing.T, args []string, input string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func decodeOutput(t *testing.T, output string) commandOutput {
	t.Helper()
	var got commandOutput
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("decode output %q: %v", output, err)
	}
	return got
}

func assertNoFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected database at %q: stat error = %v", path, err)
	}
}

func TestRunDryRunValidatesWithoutOpeningDatabase(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "never-created", "security.db")
	args := append(requiredArgs(), "--dry-run", "--db", dbPath)
	code, stdout, stderr := execute(t, args, testReport)
	if code != 0 || stderr != "" {
		t.Fatalf("dry run: code = %d, stderr = %q", code, stderr)
	}
	got := decodeOutput(t, stdout)
	if !got.DryRun || got.Replay || got.Findings != 1 || got.Observations != 1 {
		t.Fatalf("unexpected dry run result: %+v", got)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(got.RunID) {
		t.Fatalf("run ID is not a UUID: %q", got.RunID)
	}
	assertNoFile(t, dbPath)
	if _, err := os.Stat(filepath.Dir(dbPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry run created database parent directory: %v", err)
	}
	if strings.Contains(stdout, "synthetic_example") || strings.Contains(stdout, "example/repo") {
		t.Fatalf("dry run output exposes source details: %q", stdout)
	}
}

func TestRunRequiresExplicitFlagsBeforeReadingInputOrOpeningDatabase(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no flags", nil},
		{"missing input", []string{"--repository", "example/repo", "--observed-at", testObservedAt, "--dry-run"}},
		{"missing repository", []string{"--input", "-", "--observed-at", testObservedAt, "--dry-run"}},
		{"empty repository", []string{"--input", "-", "--repository", "", "--observed-at", testObservedAt, "--dry-run"}},
		{"blank repository", []string{"--input", "-", "--repository", " \t", "--observed-at", testObservedAt, "--dry-run"}},
		{"long repository", []string{"--input", "-", "--repository", strings.Repeat("a", 257) + "/repo", "--observed-at", testObservedAt, "--dry-run"}},
		{"control in repository", []string{"--input", "-", "--repository", "example\naccount", "--observed-at", testObservedAt, "--dry-run"}},
		{"format character in repository", []string{"--input", "-", "--repository", "example\u200baccount", "--observed-at", testObservedAt, "--dry-run"}},
		{"invalid UTF8 in repository", []string{"--input", "-", "--repository", string([]byte{0xff}), "--observed-at", testObservedAt, "--dry-run"}},
		{"missing timestamp", []string{"--input", "-", "--repository", "example/repo", "--dry-run"}},
		{"invalid timestamp", []string{"--input", "-", "--repository", "example/repo", "--observed-at", "bad-PRIVATE-TOKEN", "--dry-run"}},
		{"missing database", requiredArgs()},
		{"empty database", append(requiredArgs(), "--db", "")},
		{"invalid run ID", append(requiredArgs(), "--dry-run", "--run-id", "PRIVATE-TOKEN")},
		{"extra argument", append(requiredArgs(), "--dry-run", "unexpected-PRIVATE-TOKEN")},
		{"unknown flag", append(requiredArgs(), "--dry-run", "--unknown=PRIVATE-TOKEN")},
		{"invalid boolean", append(requiredArgs(), "--dry-run=PRIVATE-TOKEN")},
		{"input URL", []string{"--input", "https://example.invalid/report.json", "--repository", "example/repo", "--observed-at", testObservedAt, "--dry-run"}},
		{"database URI", append(requiredArgs(), "--db", "file:security.db?mode=memory")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			reader := &failOnRead{t: t}
			if code := run(tt.args, reader, &stdout, &stderr); code == 0 {
				t.Fatalf("invalid arguments succeeded: %v", tt.args)
			}
			if stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("invalid arguments: stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "PRIVATE-TOKEN") {
				t.Fatalf("error leaked flag value: %q", stderr.String())
			}
		})
	}
}

type failOnRead struct{ t *testing.T }

func (r *failOnRead) Read([]byte) (int, error) {
	r.t.Helper()
	r.t.Fatal("input was read before argument validation completed")
	return 0, io.EOF
}

func TestRunRejectsInvalidInputWithoutCreatingDatabase(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"malformed", `{"PRIVATE-TOKEN":`},
		{"not report", `{"SchemaVersion":2,"PRIVATE-TOKEN":"secret"}`},
		{"multiple documents", testReport + testReport},
		{"unsupported state", strings.Replace(testReport, `"state":"open"`, `"state":"unsupported"`, 1)},
		{"literal secret", strings.Replace(testReport, `"secret":null`, `"secret":"PRIVATE-SECRET-VALUE"`, 1)},
		{"masked secret", strings.Replace(testReport, `"secret":null`, `"secret":"***"`, 1)},
		{"oversized", testReport + strings.Repeat(" ", 10*1024*1024)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "security.db")
			code, stdout, stderr := execute(t, append(requiredArgs(), "--db", dbPath), tt.input)
			if code == 0 || stdout != "" || stderr == "" {
				t.Fatalf("invalid input: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
			}
			if strings.Contains(stderr, "PRIVATE-TOKEN") || strings.Contains(stderr, "PRIVATE-SECRET-VALUE") {
				t.Fatalf("error leaked source input: %q", stderr)
			}
			assertNoFile(t, dbPath)
		})
	}
}

func TestRunInputLimitIsExactlyTenMiBAndDoesNotOverRead(t *testing.T) {
	input := testReport + strings.Repeat(" ", 10*1024*1024-len(testReport))
	code, stdout, stderr := execute(t, append(requiredArgs(), "--dry-run"), input)
	if code != 0 || stderr != "" || decodeOutput(t, stdout).Findings != 1 {
		t.Fatalf("exactly 10 MiB should be accepted: code = %d, stderr = %q", code, stderr)
	}
	reader := &countingReader{remaining: 20 * 1024 * 1024}
	var out, errOut bytes.Buffer
	if code := run(append(requiredArgs(), "--dry-run"), reader, &out, &errOut); code == 0 {
		t.Fatal("oversized input succeeded")
	}
	if reader.read != 10*1024*1024+1 {
		t.Fatalf("read %d bytes; want bounded %d", reader.read, 10*1024*1024+1)
	}
}

type countingReader struct{ remaining, read int }

func (r *countingReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.remaining)
	for i := range p[:n] {
		p[i] = ' '
	}
	r.remaining -= n
	r.read += n
	return n, nil
}

func TestRunDeterministicIDUsesRepositoryAndOriginalBytes(t *testing.T) {
	args := append(requiredArgs(), "--dry-run")
	_, first, _ := execute(t, args, testReport)
	_, second, _ := execute(t, args, testReport)
	_, changedBytes, _ := execute(t, args, testReport+"\n")
	changedRepositoryArgs := []string{"--input", "-", "--repository", "another/repo", "--observed-at", testObservedAt, "--dry-run"}
	_, changedRepository, _ := execute(t, changedRepositoryArgs, testReport)
	a, b := decodeOutput(t, first), decodeOutput(t, second)
	c, d := decodeOutput(t, changedBytes), decodeOutput(t, changedRepository)
	if a.RunID != b.RunID || a.RunID == c.RunID || a.RunID == d.RunID {
		t.Fatalf("run IDs: original = %q, replay = %q, changed bytes = %q, changed repository = %q", a.RunID, b.RunID, c.RunID, d.RunID)
	}
}

func TestRunImportsReplaysAndRejectsChangedExplicitRunID(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "security.db")
	const runID = "9efde342-e17b-4dcb-97c3-f58c1fc01761"
	args := append(requiredArgs(), "--db", dbPath, "--run-id", runID)
	code, stdout, stderr := execute(t, args, testReport)
	if code != 0 || stderr != "" {
		t.Fatalf("import: code = %d, stderr = %q", code, stderr)
	}
	first := decodeOutput(t, stdout)
	if first.RunID != runID || first.Replay || first.DryRun || first.Findings != 1 || first.Observations != 1 {
		t.Fatalf("unexpected import result: %+v", first)
	}
	code, stdout, stderr = execute(t, args, testReport)
	if code != 0 || stderr != "" || !decodeOutput(t, stdout).Replay {
		t.Fatalf("replay: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	for _, changedInput := range []string{testReport + "\n", strings.Replace(testReport, `"secret_type":"synthetic_example"`, `"secret_type":"synthetic_other"`, 1)} {
		code, stdout, stderr = execute(t, args, changedInput)
		if code == 0 || stdout != "" || stderr == "" {
			t.Fatalf("reused run ID must reject changed input: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
		}
	}
	s, err := store.NewWithPath(dbPath)
	if err != nil {
		t.Fatalf("open imported database: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	findings, err := s.QueryFindings(context.Background())
	if err != nil || len(findings) != 1 || findings[0].SecretType != "synthetic_example" {
		t.Fatalf("findings changed after conflict: %+v, %v", findings, err)
	}
	observations, err := s.QueryObservations(context.Background(), findings[0].ID)
	if err != nil || len(observations) != 1 {
		t.Fatalf("replay or conflict duplicated observations: %+v, %v", observations, err)
	}
	runs, err := s.QueryIngestRuns(context.Background())
	if err != nil || len(runs) != 1 || runs[0].Coverage != "partial" || runs[0].Result != "success" {
		t.Fatalf("unexpected import ledger: %+v, %v", runs, err)
	}
}

func TestRunReadsExplicitFileAndReleasesResources(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "report.json")
	dbPath := filepath.Join(dir, "security.db")
	if err := os.WriteFile(inputPath, []byte(testReport), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--input", inputPath, "--repository", "example/repo", "--observed-at", testObservedAt, "--db", dbPath}
	for i := 0; i < 4; i++ {
		code, _, stderr := execute(t, args, "")
		if code != 0 || stderr != "" {
			t.Fatalf("file import %d: code = %d, stderr = %q", i, code, stderr)
		}
	}
	if err := os.WriteFile(inputPath, []byte(`{"malformed":`), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := execute(t, args, ""); code == 0 {
		t.Fatal("invalid file input unexpectedly succeeded")
	}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if err == nil && (target == inputPath || strings.HasPrefix(target, dbPath)) {
				t.Fatalf("input file or database descriptor leaked: %q", target)
			}
		}
	}
	if err := os.Rename(inputPath, inputPath+".closed"); err != nil {
		t.Fatalf("input file remains open: %v", err)
	}
	if err := os.Rename(dbPath, dbPath+".closed"); err != nil {
		t.Fatalf("database remains open: %v", err)
	}
}

func TestRunReportsFileAndReadFailuresWithoutOpeningDatabase(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "security.db")
		args := []string{"--input", filepath.Join(dir, "missing.json"), "--repository", "example/repo", "--observed-at", testObservedAt, "--db", dbPath}
		code, stdout, stderr := execute(t, args, "")
		if code == 0 || stdout != "" || stderr == "" {
			t.Fatalf("missing file: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
		}
		assertNoFile(t, dbPath)
	})
	t.Run("read error", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "security.db")
		var stdout, stderr bytes.Buffer
		code := run(append(requiredArgs(), "--db", dbPath), errorReader{}, &stdout, &stderr)
		if code == 0 || stdout.Len() != 0 || stderr.Len() == 0 || strings.Contains(stderr.String(), "PRIVATE-TOKEN") {
			t.Fatalf("read failure: code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
		}
		assertNoFile(t, dbPath)
	})
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-TOKEN") }

func TestRunHelpDoesNotReadInputOrOpenDatabase(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &failOnRead{t: t}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "may be created or migrated") {
		t.Fatalf("help: code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestRunRejectsDirectoryInputBeforeDatabaseOpen(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "security.db")
	args := []string{"--input", dir, "--repository", "example/repo", "--observed-at", testObservedAt, "--db", dbPath}
	code, stdout, stderr := execute(t, args, "")
	if code == 0 || stdout != "" || stderr == "" {
		t.Fatalf("directory input: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	assertNoFile(t, dbPath)
}

func TestRunDefaultIDReplaysAndRejectsChangedTimestamp(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "security.db")
	args := append(requiredArgs(), "--db", dbPath)
	code, firstOutput, stderr := execute(t, args, testReport)
	if code != 0 || stderr != "" {
		t.Fatalf("initial import: code = %d, stderr = %q", code, stderr)
	}
	first := decodeOutput(t, firstOutput)
	code, replayOutput, stderr := execute(t, args, testReport)
	replay := decodeOutput(t, replayOutput)
	if code != 0 || stderr != "" || !replay.Replay || first.RunID != replay.RunID {
		t.Fatalf("default ID replay: code = %d, first = %+v, replay = %+v, stderr = %q", code, first, replay, stderr)
	}
	changedArgs := []string{"--input", "-", "--repository", "example/repo", "--observed-at", "2026-11-06T12:00:00Z", "--db", dbPath}
	code, stdout, stderr := execute(t, changedArgs, testReport)
	if code == 0 || stdout != "" || stderr == "" {
		t.Fatalf("same deterministic run ID with changed time should conflict: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}

func TestRunInvalidInputLeavesExistingDatabaseUnchanged(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "existing.db")
	original := []byte("synthetic-not-a-sqlite-db-PRIVATE-TOKEN")
	if err := os.WriteFile(dbPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := execute(t, append(requiredArgs(), "--db", dbPath), `{"malformed":`)
	if code == 0 || stdout != "" || stderr == "" || strings.Contains(stderr, "PRIVATE-TOKEN") {
		t.Fatalf("invalid input: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	after, err := os.ReadFile(dbPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatalf("invalid input touched existing database: bytes = %q, error = %v", after, err)
	}
}

func TestRunLiteralSecretLeavesExistingDatabaseUnchanged(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "existing.db")
	original := []byte("synthetic-non-database")
	if err := os.WriteFile(dbPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	input := strings.Replace(testReport, `"secret":null`, `"secret":"PRIVATE-SECRET-VALUE"`, 1)
	code, stdout, stderr := execute(t, append(requiredArgs(), "--db", dbPath), input)
	if code == 0 || stdout != "" || stderr == "" || strings.Contains(stderr, "PRIVATE-SECRET-VALUE") {
		t.Fatal("literal secret accepted or echoed")
	}
	after, err := os.ReadFile(dbPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("secret rejection touched existing DB")
	}
}

func TestRunOutputFailureDoesNotLeakUnderlyingError(t *testing.T) {
	var stderr bytes.Buffer
	code := run(append(requiredArgs(), "--dry-run"), strings.NewReader(testReport), errorWriter{}, &stderr)
	if code == 0 || stderr.Len() == 0 || strings.Contains(stderr.String(), "PRIVATE-TOKEN") {
		t.Fatalf("output failure: code = %d, stderr = %q", code, stderr.String())
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("PRIVATE-TOKEN") }

func TestRunRejectsMetadataLimitsBeforeOpeningDatabase(t *testing.T) {
	// A type identifier is bounded and cannot contain free text or secret material.
	input := strings.Replace(testReport, `"secret_type":"synthetic_example"`, `"secret_type":"`+strings.Repeat("a", 129)+`"`, 1)
	for _, dryRun := range []bool{false, true} {
		t.Run(map[bool]string{false: "import", true: "dry run"}[dryRun], func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "security.db")
			args := append(requiredArgs(), "--db", dbPath)
			if dryRun {
				args = append(args, "--dry-run")
			}
			code, stdout, stderr := execute(t, args, input)
			if code == 0 || stdout != "" || stderr == "" {
				t.Fatalf("invalid normalized payload: code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
			}
			assertNoFile(t, dbPath)
		})
	}
}

func TestRunEmptyPartialImportRetainsPreviouslyObservedFindings(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "security.db")
	args := append(requiredArgs(), "--db", dbPath)
	if code, _, stderr := execute(t, args, testReport); code != 0 {
		t.Fatalf("initial import: code = %d, stderr = %q", code, stderr)
	}
	emptyReport := `[]`
	code, stdout, stderr := execute(t, args, emptyReport)
	if code != 0 || stderr != "" {
		t.Fatalf("empty import: code = %d, stderr = %q", code, stderr)
	}
	got := decodeOutput(t, stdout)
	if got.Findings != 0 || got.Observations != 0 || got.Replay || got.DryRun {
		t.Fatalf("empty import result: %+v", got)
	}
	s, err := store.NewWithPath(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	}()
	findings, err := s.QueryFindings(context.Background())
	if err != nil || len(findings) != 1 || findings[0].SourceStatus != "active" {
		t.Fatalf("empty partial import changed prior findings: %+v, %v", findings, err)
	}
	runs, err := s.QueryIngestRuns(context.Background())
	if err != nil || len(runs) != 2 {
		t.Fatalf("expected both runs retained: %+v, %v", runs, err)
	}
	for _, run := range runs {
		if run.Coverage != "partial" || run.Result != "success" {
			t.Fatalf("unexpected empty-report coverage: %+v", run)
		}
	}
}

func TestRunRejectsUNCAndDevicePathsBeforeInputAccess(t *testing.T) {
	for _, path := range []string{`\\server\share\feed.json`, `//server/share/feed.json`, `\/server/share/feed.json`, `/\server\share\feed.json`, `\\?\C:\feed.json`, `\\.\pipe\synthetic`} {
		if localPath(path) {
			t.Fatalf("network/device path accepted by local validator: %q", path)
		}
		for _, target := range []string{"input", "database"} {
			t.Run(target+path, func(t *testing.T) {
				args := requiredArgs()
				if target == "input" {
					args[1] = path
					args = append(args, "--dry-run")
				} else {
					args = append(args, "--db", path)
				}
				var out, errout bytes.Buffer
				if code := run(args, &failOnRead{t: t}, &out, &errout); code == 0 || out.Len() != 0 || errout.Len() == 0 {
					t.Fatalf("network path accepted: code=%d", code)
				}
			})
		}
	}
}
