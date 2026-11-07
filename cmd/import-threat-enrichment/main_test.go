package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

const testObservedAt = "2026-11-07T20:00:00Z"
const testReport = "#model_version:v2026.01.01,score_date:2026-11-07\ncve,epss,percentile\nCVE-2026-0001,0.25,0.8\n"
const testKEV = `{"catalogVersion":"2026.11.07","dateReleased":"2026-11-07T12:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-0001","dateAdded":"2026-11-06"}]}`

func args() []string {
	return []string{"--input", "-", "--source", "epss", "--cves", "CVE-2026-0001", "--observed-at", testObservedAt}
}
func execute(t *testing.T, argv []string, input string) (int, string, string) {
	t.Helper()
	var out, errout bytes.Buffer
	code := run(argv, strings.NewReader(input), &out, &errout)
	return code, out.String(), errout.String()
}
func decode(t *testing.T, s string) summary {
	t.Helper()
	var v summary
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decode=%v output=%s", err, s)
	}
	return v
}
func absent(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected file %s err=%v", p, err)
	}
}

type noRead struct{ t *testing.T }

func (r noRead) Read([]byte) (int, error) { r.t.Fatal("read before flag validation"); return 0, io.EOF }

func TestRunValidatesRequiredFlagsBeforeReading(t *testing.T) {
	for _, a := range [][]string{nil, {"--input", "-", "--dry-run"}, {"--input", "-", "--source", "unknown", "--cves", "CVE-2026-0001", "--observed-at", testObservedAt, "--dry-run"}, {"--input", "-", "--source", "epss", "--cves", "GHSA-PRIVATE-MARKER", "--observed-at", testObservedAt, "--dry-run"}, append(args(), "--run-id", "PRIVATE-MARKER", "--dry-run"), append(args(), "--unknown=PRIVATE-MARKER"), args(), {"--input", "https://example.invalid/PRIVATE-MARKER", "--source", "epss", "--cves", "CVE-2026-0001", "--observed-at", testObservedAt, "--dry-run"}} {
		var out, errout bytes.Buffer
		if code := run(a, noRead{t}, &out, &errout); code == 0 || out.Len() != 0 || errout.Len() == 0 || strings.Contains(errout.String(), "PRIVATE-MARKER") {
			t.Fatalf("invalid flags code=%d output=%s err=%s", code, &out, &errout)
		}
	}
}
func TestRunDryRunAndSelectionSourceDeterminism(t *testing.T) {
	db := filepath.Join(t.TempDir(), "never-created", "security.db")
	code, out, errout := execute(t, append(args(), "--dry-run", "--db", db), testReport)
	if code != 0 || errout != "" {
		t.Fatalf("dry-run=%d %s", code, errout)
	}
	a := decode(t, out)
	if !a.DryRun || a.Replay || a.Entries != 1 || !validUUID(a.RunID) || strings.Contains(out, "CVE-") {
		t.Fatalf("summary=%+v", a)
	}
	absent(t, filepath.Dir(db))
	_, out, _ = execute(t, append(args(), "--dry-run"), testReport)
	if decode(t, out).RunID != a.RunID {
		t.Fatal("default ID not deterministic")
	}
	_, out, _ = execute(t, append(args(), "--dry-run"), testReport+"\n")
	if decode(t, out).RunID == a.RunID {
		t.Fatal("bytes not bound")
	}
	b := []string{"--input", "-", "--source", "epss", "--cves", "CVE-2026-0002,CVE-2026-0001", "--observed-at", testObservedAt, "--dry-run"}
	_, out, _ = execute(t, b, testReport)
	if decode(t, out).RunID == a.RunID {
		t.Fatal("selection not bound")
	}
	b[5] = "cve-2026-0001,CVE-2026-0002,CVE-2026-0001"
	_, canonical, _ := execute(t, b, testReport)
	if decode(t, canonical).RunID != decode(t, out).RunID {
		t.Fatal("canonical selection changed ID")
	}
	kev := []string{"--input", "-", "--source", "kev", "--cves", "CVE-2026-0001", "--observed-at", testObservedAt, "--dry-run"}
	if code, out, e := execute(t, kev, testKEV); code != 0 || e != "" || decode(t, out).Entries != 1 {
		t.Fatalf("kev=%d %s %s", code, out, e)
	}
}
func TestRunInvalidFeedNeverOpensExistingOrNewDatabase(t *testing.T) {
	for _, input := range []string{"", `{"PRIVATE-MARKER":`, strings.Replace(testReport, "0.25", "NaN", 1), strings.Replace(testReport, "score_date:2026-11-07", "score_date:2099-01-01", 1), strings.Repeat(" ", maxInputBytes+1)} {
		dir := t.TempDir()
		db := filepath.Join(dir, "existing.db")
		original := []byte("synthetic-not-database-PRIVATE-MARKER")
		if err := os.WriteFile(db, original, 0600); err != nil {
			t.Fatal(err)
		}
		code, out, e := execute(t, append(args(), "--db", db), input)
		if code == 0 || out != "" || e == "" || strings.Contains(e, "PRIVATE-MARKER") {
			t.Fatal("invalid input accepted or leaked")
		}
		after, err := os.ReadFile(db)
		if err != nil || !bytes.Equal(original, after) {
			t.Fatal("invalid input opened DB")
		}
		fresh := filepath.Join(dir, "new.db")
		code, _, _ = execute(t, append(args(), "--db", fresh), input)
		if code == 0 {
			t.Fatal("invalid accepted")
		}
		absent(t, fresh)
	}
}
func TestRunImportReplayConflictsAndNoLegacyMutation(t *testing.T) {
	db := filepath.Join(t.TempDir(), "security.db")
	a := append(args(), "--db", db)
	code, out, e := execute(t, a, testReport)
	if code != 0 || e != "" {
		t.Fatalf("import=%d %s", code, e)
	}
	first := decode(t, out)
	if first.Replay || first.DryRun || first.Entries != 1 {
		t.Fatalf("first=%+v", first)
	}
	code, out, e = execute(t, a, testReport)
	if code != 0 || e != "" || !decode(t, out).Replay {
		t.Fatal("replay failed")
	}
	explicit := append(a, "--run-id", first.RunID)
	for _, input := range []string{testReport + "\n", strings.Replace(testReport, "0.25", "0.9", 1)} {
		if code, out, e := execute(t, explicit, input); code == 0 || out != "" || e == "" {
			t.Fatal("reused ID accepted changed evidence")
		}
	}
	changed := []string{"--input", "-", "--source", "epss", "--cves", "CVE-2026-0001", "--observed-at", "2026-11-07T21:00:00Z", "--db", db}
	if code, _, _ := execute(t, changed, testReport); code == 0 {
		t.Fatal("default ID silently refreshed timestamp")
	}
	s, err := store.NewWithPath(db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	runs, err := s.QueryIngestRuns(context.Background())
	if err != nil || len(runs) != 1 || runs[0].Coverage != "partial" {
		t.Fatalf("runs=%+v %v", runs, err)
	}
	findings, err := s.QueryFindings(context.Background())
	if err != nil || len(findings) != 0 || len(s.List()) != 0 {
		t.Fatal("enrichment created/changed findings or alerts")
	}
}
func TestRunMissingSelectedCVEIsNotZeroOrNegative(t *testing.T) {
	a := []string{"--input", "-", "--source", "epss", "--cves", "CVE-2026-0002", "--observed-at", testObservedAt, "--dry-run"}
	code, out, e := execute(t, a, testReport)
	if code != 0 || e != "" || decode(t, out).Entries != 0 {
		t.Fatalf("missing=%d %s %s", code, out, e)
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-MARKER") }

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("PRIVATE-MARKER") }
func TestRunSanitizesIOErrorsAndReleasesFile(t *testing.T) {
	var out, e bytes.Buffer
	if code := run(append(args(), "--dry-run"), failedReader{}, &out, &e); code == 0 || strings.Contains(e.String(), "PRIVATE-MARKER") {
		t.Fatal("read error leaked")
	}
	e.Reset()
	if code := run(append(args(), "--dry-run"), strings.NewReader(testReport), failedWriter{}, &e); code == 0 || strings.Contains(e.String(), "PRIVATE-MARKER") {
		t.Fatal("write error leaked")
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "feed.csv")
	if err := os.WriteFile(input, []byte(testReport), 0600); err != nil {
		t.Fatal(err)
	}
	a := args()
	a[1] = input
	code, _, errout := execute(t, append(a, "--dry-run"), "")
	if code != 0 || errout != "" {
		t.Fatal("file input failed")
	}
	if err := os.Rename(input, input+".closed"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	e.Reset()
	if code := run([]string{"--help"}, noRead{t}, &out, &e); code != 0 || !strings.Contains(out.String(), "may be created or migrated") {
		t.Fatal("help failed")
	}
}

func TestRunRejectsUNCAndDevicePathsBeforeInputAccess(t *testing.T) {
	for _, path := range []string{`\\server\share\feed.csv`, `//server/share/feed.csv`, `\/server/share/feed.csv`, `/\server\share\feed.csv`, `\\?\C:\feed.csv`, `\\.\pipe\synthetic`} {
		if localPath(path) {
			t.Fatalf("network/device path accepted by local validator: %q", path)
		}
		for _, target := range []string{"input", "database"} {
			t.Run(target+path, func(t *testing.T) {
				a := args()
				if target == "input" {
					a[1] = path
					a = append(a, "--dry-run")
				} else {
					a = append(a, "--db", path)
				}
				var out, errout bytes.Buffer
				if code := run(a, noRead{t: t}, &out, &errout); code == 0 || out.Len() != 0 || errout.Len() == 0 {
					t.Fatalf("network path accepted: code=%d", code)
				}
			})
		}
	}
}
