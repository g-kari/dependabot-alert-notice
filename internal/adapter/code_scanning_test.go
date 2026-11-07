package adapter

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

const codeScanningFixture = `[{"number":42,"state":"open","html_url":"https://github.com/example/repo/security/code-scanning/42","url":"https://attacker.invalid/?token=PRIVATE-TOKEN","rule":{"id":"go/example","name":"PRIVATE-TOKEN","description":"PRIVATE-TOKEN","severity":"error","security_severity_level":"high","tags":["PRIVATE-TOKEN"]},"tool":{"name":"CodeQL","guid":"","version":"PRIVATE-TOKEN"},"most_recent_instance":{"ref":"PRIVATE-TOKEN","message":{"text":"PRIVATE-TOKEN"},"location":{"path":"src/example.go","start_line":12,"end_line":14}},"dismissed_comment":"PRIVATE-TOKEN","dismissed_by":{"login":"PRIVATE-TOKEN"}}]`

func codeScanningOptions() CodeScanningOptions {
	return CodeScanningOptions{Repository: "Example/Repo", RunID: "00000000-0000-8000-8000-000000000001", ObservedAt: time.Date(2026, 11, 7, 18, 0, 0, 0, time.UTC)}
}
func parseCodeScanning(t *testing.T, input string) []model.SecurityFinding {
	t.Helper()
	items, err := ParseCodeScanningJSON(strings.NewReader(input), codeScanningOptions())
	if err != nil {
		t.Fatal(err)
	}
	return items
}
func TestParseCodeScanningProjectsSafeMetadataAndSharesRepositoryAsset(t *testing.T) {
	got := parseCodeScanning(t, codeScanningFixture)
	if len(got) != 1 {
		t.Fatalf("items=%d", len(got))
	}
	item := got[0]
	if item.Asset.Provider != "github" || item.Asset.NativeID != "example/repo" || item.Asset.Account != "example" || item.Finding.Category != "code_scanning" || item.Finding.RuleID != "go/example" || item.Finding.ToolName != "CodeQL" || item.Finding.FilePath != "src/example.go" || item.Finding.StartLine != 12 || item.Finding.Severity != model.SeverityHigh || item.Observation.Source != "github_code_scanning" {
		t.Fatalf("normalized=%+v", item)
	}
	if item.Observation.RawRef != "https://github.com/example/repo/code-scanning/42" {
		t.Fatalf("reference=%q", item.Observation.RawRef)
	}
	body, _ := json.Marshal(item)
	if strings.Contains(string(body), "PRIVATE-TOKEN") {
		t.Fatalf("sensitive input retained: %s", body)
	}
	dep, err := NormalizeDependabot(model.AlertRecord{Alert: model.Alert{Owner: "Example", Repo: "Repo", Number: 42}}, "run", codeScanningOptions().ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if dep.Asset.ID != item.Asset.ID || dep.Finding.ID == item.Finding.ID {
		t.Fatal("repository asset not shared or source identities merged")
	}
}
func TestParseCodeScanningLifecycleSeverityAndStableIdentity(t *testing.T) {
	original := parseCodeScanning(t, codeScanningFixture)[0]
	for _, tt := range []struct {
		state string
		want  model.SourceStatus
	}{{"open", model.SourceStatusActive}, {"fixed", model.SourceStatusResolved}, {"dismissed", model.SourceStatusSuppressed}} {
		input := strings.Replace(codeScanningFixture, `"state":"open"`, `"state":"`+tt.state+`"`, 1)
		got := parseCodeScanning(t, input)[0]
		if got.Finding.SourceStatus != tt.want || got.Finding.TriageStatus != model.TriageStatusNew || got.Finding.ID != original.Finding.ID {
			t.Fatalf("state=%s got=%+v", tt.state, got.Finding)
		}
		if tt.state != "open" && got.Observation.Fingerprint == original.Observation.Fingerprint {
			t.Fatal("lifecycle excluded from fingerprint")
		}
	}
	for _, tt := range []struct {
		security, severity string
		want               model.Severity
	}{{"critical", "warning", model.SeverityCritical}, {"medium", "error", model.SeverityMedium}, {"low", "error", model.SeverityLow}, {"", "error", "unknown"}, {"", "warning", "unknown"}, {"", "note", "unknown"}} {
		input := strings.Replace(codeScanningFixture, `"security_severity_level":"high"`, `"security_severity_level":"`+tt.security+`"`, 1)
		input = strings.Replace(input, `"severity":"error"`, `"severity":"`+tt.severity+`"`, 1)
		if got := parseCodeScanning(t, input)[0]; got.Finding.Severity != tt.want {
			t.Fatalf("security=%s severity=%s got=%s", tt.security, tt.severity, got.Finding.Severity)
		}
	}
	changed := strings.Replace(codeScanningFixture, `"path":"src/example.go"`, `"path":"moved/example.go"`, 1)
	if got := parseCodeScanning(t, changed)[0]; got.Finding.ID != original.Finding.ID || got.Observation.Fingerprint == original.Observation.Fingerprint {
		t.Fatal("location changed native identity or failed to update evidence")
	}
	opts := codeScanningOptions()
	opts.Repository = "example/other"
	otherInput := strings.Replace(codeScanningFixture, "https://github.com/example/repo/security/code-scanning/42", "https://github.com/example/other/security/code-scanning/42", 1)
	other, err := ParseCodeScanningJSON(strings.NewReader(otherInput), opts)
	if err != nil || other[0].Finding.ID == original.Finding.ID {
		t.Fatal("repository identities collided")
	}
}
func TestParseCodeScanningRejectsInvalidAndBoundsWithoutLeaking(t *testing.T) {
	for _, input := range []string{"", "null", "{}", "[null]", "[[]]", codeScanningFixture + "[]", strings.Replace(codeScanningFixture, `"html_url":"https://github.com/example/repo/security/code-scanning/42"`, `"html_url":"https://github.com/other/repo/security/code-scanning/42"`, 1), strings.Replace(codeScanningFixture, `"number":42`, `"number":0`, 1), strings.Replace(codeScanningFixture, `"number":42`, `"number":1.5`, 1), strings.Replace(codeScanningFixture, `"state":"open"`, `"state":"PRIVATE-TOKEN"`, 1), strings.Replace(codeScanningFixture, `"security_severity_level":"high"`, `"security_severity_level":"PRIVATE-TOKEN"`, 1), strings.Replace(codeScanningFixture, `"id":"go/example"`, `"id":""`, 1), strings.Replace(codeScanningFixture, `"name":"CodeQL"`, `"name":"CodeQL\nPRIVATE-TOKEN"`, 1), strings.Replace(codeScanningFixture, `"path":"src/example.go"`, `"path":"../PRIVATE-TOKEN"`, 1), strings.Replace(codeScanningFixture, `"path":"src/example.go"`, `"path":"/PRIVATE-TOKEN"`, 1), strings.Replace(codeScanningFixture, `"start_line":12`, `"start_line":-1`, 1), strings.Repeat(" ", 10<<20) + codeScanningFixture, string([]byte{0xff})} {
		got, err := ParseCodeScanningJSON(strings.NewReader(input), codeScanningOptions())
		if err == nil || len(got) != 0 {
			t.Fatalf("invalid input accepted (len=%d)", len(input))
		}
		if strings.Contains(err.Error(), "PRIVATE-TOKEN") {
			t.Fatal("error leaked input")
		}
	}
	for _, repo := range []string{"", "owner", "a/b/c", "a/..", "./repo", "a/repo?token=x", "a/repo#x", "a/repo\u200b", "a/repo ", "a/repo%2fother"} {
		opts := codeScanningOptions()
		opts.Repository = repo
		if _, err := ParseCodeScanningJSON(strings.NewReader("[]"), opts); err == nil {
			t.Fatalf("invalid repo=%q", repo)
		}
	}
	if got := parseCodeScanning(t, "[]"); len(got) != 0 {
		t.Fatal("empty snapshot not empty")
	}
	if _, err := ParseCodeScanningJSON(nil, codeScanningOptions()); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := ParseCodeScanningJSON(codeScanningErrorReader{}, codeScanningOptions()); err == nil || strings.Contains(err.Error(), "PRIVATE-TOKEN") {
		t.Fatal("reader error not sanitized")
	}
	entry := `{"number":42,"state":"open","rule":{"id":"go/example"},"tool":{"name":"CodeQL"}}`
	array := "[" + strings.Repeat(entry+",", 19999) + entry + "]"
	if got := parseCodeScanning(t, array); len(got) != 1 {
		t.Fatal("exact entry boundary rejected")
	}
	array = "[" + strings.Repeat(entry+",", 20000) + entry + "]"
	if _, err := ParseCodeScanningJSON(strings.NewReader(array), codeScanningOptions()); err == nil {
		t.Fatal("entry limit not enforced")
	}
}

type codeScanningErrorReader struct{}

func (codeScanningErrorReader) Read([]byte) (int, error) { return 0, errors.New("PRIVATE-TOKEN") }

var _ io.Reader = codeScanningErrorReader{}

func TestParseCodeScanningDuplicateAndRunEvidence(t *testing.T) {
	one := strings.Trim(codeScanningFixture, "[]")
	if got := parseCodeScanning(t, "["+one+","+one+"]"); len(got) != 1 {
		t.Fatal("exact duplicate not deduplicated")
	}
	changed := strings.Replace(one, `"state":"open"`, `"state":"fixed"`, 1)
	if _, err := ParseCodeScanningJSON(strings.NewReader("["+one+","+changed+"]"), codeScanningOptions()); err == nil {
		t.Fatal("conflicting duplicate accepted")
	}
	original := parseCodeScanning(t, codeScanningFixture)[0]
	opts := codeScanningOptions()
	opts.RunID = "new-run"
	next, err := ParseCodeScanningJSON(strings.NewReader(codeScanningFixture), opts)
	if err != nil {
		t.Fatal(err)
	}
	if next[0].Finding.ID != original.Finding.ID || next[0].Observation.ID == original.Observation.ID || next[0].Observation.Fingerprint != original.Observation.Fingerprint {
		t.Fatal("run identity/evidence contract violated")
	}
}
func FuzzParseCodeScanningJSON(f *testing.F) {
	f.Add(codeScanningFixture)
	f.Add("[]")
	f.Add("[null]")
	f.Fuzz(func(t *testing.T, input string) {
		items, err := ParseCodeScanningJSON(strings.NewReader(input), codeScanningOptions())
		if err != nil && len(items) != 0 {
			t.Fatal("partial output on failure")
		}
	})
}

func TestParseCodeScanningAcceptsDocumentedAndCurrentURLForms(t *testing.T) {
	current := parseCodeScanning(t, codeScanningFixture)[0]
	documented := parseCodeScanning(t, strings.Replace(codeScanningFixture, "/security/code-scanning/42", "/code-scanning/42", 1))[0]
	if current != documented {
		t.Fatal("URL route alias changed normalized evidence")
	}
}
