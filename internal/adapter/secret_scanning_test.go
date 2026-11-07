package adapter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// Every value here is synthetic. Never use real secret material in fixtures.
const secretScanningFixture = `[{"number":42,"state":"open","secret_type":"synthetic_example","secret":null,"html_url":"https://github.com/example/repo/security/secret-scanning/42","secret_type_display_name":"PRIVATE-SYNTHETIC-MARKER","resolution_comment":"PRIVATE-SYNTHETIC-MARKER","resolved_by":{"login":"PRIVATE-SYNTHETIC-MARKER"},"first_location_detected":{"path":"PRIVATE-SYNTHETIC-MARKER","blob_url":"https://invalid.test/?token=PRIVATE-SYNTHETIC-MARKER"},"validity":"active","assigned_to":{"login":"PRIVATE-SYNTHETIC-MARKER"}}]`

func secretScanningOptions() SecretScanningOptions {
	return SecretScanningOptions{Repository: "Example/Repo", RunID: "00000000-0000-8000-8000-000000000001", ObservedAt: time.Date(2026, 11, 7, 20, 0, 0, 0, time.UTC)}
}

func parseSecretScanning(t *testing.T, input string) []model.SecurityFinding {
	t.Helper()
	items, err := ParseSecretScanningJSON(strings.NewReader(input), secretScanningOptions())
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func TestParseSecretScanningProjectsOnlySafeMetadataAndSharesAsset(t *testing.T) {
	items := parseSecretScanning(t, secretScanningFixture)
	if len(items) != 1 {
		t.Fatalf("items=%d", len(items))
	}
	x := items[0]
	if x.Asset.NativeID != "example/repo" || x.Asset.Provider != "github" || x.Finding.Category != "secret_scanning" || x.Finding.SecretType != "synthetic_example" || x.Finding.SecretResolution != "" || x.Finding.Severity != "unknown" || x.Finding.SourceStatus != model.SourceStatusActive || x.Observation.Source != "github_secret_scanning" || x.Observation.RawRef != "https://github.com/example/repo/security/secret-scanning/42" {
		t.Fatalf("normalized=%+v", x)
	}
	body, err := json.Marshal(x)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "PRIVATE-SYNTHETIC-MARKER") || x.Finding.FilePath != "" || x.Finding.RuleID != "" {
		t.Fatal("excluded metadata retained")
	}
	dep, err := NormalizeDependabot(model.AlertRecord{Alert: model.Alert{Owner: "Example", Repo: "Repo", Number: 42}}, "run", secretScanningOptions().ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	code := parseCodeScanning(t, codeScanningFixture)[0]
	if x.Asset.ID != dep.Asset.ID || x.Asset.ID != code.Asset.ID || x.Finding.ID == dep.Finding.ID || x.Finding.ID == code.Finding.ID {
		t.Fatal("source finding isolation or shared asset identity violated")
	}
	opts := secretScanningOptions()
	opts.Repository = "example/other"
	other, err := ParseSecretScanningJSON(strings.NewReader(strings.ReplaceAll(secretScanningFixture, "example/repo", "example/other")), opts)
	if err != nil || other[0].Finding.ID == x.Finding.ID {
		t.Fatal("repository finding identities collided")
	}
	ignoredChanged := strings.ReplaceAll(secretScanningFixture, "PRIVATE-SYNTHETIC-MARKER", "ANOTHER-SYNTHETIC-MARKER")
	ignoredChanged = strings.Replace(ignoredChanged, `"validity":"active"`, `"validity":"inactive"`, 1)
	if changed := parseSecretScanning(t, ignoredChanged)[0]; changed != x {
		t.Fatal("ignored private metadata or validity changed projection")
	}
}

func TestParseSecretScanningLifecycleDoesNotEquateResolutionWithRevocation(t *testing.T) {
	original := parseSecretScanning(t, secretScanningFixture)[0]
	for _, tt := range []struct {
		resolution string
		status     model.SourceStatus
	}{{"revoked", model.SourceStatusResolved}, {"false_positive", model.SourceStatusSuppressed}, {"wont_fix", model.SourceStatusSuppressed}, {"used_in_tests", model.SourceStatusSuppressed}, {"pattern_edited", model.SourceStatusSuppressed}, {"pattern_deleted", model.SourceStatusSuppressed}} {
		input := strings.Replace(secretScanningFixture, `"state":"open"`, `"state":"resolved","resolution":"`+tt.resolution+`"`, 1)
		got := parseSecretScanning(t, input)[0]
		if got.Finding.ID != original.Finding.ID || got.Finding.SourceStatus != tt.status || got.Finding.SecretResolution != tt.resolution || got.Finding.TriageStatus != model.TriageStatusNew || got.Observation.Fingerprint == original.Observation.Fingerprint {
			t.Fatalf("resolution=%s got=%+v", tt.resolution, got.Finding)
		}
	}
	opts := secretScanningOptions()
	opts.RunID = "another-run"
	opts.ObservedAt = opts.ObservedAt.Add(time.Hour)
	next, err := ParseSecretScanningJSON(strings.NewReader(secretScanningFixture), opts)
	if err != nil || next[0].Finding.ID != original.Finding.ID || next[0].Observation.Fingerprint != original.Observation.Fingerprint || next[0].Observation.ID == original.Observation.ID {
		t.Fatal("observation time or run changed native identity/evidence")
	}
}

func TestParseSecretScanningRejectsLiteralSecretBeforeReturningAnyItems(t *testing.T) {
	for _, secret := range []string{`"SYNTHETIC-REJECTED-VALUE"`, `"***"`, `" "`, `{}`, `[]`, `123`, `true`} {
		input := strings.Replace(secretScanningFixture, `"secret":null`, `"secret":`+secret, 1)
		got, err := ParseSecretScanningJSON(strings.NewReader(input), secretScanningOptions())
		if err == nil || len(got) != 0 || strings.Contains(err.Error(), "SYNTHETIC-REJECTED-VALUE") {
			t.Fatalf("literal/type accepted or error leaked (type=%s)", secret)
		}
	}
	for _, member := range []string{`"secret":"SYNTHETIC-REJECTED-VALUE","secret":null`, `"Secret":"SYNTHETIC-REJECTED-VALUE"`, `"secr\u0065t":"SYNTHETIC-REJECTED-VALUE"`} {
		input := strings.Replace(secretScanningFixture, `"secret":null`, member, 1)
		if _, err := ParseSecretScanningJSON(strings.NewReader(input), secretScanningOptions()); err == nil {
			t.Fatal("alternate/duplicate literal secret bypassed validation")
		}
	}
	for _, replacement := range []string{"", `"secret":"",`} {
		parseSecretScanning(t, strings.Replace(secretScanningFixture, `"secret":null,`, replacement, 1))
	}
	valid := strings.Trim(secretScanningFixture, "[]")
	bad := strings.Replace(valid, `"secret":null`, `"secret":"SYNTHETIC-REJECTED-VALUE"`, 1)
	if got, err := ParseSecretScanningJSON(strings.NewReader("["+valid+","+bad+"]"), secretScanningOptions()); err == nil || len(got) != 0 {
		t.Fatal("valid prefix escaped literal-secret rejection")
	}
}

func TestParseSecretScanningBoundsScopeAndSanitizedErrors(t *testing.T) {
	for _, input := range []string{"", "null", "{}", "[null]", "[[]]", secretScanningFixture + "[]", string([]byte{0xff}), strings.Repeat(" ", 10<<20) + secretScanningFixture,
		strings.Replace(secretScanningFixture, `"number":42`, `"number":0`, 1),
		strings.Replace(secretScanningFixture, `"number":42`, `"number":1.5`, 1),
		strings.Replace(secretScanningFixture, `"state":"open"`, `"state":"PRIVATE-SYNTHETIC-MARKER"`, 1),
		strings.Replace(secretScanningFixture, `"state":"open"`, `"state":"resolved"`, 1),
		strings.Replace(secretScanningFixture, `"state":"open"`, `"state":"open","resolution":"revoked"`, 1),
		strings.Replace(secretScanningFixture, `"state":"open"`, `"state":"resolved","resolution":"future_unknown"`, 1),
		strings.Replace(secretScanningFixture, "synthetic_example", "invalid/PRIVATE-SYNTHETIC-MARKER", 1),
		strings.Replace(secretScanningFixture, "synthetic_example", strings.Repeat("a", 129), 1),
		strings.Replace(secretScanningFixture, "https://github.com/example/repo/security/secret-scanning/42", "https://github.com/other/repo/security/secret-scanning/42", 1),
		strings.Replace(secretScanningFixture, "https://github.com/example/repo/security/secret-scanning/42", "https://github.com/example/repo/security/secret-scanning/42?token=PRIVATE-SYNTHETIC-MARKER", 1)} {
		items, err := ParseSecretScanningJSON(strings.NewReader(input), secretScanningOptions())
		if err == nil || len(items) != 0 {
			t.Fatalf("invalid input accepted len=%d", len(input))
		}
		if strings.Contains(err.Error(), "PRIVATE-SYNTHETIC-MARKER") {
			t.Fatal("error leaks input")
		}
	}
	for _, repo := range []string{"", "a", "a/b/c", "a/..", "a/repo?x", "a/repo\u200b"} {
		opts := secretScanningOptions()
		opts.Repository = repo
		if _, err := ParseSecretScanningJSON(strings.NewReader("[]"), opts); err == nil {
			t.Fatalf("invalid repo=%q", repo)
		}
	}
	if _, err := ParseSecretScanningJSON(nil, secretScanningOptions()); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := ParseSecretScanningJSON(secretScanningErrorReader{}, secretScanningOptions()); err == nil || strings.Contains(err.Error(), "PRIVATE-SYNTHETIC-MARKER") {
		t.Fatal("reader error not sanitized")
	}
	entry := `{"number":42,"state":"open","secret_type":"synthetic_example"}`
	if got := parseSecretScanning(t, "["+strings.Repeat(entry+",", 19999)+entry+"]"); len(got) != 1 {
		t.Fatal("exact boundary or duplicates failed")
	}
	if _, err := ParseSecretScanningJSON(strings.NewReader("["+strings.Repeat(entry+",", 20000)+entry+"]"), secretScanningOptions()); err == nil {
		t.Fatal("entry bound not enforced")
	}
	if got := parseSecretScanning(t, "[]"); len(got) != 0 {
		t.Fatal("empty report not empty")
	}
	changed := strings.Replace(entry, `"state":"open"`, `"state":"resolved","resolution":"revoked"`, 1)
	if _, err := ParseSecretScanningJSON(strings.NewReader("["+entry+","+changed+"]"), secretScanningOptions()); err == nil {
		t.Fatal("conflicting duplicate accepted")
	}
}

type secretScanningErrorReader struct{}

func (secretScanningErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("PRIVATE-SYNTHETIC-MARKER")
}

func FuzzParseSecretScanningJSON(f *testing.F) {
	f.Add(secretScanningFixture)
	f.Add("[]")
	f.Add(`[ {"secret":"SYNTHETIC-REJECTED-VALUE"} ]`)
	f.Fuzz(func(t *testing.T, input string) {
		items, err := ParseSecretScanningJSON(strings.NewReader(input), secretScanningOptions())
		if err != nil && len(items) != 0 {
			t.Fatal("partial results after error")
		}
	})
}
