package adapter

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func trivyTestOptions() TrivyOptions {
	return TrivyOptions{Scope: "synthetic-ci", RunID: "trivy-run-1", ObservedAt: time.Date(2026, 11, 5, 14, 0, 0, 0, time.FixedZone("test", 3600))}
}

func trivyTestReport(t *testing.T) map[string]any {
	t.Helper()
	body, err := os.ReadFile("testdata/trivy-v2-synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func trivyTestResult(report map[string]any) map[string]any {
	return report["Results"].([]any)[0].(map[string]any)
}

func trivyTestVulnerability(report map[string]any) map[string]any {
	return trivyTestResult(report)["Vulnerabilities"].([]any)[0].(map[string]any)
}

func trivyTestJSON(t *testing.T, report map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func parseTrivyForTest(t *testing.T, report map[string]any, options TrivyOptions) []model.SecurityFinding {
	t.Helper()
	got, err := ParseTrivyJSON(bytes.NewReader(trivyTestJSON(t, report)), options)
	if err != nil {
		t.Fatalf("ParseTrivyJSON synthetic report: %v", err)
	}
	return got
}

func TestParseTrivyJSONMapsVulnerabilitiesWithoutTreatingFixAvailabilityAsResolution(t *testing.T) {
	options := trivyTestOptions()
	got := parseTrivyForTest(t, trivyTestReport(t), options)
	if len(got) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(got))
	}
	a, f, o := got[0].Asset, got[0].Finding, got[0].Observation
	if a.Type != "container_image" || a.Provider != "trivy" || a.Account != options.Scope || a.NativeID != "sha256:"+strings.Repeat("a", 64) || a.Environment != "" {
		t.Errorf("asset = %+v, want explicitly scoped immutable image", a)
	}
	if f.Category != "vulnerability" || f.AssetID != a.ID || f.Severity != model.SeverityHigh || f.SourceStatus != model.SourceStatusActive || f.TriageStatus != model.TriageStatusNew {
		t.Errorf("finding = %+v, want active vulnerability independent of Trivy Status=fixed", f)
	}
	if f.VulnerabilityID != "CVE-2099-0001" || f.PackageName != "synthetic-package" || f.PackageEcosystem != "npm" || f.InstalledVersion != "1.0.0" || f.FixedVersion != "1.0.1" || f.Title != "Synthetic vulnerability for offline adapter tests" {
		t.Errorf("finding detail fields = %+v", f)
	}
	if f.CanonicalKey != `["CVE-2099-0001","npm","synthetic-package","package-lock.json"]` {
		t.Errorf("canonical key = %q, want JSON advisory/ecosystem/package/path tuple", f.CanonicalKey)
	}
	if o.Source != "trivy" || o.Account != options.Scope || o.SourceFindingID == "" || o.FindingID != f.ID || o.IngestRunID != options.RunID || o.RawRef != "https://example.invalid/advisories/CVE-2099-0001" || len(o.Fingerprint) != 64 {
		t.Errorf("observation = %+v, want scoped selected source evidence", o)
	}
	if !f.FirstSeen.Equal(options.ObservedAt) || !f.LastSeen.Equal(options.ObservedAt) || !o.ObservedAt.Equal(options.ObservedAt) || o.ObservedAt.Location() != time.UTC {
		t.Errorf("timestamps = %v/%v/%v, want explicit observed time in UTC", f.FirstSeen, f.LastSeen, o.ObservedAt)
	}
}

func TestParseTrivyJSONHasDeterministicAssetAndPackageScopedIdentity(t *testing.T) {
	options := trivyTestOptions()
	original := parseTrivyForTest(t, trivyTestReport(t), options)[0]
	if repeated := parseTrivyForTest(t, trivyTestReport(t), options)[0]; !reflect.DeepEqual(original, repeated) {
		t.Fatal("identical input changed normalized output")
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]any, *TrivyOptions)
	}{
		{"scope", func(_ map[string]any, o *TrivyOptions) { o.Scope = "other-ci" }},
		{"image", func(r map[string]any, _ *TrivyOptions) {
			r["Metadata"].(map[string]any)["ImageID"] = "sha256:" + strings.Repeat("b", 64)
		}},
		{"target", func(r map[string]any, _ *TrivyOptions) { trivyTestResult(r)["Target"] = "nested/package-lock.json" }},
		{"class", func(r map[string]any, _ *TrivyOptions) { trivyTestResult(r)["Class"] = "os-pkgs" }},
		{"type", func(r map[string]any, _ *TrivyOptions) { trivyTestResult(r)["Type"] = "alpine" }},
		{"package", func(r map[string]any, _ *TrivyOptions) { trivyTestVulnerability(r)["PkgName"] = "another-package" }},
		{"package ID", func(r map[string]any, _ *TrivyOptions) { trivyTestVulnerability(r)["PkgID"] = "another-instance" }},
		{"package identifier", func(r map[string]any, _ *TrivyOptions) {
			trivyTestVulnerability(r)["PkgIdentifier"] = map[string]any{"PURL": "pkg:npm/synthetic-package@1.0.0?arch=arm64", "UID": "synthetic-arm64"}
		}},
		{"package path", func(r map[string]any, _ *TrivyOptions) {
			trivyTestVulnerability(r)["PkgPath"] = "node_modules/other/package.json"
		}},
		{"installed version", func(r map[string]any, _ *TrivyOptions) { trivyTestVulnerability(r)["InstalledVersion"] = "0.9.0" }},
		{"advisory", func(r map[string]any, _ *TrivyOptions) {
			trivyTestVulnerability(r)["VulnerabilityID"] = "CVE-2099-0002"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, options := trivyTestReport(t), trivyTestOptions()
			tc.change(r, &options)
			changed := parseTrivyForTest(t, r, options)[0]
			if original.Finding.ID == changed.Finding.ID || original.Observation.SourceFindingID == changed.Observation.SourceFindingID {
				t.Errorf("%s reused native finding identity", tc.name)
			}
		})
	}
	options.RunID = "trivy-run-2"
	options.ObservedAt = options.ObservedAt.Add(time.Hour)
	nextRun := parseTrivyForTest(t, trivyTestReport(t), options)[0]
	if original.Finding.ID != nextRun.Finding.ID || original.Observation.ID == nextRun.Observation.ID || original.Observation.Fingerprint != nextRun.Observation.Fingerprint {
		t.Fatal("new run must retain native finding identity and separate observations")
	}
	for _, field := range []string{"Title", "FixedVersion", "Severity"} {
		r := trivyTestReport(t)
		value := "changed"
		if field == "Severity" {
			value = "CRITICAL"
		}
		trivyTestVulnerability(r)[field] = value
		changed := parseTrivyForTest(t, r, trivyTestOptions())[0]
		if original.Finding.ID != changed.Finding.ID || original.Observation.Fingerprint == changed.Observation.Fingerprint || original.Observation.ID == changed.Observation.ID {
			t.Errorf("changed %s should update evidence without replacing identity", field)
		}
	}
}

func TestParseTrivyJSONDoesNotRetainOrFingerprintSecretsConfigsAndUnknownPayloads(t *testing.T) {
	r := trivyTestReport(t)
	original := parseTrivyForTest(t, r, trivyTestOptions())
	const marker = "SYNTHETIC_DO_NOT_PERSIST"
	r["Metadata"].(map[string]any)["ImageConfig"] = map[string]any{"Env": []string{"TOKEN=" + marker}}
	trivyTestResult(r)["Secrets"] = []any{map[string]any{"Match": marker, "Code": map[string]any{"Lines": []any{marker}}}}
	trivyTestResult(r)["Misconfigurations"] = []any{map[string]any{"CauseMetadata": map[string]any{"Code": marker}}}
	trivyTestResult(r)["Licenses"] = []any{map[string]any{"Text": marker}}
	trivyTestVulnerability(r)["Description"] = marker
	trivyTestVulnerability(r)["Custom"] = map[string]any{"credential": marker}
	trivyTestVulnerability(r)["References"] = []string{"https://example.invalid/?token=" + marker}
	got := parseTrivyForTest(t, r, trivyTestOptions())
	if !reflect.DeepEqual(original, got) {
		t.Fatal("ignored secret/config/license/description/custom fields changed normalized evidence")
	}
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(marker)) {
		t.Fatal("ignored payload appeared in normalized data")
	}
}

func TestParseTrivyJSONAllowsOnlyCredentialFreeHTTPVulnerabilityReferences(t *testing.T) {
	for _, value := range []string{"javascript:alert(1)", "file:///tmp/report.json", "//example.invalid/advisory", "https://user:password@example.invalid/CVE", "https://example.invalid/CVE?token=synthetic", "https://example.invalid/CVE#synthetic", "https://example.invalid/CVE%0aInjected", "https:///missing-host", "https://example.invalid:bad/CVE"} {
		t.Run(value, func(t *testing.T) {
			r := trivyTestReport(t)
			trivyTestVulnerability(r)["PrimaryURL"] = value
			got := parseTrivyForTest(t, r, trivyTestOptions())
			if got[0].Observation.RawRef != "" {
				t.Errorf("unsafe PrimaryURL %q retained as %q", value, got[0].Observation.RawRef)
			}
		})
	}
}

func TestParseTrivyJSONUsesImmutableImageIdentityAndExplicitFilesystemScope(t *testing.T) {
	r := trivyTestReport(t)
	original := parseTrivyForTest(t, r, trivyTestOptions())[0]
	r["ArtifactName"] = "other-name:tag"
	r["Metadata"].(map[string]any)["RepoTags"] = []string{"other-name:tag"}
	if got := parseTrivyForTest(t, r, trivyTestOptions())[0]; got.Asset.ID != original.Asset.ID || got.Finding.ID != original.Finding.ID {
		t.Fatal("mutable tag changed immutable image identity")
	}
	delete(r["Metadata"].(map[string]any), "ImageID")
	r["Metadata"].(map[string]any)["RepoDigests"] = []string{"registry.invalid/service@sha256:" + strings.Repeat("a", 64)}
	if got := parseTrivyForTest(t, r, trivyTestOptions())[0]; got.Asset.ID != original.Asset.ID {
		t.Fatal("same immutable digest changed asset identity between ImageID and RepoDigests")
	}
	r["ArtifactType"], r["ArtifactName"] = "filesystem", "/synthetic/workspace"
	delete(r, "Metadata")
	filesystem := parseTrivyForTest(t, r, trivyTestOptions())[0]
	if filesystem.Asset.Type != "filesystem" || filesystem.Asset.NativeID != "/synthetic/workspace" || filesystem.Asset.ID == original.Asset.ID {
		t.Errorf("filesystem asset = %+v", filesystem.Asset)
	}
	options := trivyTestOptions()
	options.Scope = "other-ci"
	if got := parseTrivyForTest(t, r, options)[0]; got.Asset.ID == filesystem.Asset.ID {
		t.Fatal("same filesystem path in different scopes collided")
	}
}

func TestParseTrivyJSONAcceptsOnlyKnownSeveritiesAndNormalizesEcosystemHints(t *testing.T) {
	for _, severity := range []string{"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		r := trivyTestReport(t)
		trivyTestVulnerability(r)["Severity"] = severity
		got := parseTrivyForTest(t, r, trivyTestOptions())[0]
		if string(got.Finding.Severity) != strings.ToLower(severity) {
			t.Errorf("severity %q became %q", severity, got.Finding.Severity)
		}
	}
	for kind, want := range map[string]string{"npm": "npm", "yarn": "npm", "gomod": "go", "gobinary": "go", "pip": "pip", "poetry": "pip", "bundler": "rubygems", "cargo": "rust", "jar": "maven", "nuget": "nuget"} {
		r := trivyTestReport(t)
		trivyTestResult(r)["Type"] = kind
		got := parseTrivyForTest(t, r, trivyTestOptions())[0]
		if got.Finding.PackageEcosystem != want {
			t.Errorf("type %q ecosystem = %q, want %q", kind, got.Finding.PackageEcosystem, want)
		}
	}
}

func TestParseTrivyJSONRejectsInvalidRequiredFieldsWithoutPartialOutput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing schema", func(r map[string]any) { delete(r, "SchemaVersion") }},
		{"schema one", func(r map[string]any) { r["SchemaVersion"] = 1 }},
		{"schema string", func(r map[string]any) { r["SchemaVersion"] = "2" }},
		{"missing artifact type", func(r map[string]any) { delete(r, "ArtifactType") }},
		{"unsupported artifact", func(r map[string]any) { r["ArtifactType"] = "repository" }},
		{"mutable image only", func(r map[string]any) { delete(r, "Metadata") }},
		{"invalid image digest", func(r map[string]any) { r["Metadata"].(map[string]any)["ImageID"] = "sha256:short" }},
		{"ambiguous image digests", func(r map[string]any) {
			r["Metadata"] = map[string]any{"RepoDigests": []string{"one.invalid/image@sha256:" + strings.Repeat("a", 64), "two.invalid/image@sha256:" + strings.Repeat("b", 64)}}
		}},
		{"missing filesystem name", func(r map[string]any) { r["ArtifactType"] = "filesystem"; delete(r, "ArtifactName") }},
		{"missing target", func(r map[string]any) { delete(trivyTestResult(r), "Target") }},
		{"missing target in empty result", func(r map[string]any) {
			delete(trivyTestResult(r), "Target")
			delete(trivyTestResult(r), "Vulnerabilities")
		}},
		{"missing class", func(r map[string]any) { delete(trivyTestResult(r), "Class") }},
		{"invalid class", func(r map[string]any) { trivyTestResult(r)["Class"] = "secret" }},
		{"missing type", func(r map[string]any) { delete(trivyTestResult(r), "Type") }},
		{"missing advisory", func(r map[string]any) { delete(trivyTestVulnerability(r), "VulnerabilityID") }},
		{"missing package", func(r map[string]any) { delete(trivyTestVulnerability(r), "PkgName") }},
		{"missing installed version", func(r map[string]any) { delete(trivyTestVulnerability(r), "InstalledVersion") }},
		{"missing severity", func(r map[string]any) { delete(trivyTestVulnerability(r), "Severity") }},
		{"invalid severity", func(r map[string]any) { trivyTestVulnerability(r)["Severity"] = "URGENT" }},
		{"control in name", func(r map[string]any) { trivyTestVulnerability(r)["PkgName"] = "bad\nname" }},
		{"bidi in name", func(r map[string]any) { trivyTestVulnerability(r)["PkgName"] = "bad\u202ename" }},
		{"oversized field", func(r map[string]any) { trivyTestVulnerability(r)["Title"] = strings.Repeat("x", 4097) }},
		{"oversized results", func(r map[string]any) { r["Results"] = make([]any, 2049) }},
		{"oversized findings", func(r map[string]any) { trivyTestResult(r)["Vulnerabilities"] = make([]any, 20001) }},
		{"null result", func(r map[string]any) { r["Results"] = []any{nil} }},
		{"null vulnerability", func(r map[string]any) { trivyTestResult(r)["Vulnerabilities"] = []any{nil} }},
		{"valid then invalid", func(r map[string]any) {
			trivyTestResult(r)["Vulnerabilities"] = append(trivyTestResult(r)["Vulnerabilities"].([]any), map[string]any{"PkgName": "invalid"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := trivyTestReport(t)
			tc.change(r)
			got, err := ParseTrivyJSON(bytes.NewReader(trivyTestJSON(t, r)), trivyTestOptions())
			if err == nil || len(got) != 0 {
				t.Errorf("%s: findings=%d error=%v, want error and no partial output", tc.name, len(got), err)
			}
		})
	}
}

func TestParseTrivyJSONRequiresExplicitSafeRunScopeAndTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*TrivyOptions)
	}{
		{"empty scope", func(o *TrivyOptions) { o.Scope = "" }},
		{"whitespace scope", func(o *TrivyOptions) { o.Scope = "   " }},
		{"control scope", func(o *TrivyOptions) { o.Scope = "ci\nother" }},
		{"oversized scope", func(o *TrivyOptions) { o.Scope = strings.Repeat("x", 257) }},
		{"empty run", func(o *TrivyOptions) { o.RunID = "" }},
		{"control run", func(o *TrivyOptions) { o.RunID = "run\x00" }},
		{"empty time", func(o *TrivyOptions) { o.ObservedAt = time.Time{} }},
		{"UTC time out of range", func(o *TrivyOptions) { o.ObservedAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("test", 3600)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := trivyTestOptions()
			tc.change(&o)
			got, err := ParseTrivyJSON(bytes.NewReader(trivyTestJSON(t, trivyTestReport(t))), o)
			if err == nil || len(got) != 0 {
				t.Errorf("%s: findings=%d error=%v, want validation error", tc.name, len(got), err)
			}
		})
	}
}

func TestParseTrivyJSONRejectsMalformedOversizedAndMultipleDocuments(t *testing.T) {
	valid := trivyTestJSON(t, trivyTestReport(t))
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"empty", nil}, {"null", []byte("null")}, {"array", []byte("[]")},
		{"truncated", valid[:len(valid)-1]}, {"two documents", append(append([]byte(nil), valid...), valid...)},
		{"trailing garbage", append(append([]byte(nil), valid...), []byte("garbage")...)},
		{"over 10 MiB", bytes.Repeat([]byte(" "), (10<<20)+1)},
		{"invalid UTF8", append(append([]byte(nil), valid...), 0xff)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTrivyJSON(bytes.NewReader(tc.body), trivyTestOptions())
			if err == nil || len(got) != 0 {
				t.Errorf("%s: findings=%d error=%v, want safe failure", tc.name, len(got), err)
			}
		})
	}
	if _, err := ParseTrivyJSON(nil, trivyTestOptions()); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := ParseTrivyJSON(trivyFailingReader{}, trivyTestOptions()); err == nil {
		t.Fatal("reader failure accepted")
	}
}

type trivyFailingReader struct{}

func (trivyFailingReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

func TestParseTrivyJSONEmptyAndUnsupportedCategoriesProduceNoResolutionEvidence(t *testing.T) {
	for _, result := range []any{nil, []any{}, []any{map[string]any{"Target": "synthetic.txt", "Class": "secret", "Secrets": []any{map[string]any{"Match": "SYNTHETIC_DO_NOT_STORE"}}}}} {
		r := trivyTestReport(t)
		r["Results"] = result
		got := parseTrivyForTest(t, r, trivyTestOptions())
		if len(got) != 0 {
			t.Errorf("empty/unsupported results produced %d findings", len(got))
		}
	}
	r := trivyTestReport(t)
	delete(r, "Results") // Trivy omits Results when it has no results.
	if got := parseTrivyForTest(t, r, trivyTestOptions()); len(got) != 0 {
		t.Fatal("omitted Results produced findings")
	}
}

func TestParseTrivyJSONLimitsReaderConsumption(t *testing.T) {
	reader := &io.LimitedReader{R: strings.NewReader(strings.Repeat(" ", 12<<20)), N: 12 << 20}
	if _, err := ParseTrivyJSON(reader, trivyTestOptions()); err == nil {
		t.Fatal("oversized input accepted")
	}
	if consumed := (12 << 20) - reader.N; consumed > (10<<20)+1 {
		t.Errorf("read %d bytes, want at most 10 MiB + 1", consumed)
	}
}

func TestParseTrivyJSONCollapsesExactDuplicateEntriesAndRejectsConflictingDuplicates(t *testing.T) {
	r := trivyTestReport(t)
	v := trivyTestVulnerability(r)
	trivyTestResult(r)["Vulnerabilities"] = []any{v, v}
	if got := parseTrivyForTest(t, r, trivyTestOptions()); len(got) != 1 {
		t.Errorf("exact duplicate entries produced %d findings, want 1", len(got))
	}
	conflicting := make(map[string]any, len(v))
	for key, value := range v {
		conflicting[key] = value
	}
	conflicting["Severity"] = "CRITICAL"
	trivyTestResult(r)["Vulnerabilities"] = []any{v, conflicting}
	if got, err := ParseTrivyJSON(bytes.NewReader(trivyTestJSON(t, r)), trivyTestOptions()); err == nil || len(got) != 0 {
		t.Errorf("conflicting duplicate: findings=%d error=%v, want safe failure", len(got), err)
	}
}

func TestParseTrivyJSONErrorsDoNotEchoRawInputValues(t *testing.T) {
	const marker = "SYNTHETIC_PRIVATE_VALUE_DO_NOT_ECHO"
	r := trivyTestReport(t)
	r["SchemaVersion"] = marker
	if _, err := ParseTrivyJSON(bytes.NewReader(trivyTestJSON(t, r)), trivyTestOptions()); err == nil || strings.Contains(err.Error(), marker) {
		t.Errorf("schema type error = %v, want sanitized failure", err)
	}
	r = trivyTestReport(t)
	trivyTestVulnerability(r)["PkgName"] = marker + "\n"
	if _, err := ParseTrivyJSON(bytes.NewReader(trivyTestJSON(t, r)), trivyTestOptions()); err == nil || strings.Contains(err.Error(), marker) {
		t.Errorf("field error = %v, want sanitized failure", err)
	}
}

func TestParseTrivyJSONAcceptsExactInputResultAndFindingLimits(t *testing.T) {
	r := trivyTestReport(t)
	body := trivyTestJSON(t, r)
	body = append(body, bytes.Repeat([]byte(" "), (10<<20)-len(body))...)
	if got, err := ParseTrivyJSON(bytes.NewReader(body), trivyTestOptions()); err != nil || len(got) != 1 {
		t.Fatalf("exact 10 MiB: findings=%d error=%v", len(got), err)
	}
	results := make([]any, 2048)
	for i := range results {
		results[i] = map[string]any{"Target": "synthetic-file", "Class": "lang-pkgs", "Type": "npm"}
	}
	r["Results"] = results
	if got := parseTrivyForTest(t, r, trivyTestOptions()); len(got) != 0 {
		t.Errorf("exact 2048 empty results produced %d findings", len(got))
	}
	r = trivyTestReport(t)
	entries := make([]any, 20000)
	for i := range entries {
		entries[i] = map[string]any{"VulnerabilityID": "SYNTHETIC-" + strconv.Itoa(i), "PkgName": "synthetic", "InstalledVersion": "1", "Severity": "LOW"}
	}
	trivyTestResult(r)["Vulnerabilities"] = entries
	if got := parseTrivyForTest(t, r, trivyTestOptions()); len(got) != 20000 {
		t.Errorf("exact 20000 entries produced %d findings", len(got))
	}
	second := map[string]any{"Target": "second-target", "Class": "lang-pkgs", "Type": "npm", "Vulnerabilities": []any{entries[0]}}
	r["Results"] = append(r["Results"].([]any), second)
	if got, err := ParseTrivyJSON(bytes.NewReader(trivyTestJSON(t, r)), trivyTestOptions()); err == nil || len(got) != 0 {
		t.Errorf("20001 entries across results: findings=%d error=%v", len(got), err)
	}
}

func TestParseTrivyJSONRejectsInvalidUnicodeInSelectedFields(t *testing.T) {
	body := trivyTestJSON(t, trivyTestReport(t))
	body = bytes.Replace(body, []byte(`"PkgName":"synthetic-package"`), []byte(`"PkgName":"bad\ud800name"`), 1)
	if got, err := ParseTrivyJSON(bytes.NewReader(body), trivyTestOptions()); err == nil || len(got) != 0 {
		t.Errorf("unpaired Unicode surrogate: findings=%d error=%v", len(got), err)
	}
}

func TestParseTrivyJSONBoundsExpandedCorrelationKeyAndReference(t *testing.T) {
	r := trivyTestReport(t)
	trivyTestVulnerability(r)["VulnerabilityID"] = strings.Repeat("<", 4096)
	if got, err := ParseTrivyJSON(bytes.NewReader(trivyTestJSON(t, r)), trivyTestOptions()); err == nil || len(got) != 0 {
		t.Errorf("expanded oversized canonical key: findings=%d error=%v", len(got), err)
	}
	r = trivyTestReport(t)
	trivyTestVulnerability(r)["PrimaryURL"] = "https://example.invalid/" + strings.Repeat("界", 1300)
	if got := parseTrivyForTest(t, r, trivyTestOptions()); got[0].Observation.RawRef != "" {
		t.Errorf("percent-encoded expanded URL was retained (%d bytes)", len(got[0].Observation.RawRef))
	}
}

func TestParseTrivyJSONKeepsDistinctPackageIdentifiersForSameAdvisoryAndVersion(t *testing.T) {
	r := trivyTestReport(t)
	first := trivyTestVulnerability(r)
	first["PkgIdentifier"] = map[string]any{"PURL": "pkg:npm/synthetic-package@1.0.0?arch=amd64", "UID": "synthetic-amd64"}
	second := make(map[string]any, len(first))
	for key, value := range first {
		second[key] = value
	}
	second["PkgIdentifier"] = map[string]any{"PURL": "pkg:npm/synthetic-package@1.0.0?arch=arm64", "UID": "synthetic-arm64"}
	trivyTestResult(r)["Vulnerabilities"] = []any{first, second}
	got := parseTrivyForTest(t, r, trivyTestOptions())
	if len(got) != 2 || got[0].Finding.ID == got[1].Finding.ID {
		t.Fatalf("distinct package identifiers collapsed: len=%d", len(got))
	}
	if got[0].Finding.CanonicalKey != got[1].Finding.CanonicalKey {
		t.Fatal("same advisory/package context should remain a correlation hint across package instances")
	}
}

func FuzzParseTrivyJSONReturnsNoPartialOutput(f *testing.F) {
	f.Add([]byte(`{"SchemaVersion":2,"ArtifactType":"filesystem","ArtifactName":"/synthetic","Results":[]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"SchemaVersion":2,"Results":[null]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		got, err := ParseTrivyJSON(bytes.NewReader(body), trivyTestOptions())
		if err != nil && len(got) != 0 {
			t.Fatalf("error returned partial output: findings=%d error=%v", len(got), err)
		}
	})
}
