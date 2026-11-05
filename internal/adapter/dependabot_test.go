package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func dependabotRecord() model.AlertRecord {
	return model.AlertRecord{Alert: model.Alert{
		ID: 93, Number: 7, State: "open", Owner: "Example", Repo: "Service",
		PackageName: "example-package", PackageEcosystem: "npm", ManifestPath: "package-lock.json",
		CVEID: "CVE-2026-1234", GHSAID: "GHSA-aaaa-bbbb-cccc", Severity: model.SeverityHigh,
		HTMLURL:   "https://github.com/Example/Service/security/dependabot/7",
		CreatedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}, State: model.AlertStateApproved, EvalStatus: model.EvalStatusDone}
}

func normalizeForTest(t *testing.T, record model.AlertRecord, run string, at time.Time) DependabotFinding {
	t.Helper()
	result, err := NormalizeDependabot(record, run, at)
	if err != nil {
		t.Fatalf("NormalizeDependabot(%q/%q:%d): %v", record.Alert.Owner, record.Alert.Repo, record.Alert.Number, err)
	}
	return result
}

func TestNormalizeDependabotMapsSourceIdentityAndEvidence(t *testing.T) {
	record := dependabotRecord()
	at := record.Alert.CreatedAt.Add(time.Hour)
	got := normalizeForTest(t, record, "run-1", at)
	if got.Asset.Type != "repository" || got.Asset.Provider != "github" || got.Asset.Account != "example" || got.Asset.NativeID != "example/service" {
		t.Errorf("asset = %+v, want canonical GitHub repository", got.Asset)
	}
	if got.Finding.Category != "vulnerability" || got.Finding.AssetID != got.Asset.ID || got.Finding.Severity != model.SeverityHigh || got.Finding.TriageStatus != model.TriageStatusNew || got.Finding.SourceStatus != model.SourceStatusActive {
		t.Errorf("finding = %+v, want independent vulnerability detection and triage status", got.Finding)
	}
	if !got.Finding.FirstSeen.Equal(record.Alert.CreatedAt) || !got.Finding.LastSeen.Equal(at) {
		t.Errorf("first/last seen = %v/%v, want %v/%v", got.Finding.FirstSeen, got.Finding.LastSeen, record.Alert.CreatedAt, at)
	}
	if got.Observation.Source != "dependabot" || got.Observation.Account != "example" || got.Observation.SourceFindingID != "example/service:7" || got.Observation.FindingID != got.Finding.ID || got.Observation.IngestRunID != "run-1" || got.Observation.RawRef != record.Alert.HTMLURL || !got.Observation.ObservedAt.Equal(at) {
		t.Errorf("observation = %+v, want native source identity and ingest evidence", got.Observation)
	}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for name, id := range map[string]string{"asset": got.Asset.ID, "finding": got.Finding.ID, "observation": got.Observation.ID} {
		if !uuid.MatchString(id) {
			t.Errorf("%s ID = %q, want deterministic RFC 9562 custom UUID", name, id)
		}
	}
	if got.Asset.ID == got.Finding.ID || got.Finding.ID == got.Observation.ID {
		t.Fatal("different entity namespaces share an ID")
	}
}

func TestNormalizeDependabotUsesNativeIdentityInsteadOfCVE(t *testing.T) {
	record := dependabotRecord()
	at := record.Alert.CreatedAt.Add(time.Hour)
	original := normalizeForTest(t, record, "run-1", at)
	repeated := normalizeForTest(t, record, "run-1", at)
	if !reflect.DeepEqual(original, repeated) {
		t.Fatal("identical input is not deterministic")
	}
	record.Alert.Owner = " example "
	record.Alert.Repo = "SERVICE"
	record.Alert.ID = 999
	caseVariant := normalizeForTest(t, record, "run-2", at.Add(time.Hour))
	if original.Asset.ID != caseVariant.Asset.ID || original.Finding.ID != caseVariant.Finding.ID {
		t.Fatal("case or local database ID changed native identity")
	}
	record.Alert.CVEID = "CVE-2026-9999"
	record.Alert.PackageName = "other-package"
	changedDetails := normalizeForTest(t, record, "run-2", at)
	if original.Finding.ID != changedDetails.Finding.ID {
		t.Fatal("changed advisory/package changed native finding identity")
	}
	for _, change := range []struct {
		name   string
		mutate func(*model.Alert)
	}{
		{"repository", func(a *model.Alert) { a.Repo = "other-repo" }},
		{"account", func(a *model.Alert) { a.Owner = "other-owner" }},
		{"number", func(a *model.Alert) { a.Number++ }},
	} {
		t.Run(change.name, func(t *testing.T) {
			r := dependabotRecord()
			change.mutate(&r.Alert)
			got := normalizeForTest(t, r, "run-1", at)
			if got.Finding.ID == original.Finding.ID {
				t.Errorf("%s reused finding ID for the same CVE", change.name)
			}
			if got.Finding.CanonicalKey != original.Finding.CanonicalKey {
				t.Errorf("same advisory/package/manifest should share correlation hint, got %q and %q", got.Finding.CanonicalKey, original.Finding.CanonicalKey)
			}
		})
	}
}

func TestNormalizeDependabotSeparatesNativeLifecycleFromApproval(t *testing.T) {
	resolved := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		native   string
		resolved *time.Time
		want     model.SourceStatus
	}{
		{"open", nil, model.SourceStatusActive}, {"", nil, model.SourceStatusActive},
		{"fixed", nil, model.SourceStatusResolved}, {"dismissed", nil, model.SourceStatusSuppressed},
		{"auto_dismissed", nil, model.SourceStatusSuppressed}, {"unexpected", nil, model.SourceStatusUnknown},
		{" OPEN ", nil, model.SourceStatusActive}, {"open", &resolved, model.SourceStatusResolved},
		{"dismissed", &resolved, model.SourceStatusResolved},
	}
	for _, tc := range cases {
		for _, approval := range []model.AlertState{model.AlertStatePending, model.AlertStateApproved, model.AlertStateRejected, model.AlertStateMerged} {
			t.Run(tc.native+"/"+string(approval), func(t *testing.T) {
				r := dependabotRecord()
				r.Alert.State = tc.native
				r.ResolvedAt = tc.resolved
				r.State = approval
				got := normalizeForTest(t, r, "run-1", resolved.Add(time.Hour))
				if got.Finding.SourceStatus != tc.want || got.Finding.TriageStatus != model.TriageStatusNew {
					t.Errorf("native=%q resolved=%v approval=%q: source=%q triage=%q, want source=%q triage=new", tc.native, tc.resolved, approval, got.Finding.SourceStatus, got.Finding.TriageStatus, tc.want)
				}
			})
		}
	}
}

func TestNormalizeDependabotFingerprintExcludesLocalWorkflowAndIncludesSourceState(t *testing.T) {
	record := dependabotRecord()
	at := record.Alert.CreatedAt.Add(time.Hour)
	original := normalizeForTest(t, record, "run-1", at)
	alert := record.Alert
	alert.ID = 0
	body, err := json.Marshal(struct {
		Alert        model.Alert        `json:"alert"`
		SourceStatus model.SourceStatus `json:"source_status"`
	}{alert, model.SourceStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if original.Observation.Fingerprint != hex.EncodeToString(digest[:]) {
		t.Errorf("fingerprint = %q, want SHA256 of canonical source JSON and status", original.Observation.Fingerprint)
	}
	record.Alert.ID++
	record.State = model.AlertStateMerged
	record.EvalStatus = model.EvalStatusFailed
	record.Evaluation = &model.Evaluation{Risk: "high"}
	record.NotifiedAt = at
	record.MergedAt = &at
	workflowChanged := normalizeForTest(t, record, "run-1", at)
	if workflowChanged.Observation != original.Observation {
		t.Fatal("local approval/evaluation/notification workflow changed source observation")
	}
	nextRun := normalizeForTest(t, record, "run-2", at.Add(time.Hour))
	if nextRun.Observation.Fingerprint != original.Observation.Fingerprint || nextRun.Observation.ID == original.Observation.ID {
		t.Fatal("new run must retain separate observation without changing source fingerprint")
	}
	record.ResolvedAt = &at
	resolved := normalizeForTest(t, record, "run-1", at)
	if resolved.Observation.Fingerprint == original.Observation.Fingerprint || resolved.Observation.ID == original.Observation.ID {
		t.Fatal("source resolution did not create new source evidence")
	}
	record.ResolvedAt = nil
	record.Alert.Summary = "new source evidence"
	changed := normalizeForTest(t, record, "run-1", at)
	if changed.Observation.Fingerprint == original.Observation.Fingerprint {
		t.Fatal("changed source payload reused fingerprint")
	}
}

func TestNormalizeDependabotUsesObservationTimeForLegacyMissingCreation(t *testing.T) {
	record := dependabotRecord()
	record.Alert.CreatedAt = time.Time{}
	at := time.Date(2026, 11, 5, 6, 0, 0, 0, time.FixedZone("offset", 3600))
	got := normalizeForTest(t, record, "run-1", at)
	if !got.Finding.FirstSeen.Equal(at) || !got.Finding.LastSeen.Equal(at) || !got.Observation.ObservedAt.Equal(at) {
		t.Fatalf("timestamps = %+v / %+v, want observation time %v", got.Finding, got.Observation, at)
	}
	if got.Finding.LastSeen.Location() != time.UTC || got.Observation.ObservedAt.Location() != time.UTC {
		t.Fatal("normalized timestamps are not UTC")
	}
}

func TestNormalizeDependabotCanonicalKeyPrefersAdvisoryAndPreservesPackageContext(t *testing.T) {
	record := dependabotRecord()
	at := record.Alert.CreatedAt
	original := normalizeForTest(t, record, "run", at)
	if !strings.Contains(original.Finding.CanonicalKey, "CVE-2026-1234") || !strings.Contains(original.Finding.CanonicalKey, "example-package") || !strings.Contains(original.Finding.CanonicalKey, "package-lock.json") {
		t.Errorf("canonical hint lacks source correlation context: %q", original.Finding.CanonicalKey)
	}
	record.Alert.CVEID = ""
	ghsa := normalizeForTest(t, record, "run", at)
	if !strings.Contains(ghsa.Finding.CanonicalKey, "GHSA-AAAA-BBBB-CCCC") {
		t.Errorf("GHSA fallback missing: %q", ghsa.Finding.CanonicalKey)
	}
	record.Alert.GHSAID = ""
	unidentified := normalizeForTest(t, record, "run", at)
	if unidentified.Finding.CanonicalKey != "" {
		t.Errorf("unidentified advisory has correlation hint %q, want empty to avoid false grouping", unidentified.Finding.CanonicalKey)
	}
}

func TestNormalizeDependabotRejectsInvalidIdentityAndEvidence(t *testing.T) {
	valid := dependabotRecord()
	at := valid.Alert.CreatedAt
	cases := []struct {
		name   string
		mutate func(*model.AlertRecord)
		run    string
		at     time.Time
	}{
		{"missing owner", func(r *model.AlertRecord) { r.Alert.Owner = " " }, "run", at},
		{"missing repository", func(r *model.AlertRecord) { r.Alert.Repo = "" }, "run", at},
		{"ambiguous owner", func(r *model.AlertRecord) { r.Alert.Owner = "org/sub" }, "run", at},
		{"ambiguous repository", func(r *model.AlertRecord) { r.Alert.Repo = "repo:1" }, "run", at},
		{"zero number", func(r *model.AlertRecord) { r.Alert.Number = 0 }, "run", at},
		{"negative number", func(r *model.AlertRecord) { r.Alert.Number = -1 }, "run", at},
		{"missing run", func(*model.AlertRecord) {}, " ", at},
		{"missing observation time", func(*model.AlertRecord) {}, "run", time.Time{}},
		{"invalid source JSON", func(r *model.AlertRecord) { r.Alert.CVSSScore = math.NaN() }, "run", at},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := valid
			tc.mutate(&record)
			got, err := NormalizeDependabot(record, tc.run, tc.at)
			if err == nil {
				t.Fatalf("%s normalized successfully: %+v", tc.name, got)
			}
			if !strings.Contains(err.Error(), "normalize dependabot") {
				t.Errorf("%s lacks error context: %v", tc.name, err)
			}
			if !reflect.DeepEqual(got, DependabotFinding{}) {
				t.Errorf("%s returned partial result on error: %+v", tc.name, got)
			}
		})
	}
}

func TestCanonicalKeyIsValidJSONForControlCharacters(t *testing.T) {
	record := model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1, CVEID: "CVE-2026-1", PackageName: "control\x7f\x01", ManifestPath: "path\vfile"}}
	normalized, err := NormalizeDependabot(record, "run", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var parts []string
	if err := json.Unmarshal([]byte(normalized.Finding.CanonicalKey), &parts); err != nil {
		t.Fatalf("canonical key is not JSON: %q: %v", normalized.Finding.CanonicalKey, err)
	}
	if parts[2] != record.Alert.PackageName || parts[3] != record.Alert.ManifestPath {
		t.Fatal("canonical key lost source values")
	}
}
