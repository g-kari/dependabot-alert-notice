package model

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSecurityStatusConstantsKeepDetectionAndTriageSeparate(t *testing.T) {
	source := []SourceStatus{SourceStatusActive, SourceStatusResolved, SourceStatusSuppressed, SourceStatusUnknown}
	wantSource := []string{"active", "resolved", "suppressed", "unknown"}
	for i, status := range source {
		if string(status) != wantSource[i] {
			t.Errorf("source status[%d] = %q, want %q", i, status, wantSource[i])
		}
	}
	triage := []TriageStatus{TriageStatusNew, TriageStatusTriaged, TriageStatusInProgress, TriageStatusRiskAccepted, TriageStatusClosed}
	wantTriage := []string{"new", "triaged", "in_progress", "risk_accepted", "closed"}
	for i, status := range triage {
		if string(status) != wantTriage[i] {
			t.Errorf("triage status[%d] = %q, want %q", i, status, wantTriage[i])
		}
	}
	if IngestResultRunning != "running" || IngestResultSuccess != "success" || IngestResultPartial != "partial" || IngestResultFailed != "failed" {
		t.Fatal("ingest results do not match the persisted contract")
	}
	if IngestCoverageFull != "full" || IngestCoveragePartial != "partial" || IngestCoverageUnknown != "unknown" {
		t.Fatal("ingest coverage does not match the persisted contract")
	}
}

func TestSecurityModelsPreserveFieldContracts(t *testing.T) {
	at := time.Date(2026, 11, 5, 6, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		value  any
		fields []string
	}{
		{"asset", Asset{ID: "asset", Type: "repository", Provider: "github", Account: "owner", Region: "region", NativeID: "owner/repo", Environment: "test", Criticality: "high"}, []string{"id", "type", "provider", "account", "region", "native_id", "environment", "criticality"}},
		{"finding", Finding{ID: "finding", Category: "vulnerability", AssetID: "asset", CanonicalKey: "cve:example", Severity: SeverityHigh, TriageStatus: TriageStatusNew, SourceStatus: SourceStatusActive, FirstSeen: at, LastSeen: at}, []string{"id", "category", "asset_id", "canonical_key", "severity", "triage_status", "source_status", "first_seen", "last_seen"}},
		{"observation", Observation{ID: "observation", Source: "dependabot", Account: "owner", SourceFindingID: "owner/repo:1", FindingID: "finding", IngestRunID: "run", RawRef: "https://example.test/alert", Fingerprint: "digest", ObservedAt: at}, []string{"id", "source", "account", "source_finding_id", "finding_id", "ingest_run_id", "raw_ref", "fingerprint", "observed_at"}},
		{"event", Event{ID: "event", EntityID: "finding", EventType: "observed", Actor: "dependabot", BeforeRef: "before", AfterRef: "after", Timestamp: at}, []string{"id", "entity_id", "event_type", "actor", "before_ref", "after_ref", "timestamp"}},
		{"ingest run", IngestRun{ID: "run", Connector: "dependabot", Scope: "owner/repo", Result: IngestResultSuccess, Coverage: IngestCoverageFull, Cursor: "cursor", Error: "error", StartedAt: at, FinishedAt: &at}, []string{"id", "connector", "scope", "result", "coverage", "cursor", "error", "started_at", "finished_at"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("marshal %s: %v", tc.name, err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatalf("decode %s: %v", tc.name, err)
			}
			for _, field := range tc.fields {
				if _, ok := fields[field]; !ok {
					t.Errorf("%s JSON lacks field %q: %s", tc.name, field, body)
				}
			}
		})
	}
}

func TestSecurityFindingMetadataRoundTrip(t *testing.T) {
	bundle := SecurityFinding{Finding: Finding{ID: "finding", Title: "Example vulnerability", VulnerabilityID: "CVE-2026-1234", PackageName: "example", PackageEcosystem: "npm", InstalledVersion: "1.0.0", FixedVersion: "1.1.0"}}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	var restored SecurityFinding
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Finding != bundle.Finding {
		t.Fatalf("metadata roundtrip=%+v", restored.Finding)
	}
	var legacy Finding
	if err := json.Unmarshal([]byte(`{"id":"legacy","category":"vulnerability"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.ID != "legacy" || legacy.VulnerabilityID != "" {
		t.Fatal("old findings no longer decode")
	}
}

func TestCodeScanningFindingMetadataRoundTripPreservesLegacyShape(t *testing.T) {
	original := Finding{ID: "code-finding", RuleID: "go/example", ToolName: "CodeQL", FilePath: "src/example.go", StartLine: 12}
	body, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var restored Finding
	if err := json.Unmarshal(body, &restored); err != nil {
		t.Fatal(err)
	}
	if restored != original {
		t.Fatalf("metadata roundtrip=%+v", restored)
	}
	legacy, err := json.Marshal(Finding{ID: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(legacy, &fields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"rule_id", "tool_name", "file_path", "start_line"} {
		if _, ok := fields[field]; ok {
			t.Fatalf("empty metadata changed legacy JSON shape: %s", legacy)
		}
	}
}
