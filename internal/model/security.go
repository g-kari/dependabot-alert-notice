package model

import "time"

// SourceStatus describes a detection source's lifecycle, independently of local
// triage and the existing Dependabot approval workflow.
type SourceStatus string

const (
	SourceStatusActive     SourceStatus = "active"
	SourceStatusResolved   SourceStatus = "resolved"
	SourceStatusSuppressed SourceStatus = "suppressed"
	SourceStatusUnknown    SourceStatus = "unknown"
)

// TriageStatus describes an operator's disposition of a normalized finding.
type TriageStatus string

const (
	TriageStatusNew          TriageStatus = "new"
	TriageStatusTriaged      TriageStatus = "triaged"
	TriageStatusInProgress   TriageStatus = "in_progress"
	TriageStatusRiskAccepted TriageStatus = "risk_accepted"
	TriageStatusClosed       TriageStatus = "closed"
)

// Ingest result values record completion independently from collection coverage.
const (
	IngestResultRunning = "running"
	IngestResultSuccess = "success"
	IngestResultPartial = "partial"
	IngestResultFailed  = "failed"
)

// Ingest coverage values distinguish complete collection from missing evidence.
const (
	IngestCoverageFull    = "full"
	IngestCoveragePartial = "partial"
	IngestCoverageUnknown = "unknown"
)

// Asset identifies the resource affected by one or more findings.
type Asset struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Provider    string `json:"provider"`
	Account     string `json:"account"`
	Region      string `json:"region"`
	NativeID    string `json:"native_id"`
	Environment string `json:"environment"`
	Criticality string `json:"criticality"`
}

// Finding holds an asset-specific security issue. CanonicalKey is a correlation
// hint only; source-native identity must not be replaced by advisory grouping.
type Finding struct {
	Title            string       `json:"title,omitempty"`
	VulnerabilityID  string       `json:"vulnerability_id,omitempty"`
	PackageName      string       `json:"package_name,omitempty"`
	PackageEcosystem string       `json:"package_ecosystem,omitempty"`
	InstalledVersion string       `json:"installed_version,omitempty"`
	FixedVersion     string       `json:"fixed_version,omitempty"`
	ID               string       `json:"id"`
	Category         string       `json:"category"`
	AssetID          string       `json:"asset_id"`
	CanonicalKey     string       `json:"canonical_key"`
	Severity         Severity     `json:"severity"`
	TriageStatus     TriageStatus `json:"triage_status"`
	SourceStatus     SourceStatus `json:"source_status"`
	FirstSeen        time.Time    `json:"first_seen"`
	LastSeen         time.Time    `json:"last_seen"`
}

// Observation preserves a source-native finding's evidence in an ingestion run.
// RawRef points to the evidence without duplicating potentially sensitive data.
type Observation struct {
	ID              string    `json:"id"`
	Source          string    `json:"source"`
	Account         string    `json:"account"`
	SourceFindingID string    `json:"source_finding_id"`
	FindingID       string    `json:"finding_id"`
	IngestRunID     string    `json:"ingest_run_id"`
	RawRef          string    `json:"raw_ref"`
	Fingerprint     string    `json:"fingerprint"`
	ObservedAt      time.Time `json:"observed_at"`
}

// Event is an append-only audit entry. BeforeRef and AfterRef reference evidence
// fingerprints, rather than embedding source payloads or approval credentials.
type Event struct {
	ID        string    `json:"id"`
	EntityID  string    `json:"entity_id"`
	EventType string    `json:"event_type"`
	Actor     string    `json:"actor"`
	Timestamp time.Time `json:"timestamp"`
	BeforeRef string    `json:"before_ref"`
	AfterRef  string    `json:"after_ref"`
}

// IngestRun records a connector's scope and collection completeness. A partial
// or failed run never provides evidence that an unseen finding was resolved.
type IngestRun struct {
	ID         string     `json:"id"`
	Connector  string     `json:"connector"`
	Scope      string     `json:"scope"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Result     string     `json:"result"`
	Coverage   string     `json:"coverage"`
	Cursor     string     `json:"cursor"`
	Error      string     `json:"error"`
}

// SecurityFinding carries one normalized finding together with its source
// observation and affected asset. It contains no source report or credentials.
type SecurityFinding struct {
	Asset       Asset       `json:"asset"`
	Finding     Finding     `json:"finding"`
	Observation Observation `json:"observation"`
}
