package model

import (
	"fmt"
	"strings"
	"time"
)

// AdvisoryKey identifies CVEs consistently, with a stable alert identity for
// GHSA-only or unidentified advisories so unrelated missing CVEs never collide.
func AdvisoryKey(alert Alert) string {
	if cve := strings.ToUpper(strings.TrimSpace(alert.CVEID)); cve != "" {
		return "cve:" + cve
	}
	return fmt.Sprintf("ghsa:%s:alert:%d", strings.ToUpper(strings.TrimSpace(alert.GHSAID)), alert.ID)
}

// Interval は不確実な値の下限と上限を表す。
type Interval struct {
	Low  float64
	High float64
}

// TechnicalImpact はCVEの技術的影響を正規化した値。
type TechnicalImpact struct {
	Confidentiality Interval
	Integrity       Interval
	Availability    Interval
	Privilege       Interval
	// C/I/A/X are compact aliases used by the scoring contract. When set they
	// take precedence over the descriptive fields above.
	C           Interval `json:"c,omitempty"`
	I           Interval `json:"i,omitempty"`
	A           Interval `json:"a,omitempty"`
	X           Interval `json:"x,omitempty"`
	CVSSVersion string
	CVSSVector  string
}

// ScoreInput は緊急度計算に必要な入力のスナップショット。
type ScoreInput struct {
	Profile    ServiceProfile
	Assessment CVEAssessment
	Threat     ThreatSnapshot
	Technical  TechnicalImpact
	CVSS       float64
	CVSSKnown  bool
	At         time.Time
}

// Reason はスコア計算根拠。
type Reason struct {
	RuleID string `json:"rule_id"`
	Text   string `json:"text"`
}

// ScoreResult は対応緊急度の計算結果。
type ScoreResult struct {
	ModelVersion   string   `json:"model_version"`
	ProfileID      string   `json:"profile_id,omitempty"`
	Status         string   `json:"status"`
	Priority       string   `json:"priority"`
	Confidence     string   `json:"confidence"`
	Impact         Interval `json:"impact"`
	Likelihood     Interval `json:"likelihood"`
	Lower          int      `json:"lower"`
	Upper          int      `json:"upper"`
	MissingFacts   []string `json:"missing_facts,omitempty"`
	ConfirmedRules []string `json:"confirmed_rules,omitempty"`
	PossibleRules  []string `json:"possible_rules,omitempty"`
	Reasons        []Reason `json:"reasons,omitempty"`
}

// RiskLevel はサービス属性や影響の段階を表す。
type RiskLevel string

const (
	RiskUnknown      RiskLevel = "unknown"
	RiskLow          RiskLevel = "low"
	RiskStandard     RiskLevel = "standard"
	RiskHigh         RiskLevel = "high"
	RiskCritical     RiskLevel = "critical"
	RiskRestricted   RiskLevel = "restricted"
	RiskConfidential RiskLevel = "confidential"
	RiskInternal     RiskLevel = "internal"
	RiskPublic       RiskLevel = "public"
)

// ServiceEnvironment はサービスが稼働する環境。
type ServiceEnvironment string

const (
	EnvironmentProduction  ServiceEnvironment = "production"
	EnvironmentStaging     ServiceEnvironment = "staging"
	EnvironmentDevelopment ServiceEnvironment = "development"
	EnvironmentCI          ServiceEnvironment = "ci"
	EnvironmentUnknown     ServiceEnvironment = "unknown"
)

// ExposurePath は攻撃者からの公開経路。
type ExposurePath string

const (
	ExposureInternet ExposurePath = "internet"
	ExposurePartner  ExposurePath = "partner"
	ExposureInternal ExposurePath = "internal"
	ExposureIsolated ExposurePath = "isolated"
	ExposureUnknown  ExposurePath = "unknown"
)

// AuthenticationBoundary は攻撃に必要な認証境界。
type AuthenticationBoundary string

const (
	AuthNone       AuthenticationBoundary = "none"
	AuthCustomer   AuthenticationBoundary = "customer"
	AuthEmployee   AuthenticationBoundary = "employee"
	AuthPrivileged AuthenticationBoundary = "privileged"
	AuthUnknown    AuthenticationBoundary = "unknown"
)

// PrivilegeScope は侵害時に到達可能な権限範囲。
type PrivilegeScope string

const (
	PrivilegeSharedControl   PrivilegeScope = "shared_control"
	PrivilegeProductionWrite PrivilegeScope = "production_write"
	PrivilegeServiceOnly     PrivilegeScope = "service_only"
	PrivilegeSandbox         PrivilegeScope = "sandbox"
	PrivilegeUnknown         PrivilegeScope = "unknown"
)

// ServiceProfile はサービスごとの環境リスク前提を保持する。
type ServiceProfile struct {
	ID                  string                 `yaml:"id" json:"id"`
	Extends             string                 `yaml:"extends,omitempty" json:"extends,omitempty"`
	Owner               string                 `yaml:"owner" json:"owner"`
	Repo                string                 `yaml:"repo" json:"repo"`
	Environment         ServiceEnvironment     `yaml:"environment" json:"environment"`
	Exposure            ExposurePath           `yaml:"exposure" json:"exposure"`
	Authentication      AuthenticationBoundary `yaml:"authentication" json:"authentication"`
	BusinessCriticality RiskLevel              `yaml:"business_criticality" json:"business_criticality"`
	MaxOutageMinutes    int                    `yaml:"max_outage_minutes" json:"max_outage_minutes"`
	DataClassification  RiskLevel              `yaml:"data_classification" json:"data_classification"`
	IntegrityImpact     RiskLevel              `yaml:"integrity_impact" json:"integrity_impact"`
	PrivilegeScope      PrivilegeScope         `yaml:"privilege_scope" json:"privilege_scope"`
	OwnerTeam           string                 `yaml:"owner_team" json:"owner_team"`
	ReviewedBy          string                 `yaml:"reviewed_by" json:"reviewed_by"`
	ReviewedAt          *time.Time             `yaml:"reviewed_at" json:"reviewed_at"`
	ReviewDueAt         *time.Time             `yaml:"review_due_at" json:"review_due_at"`
}

// EffectiveProfile is the immutable, fully-resolved service profile used by
// the scoring service.  It is an alias so callers can use the terminology
// from the design contract without duplicating the wire type.
type EffectiveProfile = ServiceProfile

// Assessment is the contract name for CVEAssessment.
type Assessment = CVEAssessment

// CVEAssessment はCVEとサービスの適用性・到達性に関する確認情報。
type CVEAssessment struct {
	ProfileID          string                `yaml:"profile_id" json:"profile_id"`
	Repo               string                `yaml:"repo" json:"repo"`
	AdvisoryKey        string                `yaml:"advisory_key" json:"advisory_key"`
	Applicability      string                `yaml:"applicability" json:"applicability"`
	Reachability       string                `yaml:"reachability" json:"reachability"`
	Mitigation         string                `yaml:"mitigation" json:"mitigation"`
	LocalActivity      string                `yaml:"local_activity" json:"local_activity"`
	Facts              map[string]string     `yaml:"facts" json:"facts"`
	Evidence           []Evidence            `yaml:"evidence" json:"evidence"`
	EvidenceByFact     map[string][]Evidence `yaml:"evidence_by_fact" json:"evidence_by_fact"`
	DeploymentRevision string                `yaml:"deployment_revision" json:"deployment_revision"`
}

// Evidence は判定根拠と有効期限を表す。
type Evidence struct {
	ID                 string    `yaml:"id" json:"id"`
	Source             string    `yaml:"source" json:"source"`
	Reference          string    `yaml:"reference" json:"reference"`
	Reviewer           string    `yaml:"reviewer" json:"reviewer"`
	ObservedAt         time.Time `yaml:"observed_at" json:"observed_at"`
	ExpiresAt          time.Time `yaml:"expires_at" json:"expires_at"`
	DeploymentRevision string    `yaml:"deployment_revision" json:"deployment_revision"`
}

// ThreatSnapshot はKEV、EPSS、手動の悪用情報を保持する。
type ThreatSnapshot struct {
	AdvisoryKey string `json:"advisory_key"`
	KEV         bool   `json:"kev"`
	// KEVKnown distinguishes an explicit negative from an unavailable feed.
	// It is intentionally optional for backwards-compatible configuration.
	KEVKnown       bool       `json:"kev_known,omitempty"`
	KEVDate        *time.Time `json:"kev_date,omitempty"`
	EPSS           *float64   `json:"epss,omitempty"`
	EPSSPercentile *float64   `json:"epss_percentile,omitempty"`
	EPSSDate       *time.Time `json:"epss_date,omitempty"`
	// EPSSFetchedAt preserves source freshness when KEV and EPSS are merged.
	EPSSFetchedAt *time.Time `json:"epss_fetched_at,omitempty"`
	LocalActivity string     `json:"local_activity"`
	FetchedAt     time.Time  `json:"fetched_at"`
}
