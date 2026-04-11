package model

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// CWE はCommon Weakness Enumeration情報
type CWE struct {
	ID   string `json:"cwe_id"`
	Name string `json:"name"`
}

// EPSS はExploit Prediction Scoring System情報
type EPSS struct {
	Percentage float64 `json:"percentage"` // 悪用される確率 (0.0-1.0)
	Percentile float64 `json:"percentile"` // パーセンタイル順位 (0.0-1.0)
}

// DependabotUpdateError はDependabotの更新試行エラー情報（GraphQL API由来）
type DependabotUpdateError struct {
	ErrorType string `json:"error_type"` // e.g. "security_update_not_possible"
	Title     string `json:"title"`
	Body      string `json:"body"`
}

type Alert struct {
	ID               int
	Number           int
	State            string
	Owner            string
	Repo             string
	PackageName      string
	PackageEcosystem string
	Severity         Severity
	CVEID            string `json:"CVEID"`
	GHSAID           string
	CVSSScore        float64
	CVSSVector       string
	Summary          string
	Description      string
	FixedIn          string
	HTMLURL          string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	PublishedAt      time.Time

	// 脆弱性バージョン情報
	VulnerableVersionRange string

	// 依存関係情報
	ManifestPath           string
	DependencyScope        string // "runtime", "development"
	DependencyRelationship string // "direct", "transitive", "unknown", "inconclusive"

	// EPSS (Exploit Prediction Scoring System)
	EPSS *EPSS

	// CWE一覧
	CWEs []CWE

	// 参照URL一覧
	References []string

	// Dependabot更新エラー情報（GraphQL API由来）
	UpdateError *DependabotUpdateError
}

type Evaluation struct {
	Risk           string `json:"risk"`
	Impact         string `json:"impact"`
	Recommendation string `json:"recommendation"`
	Reasoning      string `json:"reasoning"`
}

type AlertState string

const (
	AlertStatePending  AlertState = "pending"
	AlertStateApproved AlertState = "approved"
	AlertStateRejected AlertState = "rejected"
	AlertStateMerged   AlertState = "merged"
)

type EvalStatus string

const (
	EvalStatusPending    EvalStatus = "pending"    // 評価待ち（まだ処理されていない）
	EvalStatusEvaluating EvalStatus = "evaluating" // AI評価中
	EvalStatusDone       EvalStatus = "done"       // AI評価完了
	EvalStatusFailed     EvalStatus = "failed"     // AI評価失敗
)

type AlertRecord struct {
	Alert            Alert
	Evaluation       *Evaluation
	State            AlertState
	EvalStatus       EvalStatus
	NotifiedAt       time.Time
	MergedAt         *time.Time
	SlackMessageTS   string // Slack通知済みメッセージのTimestamp（編集に使用）
	DiscordMessageID string // Discord Webhookメッセージ ID（編集に使用）
}

type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
	AlertID   int
}
