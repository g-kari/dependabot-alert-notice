package model

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Alert struct {
	ID               int
	Number           int
	State            string
	Owner            string
	Repo             string
	PackageName      string
	PackageEcosystem string
	Severity         Severity
	CVEID            string
	CVSSScore        float64
	Summary          string
	FixedIn          string
	HTMLURL          string
	CreatedAt        time.Time
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
	Alert      Alert
	Evaluation *Evaluation
	State      AlertState
	EvalStatus EvalStatus
	NotifiedAt time.Time
	MergedAt   *time.Time
}

type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
	AlertID   int
}
