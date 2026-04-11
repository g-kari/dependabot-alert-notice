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

type AlertRecord struct {
	Alert      Alert
	Evaluation *Evaluation
	State      AlertState
	NotifiedAt time.Time
	MergedAt   *time.Time
}

type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
	AlertID   int
}
