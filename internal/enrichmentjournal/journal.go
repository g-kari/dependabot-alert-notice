// Package enrichmentjournal defines the closed internal operation-checkpoint
// format. It has no Store, transport, configuration or application dependency.
package enrichmentjournal

import (
	"time"
)

// Version is the only supported durable checkpoint format version.
const Version = 1

// MaxCheckpointBytes bounds one canonical encoded checkpoint, not feed bytes.
const MaxCheckpointBytes = 1 << 20

// Stage identifies a checkpoint; transition order is a branched state machine.
type Stage string

const (
	Reserved Stage = "reserved"
	Begin    Stage = "begin"
	Fail     Stage = "fail"
	Complete Stage = "complete"
	Returned Stage = "returned"
)

// Request is the immutable operation binding.
type Request struct {
	Connector string `json:"connector"`
	After     string `json:"after"`
	Limit     int    `json:"limit"`
}

// Progress preserves scan and candidate publication state. Pending refers to
// Prepared; the complete envelope is encoded once, never replaced by a run ID.
type Progress struct {
	Outcome   string `json:"outcome"`
	Code      string `json:"code"`
	RunID     string `json:"run_id"`
	Scanned   int    `json:"scanned"`
	Targets   int    `json:"targets"`
	ScanAfter string `json:"scan_after"`
	NextAfter string `json:"next_after"`
	Advance   bool   `json:"advance"`
	Exhausted bool   `json:"exhausted"`
	Pending   bool   `json:"pending"`
}

// Target preserves the original checked Finding identity and revision.
type Target struct {
	FindingID string `json:"finding_id"`
	CVEID     string `json:"cve_id"`
	Revision  string `json:"revision"`
}

// Attempt binds the operation to one prepared run UUID and target manifest.
type Attempt struct {
	RunID     string    `json:"run_id"`
	Connector string    `json:"connector"`
	Scope     string    `json:"scope"`
	StartedAt time.Time `json:"started_at"`
	Targets   []Target  `json:"targets"`
}

// Failure retains only the fixed expected code and exact finish clock.
type Failure struct {
	Code       string    `json:"code"`
	FinishedAt time.Time `json:"finished_at"`
}

// Entry preserves explicit zero versus missing evidence and positive-only KEV.
type Entry struct {
	CVEID        string     `json:"cve_id"`
	EPSS         *float64   `json:"epss"`
	Percentile   *float64   `json:"percentile"`
	KEV          bool       `json:"kev"`
	KEVDateAdded *time.Time `json:"kev_date_added"`
}

// Feed is the selected parsed evidence, never raw response bytes.
type Feed struct {
	Source       string    `json:"source"`
	Version      string    `json:"version"`
	PublishedAt  time.Time `json:"published_at"`
	ObservedAt   time.Time `json:"observed_at"`
	SelectedCVEs []string  `json:"selected_cves"`
	Entries      []Entry   `json:"entries"`
}

// Completion shares Prepared.Attempt instead of encoding a duplicate manifest.
// A future preserving-checkpoint converter must reject unequal duplicated
// Attempt/Result.Pending values before aggregation; it must not normalize them
// away. That adapter is outside this format/Store slice.
type Completion struct {
	Feed           Feed      `json:"feed"`
	OriginalDigest string    `json:"original_digest"`
	FinishedAt     time.Time `json:"finished_at"`
}

// Prepared retains one exact attempt and mutually exclusive optional writes.
type Prepared struct {
	Attempt    Attempt     `json:"attempt"`
	Failure    *Failure    `json:"failure"`
	Completion *Completion `json:"completion"`
}

// Checkpoint is an internal, closed durable DTO, not a public HTTP/CLI schema.
type Checkpoint struct {
	Version     int       `json:"version"`
	OperationID string    `json:"operation_id"`
	Request     Request   `json:"request"`
	Stage       Stage     `json:"stage"`
	Progress    Progress  `json:"progress"`
	Prepared    *Prepared `json:"prepared"`
}

// AppendRequest carries an exact caller-retained sequence and previous head.
// Sequence starts at one; replay never creates a replacement sequence or UUID.
type AppendRequest struct {
	Sequence       int64
	PreviousDigest string
	Checkpoint     Checkpoint
}

// Acknowledgement confirms journal payload storage, not an enrichment commit.
// Digest is SHA256 of canonical checkpoint JSON, not OriginalDigest/run receipt.
type Acknowledgement struct {
	OperationID string
	Sequence    int64
	Digest      string
	Replay      bool
}

// Encode validates all bounded fields before producing canonical versioned JSON.
func Encode(checkpoint Checkpoint) ([]byte, error) {
	return encodeCheckpoint(checkpoint)
}

// Decode rejects oversize, malformed, non-closed or semantically invalid input.
func Decode(data []byte) (Checkpoint, error) {
	return decodeCheckpoint(data)
}

// ValidateTransition checks initial reservation or an exact allowed advancement.
func ValidateTransition(previous *Checkpoint, next Checkpoint) error {
	return validateTransition(previous, next)
}
