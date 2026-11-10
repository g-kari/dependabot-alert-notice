package enrichmentjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func journalContractScope(t *testing.T, cves []string) string {
	t.Helper()
	data, err := json.Marshal(cves)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("cves-sha256:%x", sha256.Sum256(data))
}

func journalContractFrames(t *testing.T) []Checkpoint {
	t.Helper()
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	reserved := Checkpoint{
		Version: Version, OperationID: "80000000-0000-4000-8000-000000000001",
		Request: Request{Connector: "epss_feed", Limit: 200}, Stage: Reserved,
	}
	begin := reserved
	begin.Stage = Begin
	begin.Progress = Progress{RunID: "81000000-0000-4000-8000-000000000001", Scanned: 1, Targets: 1, ScanAfter: "finding-001", Pending: true}
	begin.Prepared = &Prepared{Attempt: Attempt{
		RunID: begin.Progress.RunID, Connector: begin.Request.Connector, StartedAt: start,
		Scope:   journalContractScope(t, []string{"CVE-2026-1234"}),
		Targets: []Target{{FindingID: "finding-001", CVEID: "CVE-2026-1234", Revision: strings.Repeat("a", 64)}},
	}}
	complete := begin
	prepared := *begin.Prepared
	zero := 0.0
	prepared.Completion = &Completion{
		Feed: Feed{
			Source: "epss", Version: "synthetic-journal", PublishedAt: start.Add(-12 * time.Hour), ObservedAt: start.Add(time.Minute),
			SelectedCVEs: []string{"CVE-2026-1234"}, Entries: []Entry{{CVEID: "CVE-2026-1234", EPSS: &zero, Percentile: &zero}},
		},
		OriginalDigest: "sha256:" + strings.Repeat("b", 64), FinishedAt: start.Add(2 * time.Minute),
	}
	complete.Stage, complete.Prepared = Complete, &prepared
	pending := complete
	pending.Stage, pending.Progress.Outcome, pending.Progress.Code = Returned, "pending", "completion_unknown"
	success := pending
	success.Progress.Outcome, success.Progress.Code, success.Progress.Pending = "success", "", false
	success.Progress.Advance, success.Progress.NextAfter = true, success.Progress.ScanAfter
	return []Checkpoint{reserved, begin, complete, pending, success}
}

func TestJournalContractClosedCodecAndBranchedTransitions(t *testing.T) {
	frames := journalContractFrames(t)
	for i, frame := range frames {
		data, err := Encode(frame)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(data)
		if err != nil || !reflect.DeepEqual(got, frame) {
			t.Fatalf("exact typed roundtrip frame=%d: %+v %v", i, got, err)
		}
		var previous *Checkpoint
		if i > 0 {
			previous = &frames[i-1]
		}
		if err := ValidateTransition(previous, frame); err != nil {
			t.Fatalf("valid branched transition frame=%d: %v", i, err)
		}
	}
	if err := ValidateTransition(&frames[1], frames[0]); err == nil {
		t.Fatal("stage rollback accepted")
	}
	collision := frames[1]
	collision.Progress.RunID = "81000000-0000-4000-8000-000000000002"
	if err := ValidateTransition(&frames[1], collision); err == nil {
		t.Fatal("prepared UUID changed")
	}
	valid, err := Encode(frames[0])
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"unknown":           append([]byte("{\"extra\":0,"), valid[1:]...),
		"duplicate-escaped": append([]byte("{\"ver\\u0073ion\":1,"), valid[1:]...),
		"trailing":          append(bytes.Clone(valid), []byte("{}")...),
		"missing":           []byte("{}"),
		"null":              []byte("null"),
		"wrong-type":        bytes.Replace(valid, []byte("\"version\":1"), []byte("\"version\":\"1\""), 1),
		"bad-utf8":          bytes.Replace(valid, []byte(frames[0].OperationID), []byte{0xff}, 1),
		"surrogate":         bytes.Replace(valid, []byte(frames[0].OperationID), []byte("\\ud800"), 1),
		"over-cap":          bytes.Repeat([]byte(" "), MaxCheckpointBytes+1),
	}
	for name, input := range cases {
		if _, err := Decode(input); err == nil {
			t.Fatalf("closed codec accepted %s", name)
		}
	}
}

func TestJournalContractMaximumEscapedCheckpointFitsOneMiB(t *testing.T) {
	frame := journalContractFrames(t)[2]
	frame.Prepared.Attempt.Targets = nil
	frame.Prepared.Completion.Feed.SelectedCVEs = nil
	frame.Prepared.Completion.Feed.Entries = nil
	frame.Prepared.Completion.Feed.Version = strings.Repeat("m", 64)
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("%03d", i) + strings.Repeat("<", 125)
		cve := fmt.Sprintf("CVE-2026-%019d", i+10000)
		frame.Prepared.Attempt.Targets = append(frame.Prepared.Attempt.Targets, Target{FindingID: id, CVEID: cve, Revision: strings.Repeat("f", 64)})
		frame.Prepared.Completion.Feed.SelectedCVEs = append(frame.Prepared.Completion.Feed.SelectedCVEs, cve)
		zero := 0.0
		frame.Prepared.Completion.Feed.Entries = append(frame.Prepared.Completion.Feed.Entries, Entry{CVEID: cve, EPSS: &zero, Percentile: &zero})
		frame.Progress.ScanAfter = id
	}
	frame.Prepared.Attempt.Scope = journalContractScope(t, frame.Prepared.Completion.Feed.SelectedCVEs)
	frame.Progress.Scanned, frame.Progress.Targets = 200, 200
	data, err := Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) >= MaxCheckpointBytes || !bytes.Contains(data, []byte("\\u003c")) {
		t.Fatalf("maximum escaped fixture did not satisfy canonical byte cap: %d", len(data))
	}
	got, err := Decode(data)
	if err != nil || !reflect.DeepEqual(got, frame) {
		t.Fatalf("maximum valid checkpoint did not roundtrip: %v", err)
	}
	oversize := frame
	oversize.Request.After = strings.Repeat("x", MaxCheckpointBytes+1)
	if _, err := Encode(oversize); err == nil {
		t.Fatal("oversize field reached canonical encoding")
	}
}
