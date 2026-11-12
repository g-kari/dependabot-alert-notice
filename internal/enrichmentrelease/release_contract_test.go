package enrichmentrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func releaseContractDigest(t *testing.T, checkpoint enrichmentjournal.Checkpoint) string {
	t.Helper()
	data, err := enrichmentjournal.Encode(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

func releaseContractRequest(t *testing.T, source, outcome string) ReleaseRequest {
	t.Helper()
	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	reserved := enrichmentjournal.Checkpoint{
		Version: enrichmentjournal.Version, OperationID: "b1000000-0000-4000-8000-000000000001",
		Request: enrichmentjournal.Request{Connector: source + "_feed", Limit: 200}, Stage: enrichmentjournal.Reserved,
	}
	request := ReleaseRequest{Reservation: ReservationRequest{
		IntentID:       "b2000000-0000-4000-8000-000000000001",
		Reserved:       enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: reserved},
		ReservedDigest: releaseContractDigest(t, reserved),
	}}
	terminal := reserved
	terminal.Stage = enrichmentjournal.Returned
	terminal.Progress.Outcome = outcome
	request.Terminal.Sequence = 2
	request.Terminal.PreviousDigest = request.Reservation.ReservedDigest
	switch outcome {
	case "no_targets":
		terminal.Progress.Scanned, terminal.Progress.ScanAfter = 1, "finding-001"
		terminal.Progress.Advance, terminal.Progress.NextAfter = true, terminal.Progress.ScanAfter
	case "exhausted":
		terminal.Progress.Exhausted = true
	case "invalid":
		terminal.Progress.Scanned, terminal.Progress.Targets, terminal.Progress.ScanAfter = 1, 1, "finding-001"
		terminal.Progress.Code = "invalid_clock"
	case "error":
		terminal.Progress.Code = "scan_failed"
	case "canceled":
		terminal.Progress.Scanned, terminal.Progress.Targets, terminal.Progress.ScanAfter = 1, 1, "finding-001"
		terminal.Progress.Code = "canceled"
	case "success", "failed":
		cves := []string{"CVE-2026-1234"}
		selected, err := json.Marshal(cves)
		if err != nil {
			t.Fatal(err)
		}
		begin := reserved
		begin.Stage = enrichmentjournal.Begin
		begin.Progress = enrichmentjournal.Progress{RunID: "b3000000-0000-4000-8000-000000000001", Scanned: 1, Targets: 1, ScanAfter: "finding-001", Pending: true}
		begin.Prepared = &enrichmentjournal.Prepared{Attempt: enrichmentjournal.Attempt{
			RunID: begin.Progress.RunID, Connector: reserved.Request.Connector,
			Scope: fmt.Sprintf("cves-sha256:%x", sha256.Sum256(selected)), StartedAt: at,
			Targets: []enrichmentjournal.Target{{FindingID: "finding-001", CVEID: cves[0], Revision: strings.Repeat("a", 64)}},
		}}
		write := begin
		prepared := *begin.Prepared
		if outcome == "success" {
			zero, date := 0.0, at.Add(-12*time.Hour)
			entry := enrichmentjournal.Entry{CVEID: cves[0], EPSS: &zero, Percentile: &zero}
			if source == "kev" {
				entry = enrichmentjournal.Entry{CVEID: cves[0], KEV: true, KEVDateAdded: &date}
			}
			prepared.Completion = &enrichmentjournal.Completion{
				Feed:           enrichmentjournal.Feed{Source: source, Version: "synthetic-release", PublishedAt: date, ObservedAt: at.Add(time.Minute), SelectedCVEs: cves, Entries: []enrichmentjournal.Entry{entry}},
				OriginalDigest: "sha256:" + strings.Repeat("b", 64), FinishedAt: at.Add(2 * time.Minute),
			}
			write.Stage = enrichmentjournal.Complete
		} else {
			prepared.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: at.Add(2 * time.Minute)}
			write.Stage = enrichmentjournal.Fail
		}
		write.Prepared = &prepared
		terminal = write
		terminal.Stage, terminal.Progress.Outcome, terminal.Progress.Pending = enrichmentjournal.Returned, outcome, false
		if outcome == "success" {
			terminal.Progress.Advance, terminal.Progress.NextAfter = true, terminal.Progress.ScanAfter
		} else {
			terminal.Progress.Code = prepared.Failure.Code
		}
		for _, pair := range [][2]enrichmentjournal.Checkpoint{{reserved, begin}, {begin, write}, {write, terminal}} {
			if err := enrichmentjournal.ValidateTransition(&pair[0], pair[1]); err != nil {
				t.Fatal(err)
			}
		}
		request.Terminal.Sequence = 4
		request.Terminal.PreviousDigest = releaseContractDigest(t, write)
	default:
		t.Fatal("unknown synthetic outcome")
	}
	if terminal.Prepared == nil {
		if err := enrichmentjournal.ValidateTransition(&reserved, terminal); err != nil {
			t.Fatal(err)
		}
	}
	request.Terminal.Checkpoint = terminal
	request.TerminalDigest = releaseContractDigest(t, terminal)
	return request
}

func releaseContractCertificate(request ReleaseRequest) Certificate {
	cp := request.Terminal.Checkpoint
	kind, receipt := cp.Progress.Outcome, ""
	var runID *string
	if cp.Prepared == nil {
		kind = "no_run"
	} else {
		id := cp.Progress.RunID
		runID = &id
		if kind == "success" {
			// Synthetic receipt-shaped data only, not obtained business proof.
			receipt = "refresh-success-v1:sha256:" + strings.Repeat("c", 64)
		}
	}
	return Certificate{
		Version: CertificateVersion, OperationID: cp.OperationID, IntentID: request.Reservation.IntentID,
		Connector: cp.Request.Connector, Generation: request.Reservation.ExpectedGeneration + 1,
		ReservedDigest: request.Reservation.ReservedDigest, TerminalSequence: request.Terminal.Sequence,
		TerminalPreviousDigest: request.Terminal.PreviousDigest, TerminalDigest: request.TerminalDigest,
		Kind: kind, RunID: runID, Receipt: receipt,
	}
}

func TestReleaseContractAllLegalTerminalBranchesArePureCandidates(t *testing.T) {
	for _, branch := range []struct{ source, outcome string }{
		{"epss", "success"}, {"kev", "success"}, {"epss", "failed"},
		{"epss", "no_targets"}, {"epss", "exhausted"}, {"epss", "invalid"}, {"epss", "error"}, {"epss", "canceled"},
	} {
		t.Run(branch.source+"/"+branch.outcome, func(t *testing.T) {
			request := releaseContractRequest(t, branch.source, branch.outcome)
			got, err := InspectTerminal(request)
			if err != nil {
				t.Fatal(err)
			}
			kind, run := branch.outcome, request.Terminal.Checkpoint.Progress.RunID
			if request.Terminal.Checkpoint.Prepared == nil {
				kind = "no_run"
			}
			if got.Kind != kind || got.RunID != run || !reflect.DeepEqual(got.Request, request) {
				t.Fatal("pure terminal inspection changed retained values or invented a run")
			}
		})
	}
}

func TestReleaseContractIndependentClosedCertificateCodec(t *testing.T) {
	certificate := releaseContractCertificate(releaseContractRequest(t, "epss", "success"))
	data, err := EncodeCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || len(data) > MaxCertificateBytes || !json.Valid(data) {
		t.Fatal("small independent certificate failed its byte contract")
	}
	got, err := DecodeCertificate(data)
	if err != nil || !reflect.DeepEqual(got, certificate) {
		t.Fatalf("typed certificate roundtrip differs: %v", err)
	}
	cases := map[string][]byte{
		"unknown":           append([]byte("{\"extra\":0,"), data[1:]...),
		"duplicate-escaped": append([]byte("{\"ver\\u0073ion\":1,"), data[1:]...),
		"case-alias":        bytes.Replace(data, []byte("\"version\":1"), []byte("\"Version\":1"), 1),
		"missing":           bytes.Replace(data, []byte("\"version\":1,"), nil, 1),
		"wrong-type":        bytes.Replace(data, []byte("\"version\":1"), []byte("\"version\":\"1\""), 1),
		"version":           bytes.Replace(data, []byte("\"version\":1"), []byte("\"version\":2"), 1),
		"required-null":     bytes.Replace(data, []byte("\"operation_id\":\""+certificate.OperationID+"\""), []byte("\"operation_id\":null"), 1),
		"run-null":          bytes.Replace(data, []byte("\"run_id\":\""+*certificate.RunID+"\""), []byte("\"run_id\":null"), 1),
		"trailing":          append(bytes.Clone(data), []byte("{}")...),
		"invalid-utf8":      bytes.Replace(data, []byte(certificate.OperationID), []byte{0xff}, 1),
		"surrogate":         bytes.Replace(data, []byte(certificate.OperationID), []byte("\\ud800"), 1),
		"oversize":          bytes.Repeat([]byte(" "), MaxCertificateBytes+1),
	}
	for name, raw := range cases {
		if _, err := DecodeCertificate(raw); err == nil {
			t.Fatalf("closed certificate decoder accepted %s", name)
		}
	}
	tooLarge := certificate
	tooLarge.Receipt = strings.Repeat("PRIVATE", MaxCertificateBytes+1)
	if _, err := EncodeCertificate(tooLarge); err == nil {
		t.Fatal("oversized field reached certificate marshaling")
	}
	noRun := releaseContractCertificate(releaseContractRequest(t, "epss", "exhausted"))
	raw, err := EncodeCertificate(noRun)
	if err != nil || !bytes.Contains(raw, []byte("\"run_id\":null")) {
		t.Fatal("no-run null identity was replaced by a UUID")
	}
	decoded, err := DecodeCertificate(raw)
	if err != nil || decoded.RunID != nil || decoded.Receipt != "" || decoded.Kind != "no_run" {
		t.Fatal("no-run certificate syntax became a business receipt")
	}
}

func TestReleaseContractBindingRejectionAndNestedOwnership(t *testing.T) {
	request := releaseContractRequest(t, "epss", "success")
	if _, err := InspectTerminal(request); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"intent", "generation-negative", "generation-overflow", "reserved-sequence", "reserved-digest", "operation", "source", "request", "terminal-digest", "sequence", "previous", "begin", "complete", "pending"} {
		t.Run(kind, func(t *testing.T) {
			wrong := releaseContractRequest(t, "epss", "success")
			switch kind {
			case "intent":
				wrong.Reservation.IntentID = "PRIVATE-invalid"
			case "generation-negative":
				wrong.Reservation.ExpectedGeneration = -1
			case "generation-overflow":
				wrong.Reservation.ExpectedGeneration = 9223372036854775807
			case "reserved-sequence":
				wrong.Reservation.Reserved.Sequence = 2
			case "reserved-digest":
				wrong.Reservation.ReservedDigest = "sha256:" + strings.Repeat("f", 64)
			case "operation":
				wrong.Terminal.Checkpoint.OperationID = "b1000000-0000-4000-8000-000000000002"
			case "source":
				wrong.Reservation.Reserved.Checkpoint.Request.Connector = "kev_feed"
				wrong.Reservation.ReservedDigest = releaseContractDigest(t, wrong.Reservation.Reserved.Checkpoint)
			case "request":
				wrong.Reservation.Reserved.Checkpoint.Request.Limit = 1
				wrong.Reservation.ReservedDigest = releaseContractDigest(t, wrong.Reservation.Reserved.Checkpoint)
			case "terminal-digest":
				wrong.TerminalDigest = "sha256:" + strings.Repeat("f", 64)
			case "sequence":
				wrong.Terminal.Sequence = 1
			case "previous":
				wrong.Terminal.PreviousDigest = ""
			case "begin":
				p := *wrong.Terminal.Checkpoint.Prepared
				p.Completion = nil
				wrong.Terminal.Checkpoint.Prepared, wrong.Terminal.Checkpoint.Stage = &p, enrichmentjournal.Begin
				wrong.Terminal.Checkpoint.Progress.Outcome = ""
				wrong.Terminal.Checkpoint.Progress.Pending = true
				wrong.Terminal.Checkpoint.Progress.Advance = false
				wrong.Terminal.Checkpoint.Progress.NextAfter = ""
			case "complete":
				wrong.Terminal.Checkpoint.Stage = enrichmentjournal.Complete
				wrong.Terminal.Checkpoint.Progress.Outcome = ""
				wrong.Terminal.Checkpoint.Progress.Pending = true
				wrong.Terminal.Checkpoint.Progress.Advance = false
				wrong.Terminal.Checkpoint.Progress.NextAfter = ""
			case "pending":
				wrong.Terminal.Checkpoint.Progress.Outcome, wrong.Terminal.Checkpoint.Progress.Code = "pending", "completion_unknown"
				wrong.Terminal.Checkpoint.Progress.Pending, wrong.Terminal.Checkpoint.Progress.Advance = true, false
				wrong.Terminal.Checkpoint.Progress.NextAfter = ""
			}
			if kind == "operation" || kind == "begin" || kind == "complete" || kind == "pending" {
				// Keep these otherwise-valid journal payloads honestly digested;
				// eligibility/binding, not a stale hash, must reject them.
				wrong.TerminalDigest = releaseContractDigest(t, wrong.Terminal.Checkpoint)
			}
			if _, err := InspectTerminal(wrong); err == nil {
				t.Fatalf("pure release inspection accepted %s", kind)
			}
		})
	}
	owned, err := InspectTerminal(request)
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	owned.Request.Terminal.Checkpoint.Prepared.Attempt.Targets[0].FindingID = "PRIVATE-target"
	owned.Request.Terminal.Checkpoint.Prepared.Completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
	*owned.Request.Terminal.Checkpoint.Prepared.Completion.Feed.Entries[0].EPSS = 1
	after, err := json.Marshal(request)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("returned nested copy mutated retained request")
	}
	kev := releaseContractRequest(t, "kev", "success")
	copy, err := InspectTerminal(kev)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := json.Marshal(copy)
	if err != nil {
		t.Fatal(err)
	}
	*kev.Terminal.Checkpoint.Prepared.Completion.Feed.Entries[0].KEVDateAdded = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	kev.Terminal.Checkpoint.Prepared.Attempt.Targets[0].Revision = strings.Repeat("f", 64)
	current, err := json.Marshal(copy)
	if err != nil || !bytes.Equal(snapshot, current) {
		t.Fatal("later caller pointer/slice mutation changed owned inspection")
	}
}
