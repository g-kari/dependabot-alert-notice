package enrichmentrelease

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func releaseLockedResolvedRequest(t *testing.T, source, outcome string) ReleaseRequest {
	t.Helper()
	request := releaseContractRequest(t, source, outcome)
	terminal := request.Terminal.Checkpoint
	write := terminal
	write.Progress.Outcome, write.Progress.Code, write.Progress.Pending = "", "", true
	write.Progress.Advance, write.Progress.Exhausted, write.Progress.NextAfter = false, false, write.Request.After
	pending := write
	if outcome == "success" {
		write.Stage = enrichmentjournal.Complete
		pending.Progress.Code = "completion_unknown"
	} else {
		write.Stage = enrichmentjournal.Fail
		pending.Progress.Code = "failure_unknown"
	}
	pending.Stage, pending.Progress.Outcome = enrichmentjournal.Returned, "pending"
	if releaseContractDigest(t, write) != request.Terminal.PreviousDigest {
		t.Fatal("synthetic previous write does not match the retained sequence-four fixture")
	}
	for _, pair := range [][2]enrichmentjournal.Checkpoint{{write, pending}, {pending, terminal}} {
		if err := enrichmentjournal.ValidateTransition(&pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
		_ = releaseContractDigest(t, pair[1])
	}
	request.Terminal.Sequence = 5
	request.Terminal.PreviousDigest = releaseContractDigest(t, pending)
	// Only this test fixture knows the last edges. The public retained
	// request still contains root+terminal, not a stored intermediate history
	// or any SQL/business proof.
	return request
}

func TestReleaseLockedContractBranchSequenceAndResolvedPending(t *testing.T) {
	for _, branch := range []struct{ source, outcome string }{{"epss", "success"}, {"kev", "success"}, {"epss", "failed"}} {
		t.Run(branch.source+"/"+branch.outcome, func(t *testing.T) {
			request := releaseLockedResolvedRequest(t, branch.source, branch.outcome)
			got, err := InspectTerminal(request)
			if err != nil {
				t.Fatal(err)
			}
			if got.Kind != branch.outcome || got.Request.Terminal.Sequence != 5 || !reflect.DeepEqual(got.Request, request) {
				t.Fatal("legal sequence-five candidate was rejected or changed")
			}
			for _, sequence := range []int64{0, 1, 2, 3, 6} {
				wrong := request
				wrong.Terminal.Sequence = sequence
				if _, err := InspectTerminal(wrong); err == nil {
					t.Fatalf("prepared terminal accepted sequence %d", sequence)
				}
			}
		})
	}
	for _, outcome := range []string{"no_targets", "exhausted", "invalid", "error", "canceled"} {
		request := releaseContractRequest(t, "epss", outcome)
		if got, err := InspectTerminal(request); err != nil || got.Kind != "no_run" || got.Request.Terminal.Sequence != 2 {
			t.Fatalf("legal sequence-two no-run candidate %s: %v", outcome, err)
		}
		for _, sequence := range []int64{0, 1, 3, 4, 5, 6} {
			wrong := request
			wrong.Terminal.Sequence = sequence
			if _, err := InspectTerminal(wrong); err == nil {
				t.Fatalf("no-run terminal accepted sequence %d", sequence)
			}
		}
		wrong := request
		wrong.Terminal.PreviousDigest = "sha256:" + strings.Repeat("f", 64)
		if _, err := InspectTerminal(wrong); err == nil {
			t.Fatal("sequence-two no-run previous head did not equal its retained reserved digest")
		}
	}
}

func TestReleaseLockedContractCertificateBranchesRequiredFieldsAndReceipt(t *testing.T) {
	failed := releaseContractCertificate(releaseLockedResolvedRequest(t, "epss", "failed"))
	data, err := EncodeCertificate(failed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCertificate(data)
	if err != nil || !reflect.DeepEqual(failed, decoded) || failed.RunID == nil || failed.Receipt != "" {
		t.Fatal("legal failed certificate data did not roundtrip")
	}
	success := releaseContractCertificate(releaseLockedResolvedRequest(t, "epss", "success"))
	noRun := releaseContractCertificate(releaseContractRequest(t, "epss", "exhausted"))
	for _, certificate := range []Certificate{success, noRun} {
		raw, err := EncodeCertificate(certificate)
		if err != nil {
			t.Fatal(err)
		}
		if roundtrip, err := DecodeCertificate(raw); err != nil || !reflect.DeepEqual(certificate, roundtrip) {
			t.Fatal("legal success/no-run certificate data changed")
		}
	}
	// security_enrichment_refresh.go:70-75 constructs this closed form from
	// hex.EncodeToString(SHA256). This remains syntax, never SQL proof.
	receipt := "refresh-success-v1:sha256:" + strings.Repeat("c", 64)
	for _, kind := range []string{
		"unknown-kind", "pending-kind", "generation-zero", "generation-negative",
		"prepared-seq2", "prepared-seq3", "prepared-seq6", "operation-id", "intent-id", "source",
		"reserved-digest", "terminal-digest", "previous-format", "success-null-run", "success-invalid-run",
		"success-empty-receipt", "success-short-receipt", "success-wrong-prefix", "success-short-hash", "success-uppercase-hash",
		"failed-null-run", "failed-invalid-run", "failed-seq2", "failed-receipt",
		"no-run-run-id", "no-run-seq4", "no-run-previous-binding", "no-run-receipt",
	} {
		t.Run(kind, func(t *testing.T) {
			wrong := success
			if strings.HasPrefix(kind, "failed-") {
				wrong = failed
			} else if strings.HasPrefix(kind, "no-run-") {
				wrong = noRun
			}
			switch kind {
			case "unknown-kind":
				wrong.Kind = "PRIVATE"
			case "pending-kind":
				wrong.Kind = "pending"
			case "generation-zero":
				wrong.Generation = 0
			case "generation-negative":
				wrong.Generation = -1
			case "prepared-seq2", "failed-seq2":
				wrong.TerminalSequence = 2
			case "prepared-seq3":
				wrong.TerminalSequence = 3
			case "prepared-seq6":
				wrong.TerminalSequence = 6
			case "operation-id":
				wrong.OperationID = "PRIVATE"
			case "intent-id":
				wrong.IntentID = "PRIVATE"
			case "source":
				wrong.Connector = "epss_offline"
			case "reserved-digest":
				wrong.ReservedDigest = ""
			case "terminal-digest":
				wrong.TerminalDigest = "sha256:" + strings.Repeat("A", 64)
			case "previous-format":
				wrong.TerminalPreviousDigest = ""
			case "success-null-run", "failed-null-run":
				wrong.RunID = nil
			case "success-invalid-run", "failed-invalid-run":
				id := "PRIVATE"
				wrong.RunID = &id
			case "success-empty-receipt":
				wrong.Receipt = ""
			case "success-short-receipt":
				wrong.Receipt = "short"
			case "success-wrong-prefix":
				wrong.Receipt = "refresh-attempt-v1:sha256:" + strings.Repeat("c", 64)
			case "success-short-hash":
				wrong.Receipt = "refresh-success-v1:sha256:" + strings.Repeat("c", 63)
			case "success-uppercase-hash":
				wrong.Receipt = "refresh-success-v1:sha256:" + strings.Repeat("A", 64)
			case "failed-receipt", "no-run-receipt":
				wrong.Receipt = receipt
			case "no-run-run-id":
				id := "b3000000-0000-4000-8000-000000000001"
				wrong.RunID = &id
			case "no-run-seq4":
				wrong.TerminalSequence = 4
			case "no-run-previous-binding":
				wrong.TerminalPreviousDigest = "sha256:" + strings.Repeat("f", 64)
			}
			if _, err := EncodeCertificate(wrong); err == nil {
				t.Fatalf("certificate encoder accepted %s", kind)
			}
			raw, err := json.Marshal(wrong)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeCertificate(raw); err == nil {
				t.Fatalf("certificate decoder accepted %s", kind)
			}
		})
	}
	// All fields are required, including nullable run_id and empty receipt.
	// Dropping run_id must not be normalized into no_run's legitimate null.
	raw, err := json.Marshal(noRun)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		t.Run("missing/"+name, func(t *testing.T) {
			missing := make(map[string]json.RawMessage, len(fields))
			for key, value := range fields {
				if key != name {
					missing[key] = value
				}
			}
			input, err := json.Marshal(missing)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeCertificate(input); err == nil {
				t.Fatalf("certificate decoder accepted missing %s", name)
			}
		})
	}
	fields["receipt"] = json.RawMessage("null")
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCertificate(raw); err == nil {
		t.Fatal("no-run receipt:null was normalized to an empty required string")
	}
}
