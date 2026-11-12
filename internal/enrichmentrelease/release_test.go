package enrichmentrelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func releaseCoreRedigest(t *testing.T, r *ReleaseRequest) {
	t.Helper()
	write := r.Terminal.Checkpoint
	write.Stage = enrichmentjournal.Complete
	write.Progress.Outcome, write.Progress.Code, write.Progress.Pending = "", "", true
	write.Progress.Advance, write.Progress.NextAfter = false, write.Request.After
	if err := enrichmentjournal.ValidateTransition(&write, r.Terminal.Checkpoint); err != nil {
		t.Fatal(err)
	}
	r.Terminal.PreviousDigest = releaseContractDigest(t, write)
	r.TerminalDigest = releaseContractDigest(t, r.Terminal.Checkpoint)
}

func TestReleasePureCopyPreservesClockRepresentationAndPartialEntries(t *testing.T) {
	for _, source := range []string{"epss", "kev"} {
		request := releaseContractRequest(t, source, "success")
		zone := time.FixedZone("synthetic-zone", -5*60*60)
		p := request.Terminal.Checkpoint.Prepared
		p.Attempt.StartedAt = p.Attempt.StartedAt.In(zone)
		p.Completion.FinishedAt = p.Completion.FinishedAt.In(zone)
		p.Completion.Feed.PublishedAt = p.Completion.Feed.PublishedAt.In(zone)
		p.Completion.Feed.ObservedAt = p.Completion.Feed.ObservedAt.In(zone)
		if source == "kev" {
			date := p.Completion.Feed.Entries[0].KEVDateAdded.In(zone)
			p.Completion.Feed.Entries[0].KEVDateAdded = &date
		}
		releaseCoreRedigest(t, &request)
		before, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		got, err := InspectTerminal(request)
		if err != nil || !reflect.DeepEqual(got.Request, request) {
			t.Fatalf("exact input clock representation changed: %v", err)
		}
		if after, err := json.Marshal(request); err != nil || !bytes.Equal(before, after) {
			t.Fatal("inspection mutated its caller during canonical hash validation")
		}
	}
	for _, empty := range []bool{false, true} {
		request := releaseContractRequest(t, "epss", "success")
		request.Terminal.Checkpoint.Prepared.Completion.Feed.Entries = nil
		if empty {
			request.Terminal.Checkpoint.Prepared.Completion.Feed.Entries = []enrichmentjournal.Entry{}
		}
		releaseCoreRedigest(t, &request)
		out, err := InspectTerminal(request)
		if err != nil || !reflect.DeepEqual(out.Request, request) || (out.Request.Terminal.Checkpoint.Prepared.Completion.Feed.Entries == nil) != !empty {
			t.Fatalf("nil/empty legal partial evidence changed: %v", err)
		}
	}
}

func TestReleasePreflightRejectsLargeInputsWithZeroCandidate(t *testing.T) {
	for _, kind := range []string{"root-string", "target-count", "target-cve", "selection-count", "entry-count", "feed-version"} {
		t.Run(kind, func(t *testing.T) {
			request := releaseContractRequest(t, "epss", "success")
			p := request.Terminal.Checkpoint.Prepared
			switch kind {
			case "root-string":
				request.Reservation.Reserved.Checkpoint.Request.After = strings.Repeat("PRIVATE", enrichmentjournal.MaxCheckpointBytes)
			case "target-count":
				p.Attempt.Targets = make([]enrichmentjournal.Target, 201)
			case "target-cve":
				p.Attempt.Targets[0].CVEID = strings.Repeat("PRIVATE", enrichmentjournal.MaxCheckpointBytes)
			case "selection-count":
				p.Completion.Feed.SelectedCVEs = make([]string, 201)
			case "entry-count":
				p.Completion.Feed.Entries = make([]enrichmentjournal.Entry, 201)
			case "feed-version":
				p.Completion.Feed.Version = strings.Repeat("PRIVATE", enrichmentjournal.MaxCheckpointBytes)
			}
			if preflightCheckpoint(request.Reservation.Reserved.Checkpoint) && preflightCheckpoint(request.Terminal.Checkpoint) {
				t.Fatal("oversize data was not rejected before journal marshaling")
			}
			out, err := InspectTerminal(request)
			if !errors.Is(err, errInvalidRelease) || strings.Contains(err.Error(), "PRIVATE") || !reflect.DeepEqual(out, Inspection{}) {
				t.Fatalf("oversize %s leaked input or a candidate: %v", kind, err)
			}
		})
	}
}

func TestReleaseMaximumEscapedLegalCheckpointAndCertificateFitSeparateCaps(t *testing.T) {
	request := releaseContractRequest(t, "epss", "success")
	request.Reservation.ExpectedGeneration = maxGeneration - 1
	cp := &request.Terminal.Checkpoint
	p := cp.Prepared
	p.Attempt.Targets = nil
	p.Completion.Feed.SelectedCVEs = nil
	p.Completion.Feed.Entries = nil
	p.Completion.Feed.Version = strings.Repeat("m", 64)
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("%03d", i) + strings.Repeat("<", 125)
		cve := fmt.Sprintf("CVE-2026-%019d", i+10000)
		p.Attempt.Targets = append(p.Attempt.Targets, enrichmentjournal.Target{FindingID: id, CVEID: cve, Revision: strings.Repeat("f", 64)})
		p.Completion.Feed.SelectedCVEs = append(p.Completion.Feed.SelectedCVEs, cve)
		zero := 0.0
		p.Completion.Feed.Entries = append(p.Completion.Feed.Entries, enrichmentjournal.Entry{CVEID: cve, EPSS: &zero, Percentile: &zero})
		cp.Progress.ScanAfter = id
	}
	selection, err := json.Marshal(p.Completion.Feed.SelectedCVEs)
	if err != nil {
		t.Fatal(err)
	}
	p.Attempt.Scope = fmt.Sprintf("cves-sha256:%x", sha256.Sum256(selection))
	cp.Progress.Scanned, cp.Progress.Targets, cp.Progress.NextAfter = 200, 200, cp.Progress.ScanAfter
	releaseCoreRedigest(t, &request)
	if !preflightCheckpoint(*cp) {
		t.Fatal("maximum existing legal shape was newly narrowed")
	}
	encoded, err := enrichmentjournal.Encode(*cp)
	if err != nil || len(encoded) >= enrichmentjournal.MaxCheckpointBytes || !bytes.Contains(encoded, []byte("\\u003c")) {
		t.Fatalf("maximum escaped checkpoint fixture invalid: %v", err)
	}
	out, err := InspectTerminal(request)
	if err != nil || !reflect.DeepEqual(out.Request, request) {
		t.Fatalf("maximum escaped checkpoint inspection failed: %v", err)
	}
	certificate := releaseContractCertificate(request)
	raw, err := EncodeCertificate(certificate)
	if err != nil || len(raw) > MaxCertificateBytes || len(raw) >= len(encoded) || certificate.Generation != maxGeneration {
		t.Fatal("small certificate was confused with full checkpoint bytes/generation")
	}
	if decoded, err := DecodeCertificate(raw); err != nil || !reflect.DeepEqual(decoded, certificate) {
		t.Fatal("maximum-width certificate scalar data failed roundtrip")
	}
}

func TestCertificateStrictNumericUnicodeAndDecodedOwnership(t *testing.T) {
	c := releaseContractCertificate(releaseContractRequest(t, "epss", "success"))
	data, err := EncodeCertificate(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		bytes.Replace(data, []byte("\"version\":1"), []byte("\"version\":1.0"), 1),
		bytes.Replace(data, []byte("\"version\":1"), []byte("\"version\":1e0"), 1),
		bytes.Replace(data, []byte("\"generation\":1"), []byte("\"generation\":9223372036854775808"), 1),
		bytes.Replace(data, []byte("\"receipt\":\""+c.Receipt+"\""), []byte("\"receipt\":{}"), 1),
		append([]byte("{\"Version\":1,"), data[1:]...),
		bytes.Replace(data, []byte(c.OperationID), []byte("\\udc00"), 1),
	} {
		out, err := DecodeCertificate(input)
		if !errors.Is(err, errInvalidRelease) || !reflect.DeepEqual(out, Certificate{}) {
			t.Fatal("invalid scalar/Unicode/case alias returned certificate data")
		}
	}
	first, err := DecodeCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DecodeCertificate(data)
	if err != nil {
		t.Fatal(err)
	}
	*first.RunID = "PRIVATE-changed"
	if *second.RunID != *c.RunID {
		t.Fatal("separate decodes share a mutable run pointer")
	}
	data[0] = '['
	if second.OperationID != c.OperationID || second.Receipt != c.Receipt || *second.RunID != *c.RunID {
		t.Fatal("decoded data retained mutable input bytes")
	}
}
