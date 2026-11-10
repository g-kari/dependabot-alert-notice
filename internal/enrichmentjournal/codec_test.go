package enrichmentjournal

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func copyJournalFrame(t *testing.T, frame Checkpoint) Checkpoint {
	t.Helper()
	data, err := Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestJournalCodecPreservesLegalPartialAndNullableEvidence(t *testing.T) {
	for _, kind := range []string{"nil-empty", "array-empty", "subset", "kev-nonmidnight", "offset-clocks"} {
		t.Run(kind, func(t *testing.T) {
			frame := journalContractFrames(t)[2]
			switch kind {
			case "nil-empty":
				frame.Prepared.Completion.Feed.Entries = nil
			case "array-empty":
				frame.Prepared.Completion.Feed.Entries = []Entry{}
			case "subset":
				other := Target{FindingID: "finding-002", CVEID: "CVE-2026-1235", Revision: strings.Repeat("c", 64)}
				frame.Prepared.Attempt.Targets = append(frame.Prepared.Attempt.Targets, other)
				frame.Prepared.Completion.Feed.SelectedCVEs = append(frame.Prepared.Completion.Feed.SelectedCVEs, other.CVEID)
				frame.Prepared.Attempt.Scope = journalContractScope(t, frame.Prepared.Completion.Feed.SelectedCVEs)
				frame.Progress.Scanned, frame.Progress.Targets, frame.Progress.ScanAfter = 2, 2, other.FindingID
			case "kev-nonmidnight":
				frame.Request.Connector, frame.Prepared.Attempt.Connector = "kev_feed", "kev_feed"
				frame.Prepared.Completion.Feed.Source = "kev"
				date := frame.Prepared.Completion.Feed.PublishedAt.Add(-time.Hour)
				frame.Prepared.Completion.Feed.Entries = []Entry{{CVEID: "CVE-2026-1234", KEV: true, KEVDateAdded: &date}}
			case "offset-clocks":
				zone := time.FixedZone("synthetic-second-offset", 3661)
				frame.Prepared.Attempt.StartedAt = frame.Prepared.Attempt.StartedAt.In(zone)
				frame.Prepared.Completion.Feed.PublishedAt = frame.Prepared.Completion.Feed.PublishedAt.In(zone)
				frame.Prepared.Completion.Feed.ObservedAt = frame.Prepared.Completion.Feed.ObservedAt.In(zone)
				frame.Prepared.Completion.FinishedAt = frame.Prepared.Completion.FinishedAt.In(zone)
			}
			data, err := Encode(frame)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(data)
			if err != nil || !reflect.DeepEqual(got, canonicalCheckpoint(frame)) {
				t.Fatalf("legal partial/null/date changed: %+v %v", got, err)
			}
			if !got.Prepared.Attempt.StartedAt.Equal(frame.Prepared.Attempt.StartedAt) || !got.Prepared.Completion.Feed.PublishedAt.Equal(frame.Prepared.Completion.Feed.PublishedAt) || !got.Prepared.Completion.Feed.ObservedAt.Equal(frame.Prepared.Completion.Feed.ObservedAt) || !got.Prepared.Completion.FinishedAt.Equal(frame.Prepared.Completion.FinishedAt) {
				t.Fatal("UTC representation changed source/business clock instants")
			}
			if kind == "nil-empty" && got.Prepared.Completion.Feed.Entries != nil || kind == "array-empty" && got.Prepared.Completion.Feed.Entries == nil {
				t.Fatal("nil and empty entries were silently normalized")
			}
		})
	}
	bad := journalContractFrames(t)[2]
	bad.Prepared.Completion.Feed.Entries[0].Percentile = nil
	if _, err := Encode(bad); err == nil {
		t.Fatal("missing percentile became known zero")
	}
}

func TestJournalCodecExactKeysRequiredNullAndUnicode(t *testing.T) {
	frame := journalContractFrames(t)[0]
	data, err := Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"case-alias":               bytes.Replace(data, []byte("\"version\":"), []byte("\"Version\":"), 1),
		"case-alias-plus-required": append([]byte("{\"Version\":1,"), data[1:]...),
		"required-null":            bytes.Replace(data, []byte("\"request\":{"), []byte("\"request\":null,\"ignored\":{"), 1),
		"integer-exponent":         bytes.Replace(data, []byte("\"version\":1"), []byte("\"version\":1e0"), 1),
		"boolean-null":             bytes.Replace(data, []byte("\"advance\":false"), []byte("\"advance\":null"), 1),
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	fields["request"] = json.RawMessage("null")
	nullRequired, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	cases["required-null-only"] = nullRequired
	for name, input := range cases {
		if _, err := Decode(input); err == nil {
			t.Fatalf("codec accepted %s", name)
		}
	}
	frame.Request.After, frame.Progress.NextAfter = "雪😀", "雪😀"
	data, err = Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("😀"), []byte("\\ud83d\\ude00"))
	got, err := Decode(data)
	if err != nil || !reflect.DeepEqual(got, frame) {
		t.Fatalf("valid UTF8/surrogate pair rejected: %+v %v", got, err)
	}
}

func TestJournalTransitionsCoverPreBeginReturnsAndRejectPreparedMutation(t *testing.T) {
	reserved := journalContractFrames(t)[0]
	for _, kind := range []string{"no_targets", "exhausted", "invalid", "error", "canceled"} {
		next := reserved
		next.Stage, next.Progress.Outcome = Returned, kind
		switch kind {
		case "no_targets":
			next.Progress.Scanned, next.Progress.ScanAfter = 1, "finding-001"
			next.Progress.Advance, next.Progress.NextAfter = true, "finding-001"
		case "exhausted":
			next.Progress.Exhausted = true
		case "invalid":
			next.Progress.Code = "invalid_clock"
			next.Progress.Scanned, next.Progress.Targets, next.Progress.ScanAfter = 1, 1, "finding-001"
		case "error":
			next.Progress.Code = "scan_failed"
		case "canceled":
			next.Progress.Code = "canceled"
			next.Progress.Scanned, next.Progress.Targets, next.Progress.ScanAfter = 1, 1, "finding-001"
		}
		if err := ValidateTransition(&reserved, next); err != nil {
			t.Fatalf("valid pre-Begin %s rejected: %v", kind, err)
		}
	}
	complete := journalContractFrames(t)[2]
	for _, kind := range []string{"target", "digest", "feed", "scan", "source", "UUID"} {
		next := copyJournalFrame(t, complete)
		next.Stage, next.Progress.Outcome, next.Progress.Code = Returned, "pending", "completion_unknown"
		switch kind {
		case "target":
			next.Prepared.Attempt.Targets[0].Revision = strings.Repeat("c", 64)
		case "digest":
			next.Prepared.Completion.OriginalDigest = "sha256:" + strings.Repeat("c", 64)
		case "feed":
			*next.Prepared.Completion.Feed.Entries[0].EPSS = 1
		case "scan":
			next.Progress.Scanned, next.Progress.ScanAfter = 2, "finding-002"
		case "source":
			next.Request.Connector = "kev_feed"
		case "UUID":
			next.Prepared.Attempt.RunID, next.Progress.RunID = "81000000-0000-4000-8000-000000000002", "81000000-0000-4000-8000-000000000002"
		}
		if err := ValidateTransition(&complete, next); err == nil {
			t.Fatalf("changed %s accepted", kind)
		}
	}
	begin := journalContractFrames(t)[1]
	for _, code := range []string{"fetch_failed", "parse_failed", "invalid_metadata", "target_changed", "store_failed", "canceled"} {
		next := copyJournalFrame(t, begin)
		next.Stage, next.Prepared.Failure = Fail, &Failure{Code: code, FinishedAt: begin.Prepared.Attempt.StartedAt.Add(time.Minute)}
		if err := ValidateTransition(&begin, next); err != nil {
			t.Fatalf("existing legal failure code %s narrowed: %v", code, err)
		}
	}
}
