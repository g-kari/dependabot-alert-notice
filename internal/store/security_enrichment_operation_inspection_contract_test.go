package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func inspectionContractFrames(t *testing.T, c SecurityEnrichmentRefreshCompletion, id int) []enrichmentjournal.Checkpoint {
	t.Helper()
	reserved := enrichmentjournal.Checkpoint{Version: 1, OperationID: fmt.Sprintf("90000000-0000-4000-8000-%012d", id), Request: enrichmentjournal.Request{Connector: c.Attempt.Connector, Limit: 200}, Stage: enrichmentjournal.Reserved}
	begin := reserved
	begin.Stage = enrichmentjournal.Begin
	begin.Progress = enrichmentjournal.Progress{RunID: c.Attempt.RunID, Scanned: len(c.Attempt.Targets), Targets: len(c.Attempt.Targets), ScanAfter: c.Attempt.Targets[len(c.Attempt.Targets)-1].FindingID, Pending: true}
	attempt := enrichmentjournal.Attempt{RunID: c.Attempt.RunID, Connector: c.Attempt.Connector, Scope: c.Attempt.Scope, StartedAt: c.Attempt.StartedAt}
	for _, target := range c.Attempt.Targets {
		attempt.Targets = append(attempt.Targets, enrichmentjournal.Target{FindingID: target.FindingID, CVEID: target.CVEID, Revision: target.Revision})
	}
	begin.Prepared = &enrichmentjournal.Prepared{Attempt: attempt}
	complete := begin
	p := *begin.Prepared
	feed := enrichmentjournal.Feed{Source: c.Feed.Source, Version: c.Feed.Version, PublishedAt: c.Feed.PublishedAt, ObservedAt: c.Feed.ObservedAt}
	feed.SelectedCVEs = append([]string(nil), c.Feed.SelectedCVEs...)
	if c.Feed.Entries != nil {
		feed.Entries = make([]enrichmentjournal.Entry, len(c.Feed.Entries))
		for i, entry := range c.Feed.Entries {
			e := enrichmentjournal.Entry{CVEID: entry.CVEID, KEV: entry.KEV}
			if entry.EPSS != nil {
				value := *entry.EPSS
				e.EPSS = &value
			}
			if entry.Percentile != nil {
				value := *entry.Percentile
				e.Percentile = &value
			}
			if entry.KEVDateAdded != nil {
				date := *entry.KEVDateAdded
				e.KEVDateAdded = &date
			}
			feed.Entries[i] = e
		}
	}
	p.Completion = &enrichmentjournal.Completion{Feed: feed, OriginalDigest: c.OriginalDigest, FinishedAt: c.FinishedAt}
	complete.Stage, complete.Prepared = enrichmentjournal.Complete, &p
	success := complete
	success.Stage = enrichmentjournal.Returned
	success.Progress.Outcome, success.Progress.Pending, success.Progress.Advance, success.Progress.NextAfter = "success", false, true, success.Progress.ScanAfter
	return []enrichmentjournal.Checkpoint{reserved, begin, complete, success}
}
func inspectionContractHash(t *testing.T, db *Store) string {
	t.Helper()
	return fmt.Sprintf("%x", sha256.Sum256([]byte(journalSnapshot(t, db, false))))
}
func inspectionAppendFrames(t *testing.T, db *Store, frames []enrichmentjournal.Checkpoint) enrichmentjournal.Acknowledgement {
	t.Helper()
	previous := ""
	var ack enrichmentjournal.Acknowledgement
	for i, frame := range frames {
		ack = appendJournalFrame(t, db, frame, int64(i+1), previous)
		previous = ack.Digest
	}
	return ack
}

func TestOperationInspectionContractHistoricalProofSurvivesCurrentFactAndFindingChanges(t *testing.T) {
	for index, source := range []string{"epss", "kev"} {
		t.Run(source, func(t *testing.T) {
			db, c := refreshContractFixture(t, source, 1700+index)
			ctx := context.Background()
			frames := inspectionContractFrames(t, c, 1700+index)
			head := inspectionAppendFrames(t, db, frames[:3]) // No returned-success claim.
			if _, err := db.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
				t.Fatal(err)
			}
			if _, err := db.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
				t.Fatal(err)
			}
			proof, err := db.ReconcileSecurityEnrichmentRefresh(ctx, c)
			if err != nil || proof.State != "success" || proof.Receipt == "" {
				t.Fatal("real historical proof absent")
			}
			newer, newFeed := enrichmentFixture(t, 1750+index, source, c.Feed.PublishedAt.Add(time.Minute), c.Feed.ObservedAt.Add(time.Minute))
			mustEnrichment(t, db, newer, newFeed)
			if _, err := db.db.Exec("UPDATE findings SET body_json=json_set(body_json,'$.title','later synthetic revision') WHERE id=?", c.Attempt.Targets[0].FindingID); err != nil {
				t.Fatal(err)
			}
			detail, err := db.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
			if err != nil || detail.Enrichment == nil {
				t.Fatal("new current fact missing")
			}
			current := detail.Enrichment.EPSS
			if source == "kev" {
				current = detail.Enrichment.KEV
			}
			if current == nil || current.RunID != newer.ID {
				t.Fatal("fixture lacks a distinct newer common fact")
			}
			before := inspectionContractHash(t, db)
			out, err := db.InspectSecurityEnrichmentOperation(ctx, frames[0].OperationID)
			if err != nil {
				t.Fatal(err)
			}
			if out.State != "valid" || out.OperationID != frames[0].OperationID || out.HeadSequence != 3 || out.HeadDigest != head.Digest || out.Checkpoint == nil || out.Checkpoint.Stage != enrichmentjournal.Complete || out.Business.State != "success" || out.Business.Receipt != proof.Receipt || out.Business.Receipt == out.HeadDigest {
				t.Fatalf("journal ack substituted for exact historical business proof: %+v", out)
			}
			if out.Checkpoint.Prepared == nil || out.Checkpoint.Prepared.Completion == nil || out.Checkpoint.Prepared.Attempt.RunID != c.Attempt.RunID || out.Checkpoint.Prepared.Completion.OriginalDigest != c.OriginalDigest || !out.Checkpoint.Prepared.Completion.Feed.PublishedAt.Equal(c.Feed.PublishedAt) || !out.Checkpoint.Prepared.Completion.Feed.ObservedAt.Equal(c.Feed.ObservedAt) || !out.Checkpoint.Prepared.Completion.FinishedAt.Equal(c.FinishedAt) {
				t.Fatal("inspection changed original envelope/clocks")
			}
			wantCheckpoint := jsonValueForInspection(t, out.Checkpoint)
			out.Checkpoint.Prepared.Attempt.Targets[0].FindingID = "PRIVATE-caller-target"
			out.Checkpoint.Prepared.Completion.OriginalDigest = "sha256:" + strings.Repeat("f", 64)
			out.Checkpoint.Prepared.Completion.Feed.SelectedCVEs[0] = "CVE-2026-9999"
			if entries := out.Checkpoint.Prepared.Completion.Feed.Entries; len(entries) > 0 {
				if entries[0].EPSS != nil {
					*entries[0].EPSS = 1
				}
				if entries[0].KEVDateAdded != nil {
					date := entries[0].KEVDateAdded.Add(time.Hour)
					*entries[0].KEVDateAdded = date
				}
			}
			again, err := db.InspectSecurityEnrichmentOperation(ctx, frames[0].OperationID)
			if err != nil || again.Business.Receipt != proof.Receipt || jsonValueForInspection(t, again.Checkpoint) != wantCheckpoint || inspectionContractHash(t, db) != before {
				t.Fatal("caller mutation or inspection changed private/database evidence")
			}
			after, err := db.GetFindingDetail(ctx, c.Attempt.Targets[0].FindingID)
			if err != nil || !reflect.DeepEqual(detail, after) {
				t.Fatal("historical inspection changed current Finding/common facts")
			}
		})
	}
}

func TestOperationInspectionContractJournalOutcomeCannotInventBusinessTerminal(t *testing.T) {
	for _, kind := range []string{"begin-only-success-row", "running", "missing", "journal-success-only", "failure-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			db, c := refreshContractFixture(t, "epss", 1800)
			ctx := context.Background()
			frames := inspectionContractFrames(t, c, 1800)
			selected := frames[:3]
			want := "running"
			wantError := false
			if kind != "missing" {
				if _, err := db.BeginSecurityEnrichmentRefresh(ctx, c.Attempt); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "begin-only-success-row":
				selected = frames[:2]
				want = "unknown"
				if _, err := db.CompleteSecurityEnrichmentRefresh(ctx, c); err != nil {
					t.Fatal(err)
				}
			case "missing":
				want = "missing"
			case "journal-success-only":
				selected = frames
			case "failure-mismatch":
				fail := frames[1]
				p := *fail.Prepared
				p.Failure = &enrichmentjournal.Failure{Code: "fetch_failed", FinishedAt: c.FinishedAt}
				fail.Stage, fail.Prepared = enrichmentjournal.Fail, &p
				selected = []enrichmentjournal.Checkpoint{frames[0], frames[1], fail}
				want, wantError = "unknown", true
				if _, err := db.FailSecurityEnrichmentRefresh(ctx, c.Attempt, "parse_failed", c.FinishedAt); err != nil {
					t.Fatal(err)
				}
			}
			inspectionAppendFrames(t, db, selected)
			before := inspectionContractHash(t, db)
			out, err := db.InspectSecurityEnrichmentOperation(ctx, frames[0].OperationID)
			if out.State != "valid" || out.Checkpoint == nil || out.Business.State != want || out.Business.Receipt != "" || (err != nil) != wantError || inspectionContractHash(t, db) != before {
				t.Fatalf("candidate/running/missing/conflict became terminal: kind=%s out=%+v err=%v", kind, out, err)
			}
		})
	}
}

func TestOperationInspectionContractNoRunHasNoUUIDReceiptOrWrites(t *testing.T) {
	db := journalOwnedStore(t)
	ctx := context.Background()
	reserved := journalStoreFrames(t)[0]
	reserved.Request.After = "previous"
	reserved.Progress.NextAfter = "previous"
	first := inspectionAppendFrames(t, db, []enrichmentjournal.Checkpoint{reserved})
	before := inspectionContractHash(t, db)
	unprepared, err := db.InspectSecurityEnrichmentOperation(ctx, reserved.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	if unprepared.State != "valid" || unprepared.HeadDigest != first.Digest || unprepared.Business.State != "unprepared" || unprepared.Business.Receipt != "" || unprepared.Checkpoint == nil || unprepared.Checkpoint.Prepared != nil || unprepared.Checkpoint.Progress.RunID != "" || inspectionContractHash(t, db) != before {
		t.Fatal("reserved record invented execution ownership")
	}
	returned := reserved
	returned.Stage = enrichmentjournal.Returned
	returned.Progress.Outcome, returned.Progress.Exhausted = "exhausted", true
	appendJournalFrame(t, db, returned, 2, first.Digest)
	before = inspectionContractHash(t, db)
	out, err := db.InspectSecurityEnrichmentOperation(ctx, reserved.OperationID)
	if err != nil || out.State != "valid" || out.Business.State != "no_run" || out.Business.Receipt != "" || out.Checkpoint == nil || out.Checkpoint.Progress.RunID != "" || out.Checkpoint.Prepared != nil || out.Checkpoint.Progress.NextAfter != "previous" || out.Checkpoint.Progress.Advance {
		t.Fatalf("no-run terminal invented receipt/UUID/progress: %+v %v", out, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	unknown, err := db.InspectSecurityEnrichmentOperation(cancelled, reserved.OperationID)
	if err == nil || unknown.State != "unknown" || unknown.Checkpoint != nil || unknown.Business.Receipt != "" {
		t.Fatal("canceled inspection exposed proof")
	}
	runs, err := db.QueryIngestRuns(ctx)
	if err != nil || len(runs) != 0 || inspectionContractHash(t, db) != before {
		t.Fatal("no-run inspection created business writes")
	}
}

func jsonValueForInspection(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
