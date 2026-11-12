package enrichmentrefresh

import (
	"math"
	"reflect"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func boundedSourceAttempt(a store.SecurityEnrichmentRefreshAttempt) bool {
	if len(a.RunID) > 36 || len(a.Connector) > 9 || len(a.Scope) > 76 || len(a.Targets) > 200 {
		return false
	}
	for _, t := range a.Targets {
		if len(t.FindingID) > 128 || len(t.CVEID) > 28 || len(t.Revision) > 64 {
			return false
		}
	}
	return true
}

func boundedSourcePending(p *Pending) bool {
	if p == nil {
		return true
	}
	if !boundedSourceAttempt(p.Attempt) {
		return false
	}
	if p.ExpectedFailure != nil && len(p.ExpectedFailure.Code) > 64 {
		return false
	}
	if p.Completion != nil {
		c := p.Completion
		if !boundedSourceAttempt(c.Attempt) || len(c.OriginalDigest) > 71 || len(c.Feed.Source) > 4 || len(c.Feed.Version) > 64 || len(c.Feed.SelectedCVEs) > 200 || len(c.Feed.Entries) > 200 {
			return false
		}
		for _, cve := range c.Feed.SelectedCVEs {
			if len(cve) > 28 {
				return false
			}
		}
		for _, entry := range c.Feed.Entries {
			if len(entry.CVEID) > 28 {
				return false
			}
		}
	}
	return true
}

func sameSourcePending(a, b *Pending) bool {
	if !reflect.DeepEqual(a, b) {
		return false
	}
	if a == nil || a.Completion == nil {
		return true
	}
	// DeepEqual treats +0 and -0 as equal. Preserve their exact representation
	// before aggregation; neither pointer presence nor a value may be discarded.
	for i, entry := range a.Completion.Feed.Entries {
		other := b.Completion.Feed.Entries[i]
		if entry.EPSS != nil && math.Float64bits(*entry.EPSS) != math.Float64bits(*other.EPSS) {
			return false
		}
		if entry.Percentile != nil && math.Float64bits(*entry.Percentile) != math.Float64bits(*other.Percentile) {
			return false
		}
	}
	return true
}

// convertJournalCheckpoint checks duplicated source values before aggregation.
// It must not hide unequal Completion.Attempt or Result.Pending values through
// canonicalization, nil/empty changes or dropping a duplicate representation.
func convertJournalCheckpoint(checkpoint PreservationCheckpoint) (enrichmentjournal.Checkpoint, error) {
	empty := enrichmentjournal.Checkpoint{}
	r := checkpoint.Result
	if len(checkpoint.OperationID) > 36 || len(checkpoint.Request.Connector) > 9 || len(checkpoint.Request.After) > 128 || len(r.Outcome) > 16 || len(r.Code) > 64 || len(r.RunID) > 36 || len(r.ScanAfter) > 128 || len(r.NextAfter) > 128 || !boundedSourcePending(checkpoint.Prepared) || !boundedSourcePending(r.Pending) {
		return empty, ErrManualInvalid
	}
	if checkpoint.Prepared != nil && checkpoint.Prepared.Completion != nil && !reflect.DeepEqual(checkpoint.Prepared.Attempt, checkpoint.Prepared.Completion.Attempt) {
		return empty, ErrManualInvalid
	}
	if r.Pending != nil && !sameSourcePending(r.Pending, checkpoint.Prepared) {
		return empty, ErrManualInvalid
	}
	out := enrichmentjournal.Checkpoint{
		Version: checkpoint.Version, OperationID: checkpoint.OperationID,
		Request:  enrichmentjournal.Request{Connector: checkpoint.Request.Connector, After: checkpoint.Request.After, Limit: checkpoint.Request.Limit},
		Stage:    enrichmentjournal.Stage(checkpoint.Stage),
		Progress: enrichmentjournal.Progress{Outcome: r.Outcome, Code: r.Code, RunID: r.RunID, Scanned: r.Scanned, Targets: r.Targets, ScanAfter: r.ScanAfter, NextAfter: r.NextAfter, Advance: r.Advance, Exhausted: r.Exhausted, Pending: r.Pending != nil},
	}
	if checkpoint.Prepared != nil {
		p := checkpoint.Prepared
		prepared := &enrichmentjournal.Prepared{Attempt: enrichmentjournal.Attempt{RunID: p.Attempt.RunID, Connector: p.Attempt.Connector, Scope: p.Attempt.Scope, StartedAt: p.Attempt.StartedAt}}
		if p.Attempt.Targets != nil {
			prepared.Attempt.Targets = make([]enrichmentjournal.Target, len(p.Attempt.Targets))
			for i, target := range p.Attempt.Targets {
				prepared.Attempt.Targets[i] = enrichmentjournal.Target{FindingID: target.FindingID, CVEID: target.CVEID, Revision: target.Revision}
			}
		}
		if p.ExpectedFailure != nil {
			prepared.Failure = &enrichmentjournal.Failure{Code: p.ExpectedFailure.Code, FinishedAt: p.ExpectedFailure.FinishedAt}
		}
		if p.Completion != nil {
			c := p.Completion
			feed := enrichmentjournal.Feed{Source: c.Feed.Source, Version: c.Feed.Version, PublishedAt: c.Feed.PublishedAt, ObservedAt: c.Feed.ObservedAt}
			if c.Feed.SelectedCVEs != nil {
				feed.SelectedCVEs = append([]string{}, c.Feed.SelectedCVEs...)
			}
			if c.Feed.Entries != nil {
				feed.Entries = make([]enrichmentjournal.Entry, len(c.Feed.Entries))
				for i, entry := range c.Feed.Entries {
					feed.Entries[i] = journalEntry(entry)
				}
			}
			prepared.Completion = &enrichmentjournal.Completion{Feed: feed, OriginalDigest: c.OriginalDigest, FinishedAt: c.FinishedAt}
		}
		out.Prepared = prepared
	}
	data, err := enrichmentjournal.Encode(out)
	if err != nil {
		return empty, ErrManualInvalid
	}
	// Decode the validated canonical payload to detach every pointer/slice.
	owned, err := enrichmentjournal.Decode(data)
	if err != nil {
		return empty, ErrManualInvalid
	}
	return owned, nil
}

func journalEntry(entry model.SecurityEnrichmentEntry) enrichmentjournal.Entry {
	out := enrichmentjournal.Entry{CVEID: entry.CVEID, KEV: entry.KEV}
	if entry.EPSS != nil {
		n := *entry.EPSS
		out.EPSS = &n
	}
	if entry.Percentile != nil {
		n := *entry.Percentile
		out.Percentile = &n
	}
	if entry.KEVDateAdded != nil {
		at := *entry.KEVDateAdded
		out.KEVDateAdded = &at
	}
	return out
}
