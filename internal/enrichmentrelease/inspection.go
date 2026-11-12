package enrichmentrelease

import (
	"slices"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

// preflightCheckpoint caps every collection/string before the existing journal
// encoder can allocate its canonical JSON. Journal validation remains the
// authority for its existing enums, clocks, CVEs, probabilities and progress.
func preflightCheckpoint(c enrichmentjournal.Checkpoint) bool {
	if len(c.OperationID) > 36 || len(c.Request.Connector) > 9 || len(c.Request.After) > 128 || len(c.Stage) > 8 ||
		len(c.Progress.Outcome) > 16 || len(c.Progress.Code) > 64 || len(c.Progress.RunID) > 36 ||
		len(c.Progress.ScanAfter) > 128 || len(c.Progress.NextAfter) > 128 {
		return false
	}
	if c.Prepared == nil {
		return true
	}
	p := c.Prepared
	if len(p.Attempt.RunID) > 36 || len(p.Attempt.Connector) > 9 || len(p.Attempt.Scope) > 128 || len(p.Attempt.Targets) > 200 {
		return false
	}
	for _, t := range p.Attempt.Targets {
		if len(t.FindingID) > 128 || len(t.CVEID) > 28 || len(t.Revision) > 64 {
			return false
		}
	}
	if p.Failure != nil && len(p.Failure.Code) > 64 {
		return false
	}
	if p.Completion != nil {
		f := p.Completion.Feed
		if len(p.Completion.OriginalDigest) > 71 || len(f.Source) > 4 || len(f.Version) > 64 || len(f.SelectedCVEs) > 200 || len(f.Entries) > 200 {
			return false
		}
		for _, cve := range f.SelectedCVEs {
			if len(cve) > 28 {
				return false
			}
		}
		for _, e := range f.Entries {
			if len(e.CVEID) > 28 {
				return false
			}
		}
	}
	return true
}

func inspectTerminal(request ReleaseRequest) (Inspection, error) {
	empty := Inspection{}
	r, t := request.Reservation, request.Terminal
	if !validUUID(r.IntentID) || r.ExpectedGeneration < 0 || r.ExpectedGeneration >= maxGeneration ||
		r.Reserved.Sequence != 1 || r.Reserved.PreviousDigest != "" || !validDigest(r.ReservedDigest) ||
		t.Sequence < 2 || t.Sequence > 5 || !validDigest(t.PreviousDigest) || !validDigest(request.TerminalDigest) ||
		!preflightCheckpoint(r.Reserved.Checkpoint) || !preflightCheckpoint(t.Checkpoint) {
		return empty, invalid("binding")
	}
	root, terminal := r.Reserved.Checkpoint, t.Checkpoint
	if root.Stage != enrichmentjournal.Reserved || terminal.Stage != enrichmentjournal.Returned || terminal.Progress.Pending {
		return empty, invalid("terminal")
	}
	rootBytes, err := enrichmentjournal.Encode(root)
	if err != nil || payloadDigest(rootBytes) != r.ReservedDigest {
		return empty, invalid("reserved checkpoint")
	}
	terminalBytes, err := enrichmentjournal.Encode(terminal)
	if err != nil || payloadDigest(terminalBytes) != request.TerminalDigest {
		return empty, invalid("terminal checkpoint")
	}
	if root.OperationID != terminal.OperationID || root.Version != terminal.Version || root.Request != terminal.Request {
		return empty, invalid("changed binding")
	}
	kind, runID := terminal.Progress.Outcome, terminal.Progress.RunID
	if terminal.Prepared == nil {
		if t.Sequence != 2 || t.PreviousDigest != r.ReservedDigest || runID != "" ||
			enrichmentjournal.ValidateTransition(&root, terminal) != nil {
			return empty, invalid("no-run branch")
		}
		// Existing journal validation allows no_targets/exhausted/invalid/
		// error/canceled here. It does not require a fabricated attempt.
		kind = "no_run"
	} else {
		if t.Sequence != 4 && t.Sequence != 5 || (kind != "success" && kind != "failed") {
			return empty, invalid("prepared branch")
		}
	}
	// Do not infer missing intermediate history or any SQL/business proof.
	// Preserve the caller's exact time values/offsets, nil/empty slices and
	// pointer values rather than replacing them with encoded UTC copies.
	owned := request
	owned.Reservation.Reserved.Checkpoint = cloneCheckpoint(root)
	owned.Terminal.Checkpoint = cloneCheckpoint(terminal)
	return Inspection{Request: owned, Kind: kind, RunID: runID}, nil
}

func cloneCheckpoint(c enrichmentjournal.Checkpoint) enrichmentjournal.Checkpoint {
	if c.Prepared == nil {
		return c
	}
	p := *c.Prepared
	p.Attempt.Targets = slices.Clone(p.Attempt.Targets)
	if p.Failure != nil {
		f := *p.Failure
		p.Failure = &f
	}
	if p.Completion != nil {
		completion := *p.Completion
		completion.Feed.SelectedCVEs = slices.Clone(completion.Feed.SelectedCVEs)
		completion.Feed.Entries = slices.Clone(completion.Feed.Entries)
		for i := range completion.Feed.Entries {
			e := &completion.Feed.Entries[i]
			if e.EPSS != nil {
				n := *e.EPSS
				e.EPSS = &n
			}
			if e.Percentile != nil {
				n := *e.Percentile
				e.Percentile = &n
			}
			if e.KEVDateAdded != nil {
				date := *e.KEVDateAdded
				e.KEVDateAdded = &date
			}
		}
		p.Completion = &completion
	}
	c.Prepared = &p
	return c
}
