package store

import (
	"context"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentjournal"
)

func TestJournalAcknowledgementContractExactReadonlySnapshotAndHead(t *testing.T) {
	ctx := context.Background()
	db := journalOwnedStore(t)
	frames := journalStoreFrames(t)
	first := enrichmentjournal.AppendRequest{Sequence: 1, Checkpoint: frames[0]}
	ack := appendJournalFrame(t, db, frames[0], 1, "")
	before := journalSnapshot(t, db, false)
	got, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "matched" || got.Acknowledgement.OperationID != ack.OperationID || got.Acknowledgement.Sequence != 1 || got.Acknowledgement.Digest != ack.Digest || got.HeadSequence != 1 || got.HeadDigest != ack.Digest || journalSnapshot(t, db, false) != before {
		t.Fatalf("exact readback lost ack/head or mutated data: %+v %v", got, err)
	}
	second := enrichmentjournal.AppendRequest{Sequence: 2, PreviousDigest: ack.Digest, Checkpoint: frames[1]}
	next := appendJournalFrame(t, db, frames[1], 2, ack.Digest)
	before = journalSnapshot(t, db, false)
	historical, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(ctx, first)
	if err != nil || historical.State != "matched" || historical.HeadSequence != 2 || historical.HeadDigest != next.Digest || historical.Acknowledgement.Digest != ack.Digest {
		t.Fatal("historical match concealed a newer head")
	}
	missing := enrichmentjournal.AppendRequest{Sequence: 3, PreviousDigest: next.Digest, Checkpoint: frames[2]}
	absent, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(ctx, missing)
	if err != nil || absent.State != "missing" || absent.Acknowledgement.Digest != "" {
		t.Fatal("missing acknowledgement became success")
	}
	conflict := first
	conflict.Checkpoint.Request.Limit = 1
	mismatch, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(ctx, conflict)
	if err != nil || mismatch.State != "conflict" || mismatch.Acknowledgement.Digest != "" {
		t.Fatal("different payload matched")
	}
	if _, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(ctx, second); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	canceled, err := db.ReadSecurityEnrichmentCheckpointAcknowledgement(cancelled, first)
	if err == nil || canceled.State != "unknown" || canceled.Acknowledgement.Digest != "" {
		t.Fatal("cancelled read claimed acknowledgement")
	}
	if journalSnapshot(t, db, false) != before {
		t.Fatal("acknowledgement checks wrote to an owned DB table")
	}
}
