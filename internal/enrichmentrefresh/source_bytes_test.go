package enrichmentrefresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/g-kari/dependabot-alert-notice/internal/threat"
)

func TestRefreshOnceEquivalentSyntheticInputsBindExactBytesToReceipt(t *testing.T) {
	// These are local parser-subset documents, not real feed responses.
	kev := []byte(`{"catalogVersion":"synthetic-bytes.1","dateReleased":"2026-11-10T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-11-09"}]}`)
	var indented bytes.Buffer
	if err := json.Indent(&indented, kev, "", "  "); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source string
		raw    [2][]byte
	}{
		{"epss", [2][]byte{[]byte(contractEPSS), []byte(strings.ReplaceAll(contractEPSS, "\n", "\r\n"))}},
		{"kev", [2][]byte{kev, indented.Bytes()}},
	} {
		t.Run(tc.source, func(t *testing.T) {
			digests := [2]string{
				fmt.Sprintf("sha256:%x", sha256.Sum256(tc.raw[0])),
				fmt.Sprintf("sha256:%x", sha256.Sum256(tc.raw[1])),
			}
			if bytes.Equal(tc.raw[0], tc.raw[1]) || digests[0] == digests[1] {
				t.Fatal("fixture variants must have different exact bytes and SHA256")
			}
			var first store.SecurityEnrichmentRefreshCompletion
			for i, raw := range tc.raw {
				db := contractStore(t, true)
				h := harness(t, db)
				h.data = raw
				h.service.Fetcher = fetchFunc(func(ctx context.Context, source string) ([]byte, error) {
					h.fetchCalls++
					if ctx.Err() != nil || source != tc.source {
						t.Fatalf("unexpected fetch context/source: %v %q", ctx.Err(), source)
					}
					return raw, nil
				})
				// Commit to owned SQLite, then obscure only the returned outcome so
				// the exact prepared completion must survive in Pending.
				h.repo.completeAfter, h.repo.reconcileError = true, true
				out, err := h.service.RefreshOnce(context.Background(), Request{Connector: tc.source + "_feed", Limit: 200})
				assertPending(t, h, out, err)
				if out.Pending.Completion == nil || h.repo.calls["complete"] != 1 || h.repo.calls["reconcile"] != 1 || h.repo.calls["fail"] != 0 || h.fetchCalls != 1 {
					t.Fatalf("completion not retained once: out=%+v calls=%v", out, h.repo.calls)
				}
				completion := *out.Pending.Completion
				if completion.OriginalDigest != digests[i] || jsonValue(t, completion) != h.repo.completeJSON || h.repo.reconcileJSON != h.repo.completeJSON {
					t.Fatalf("variant=%d exact original digest/prepared completion changed: %+v", i, completion)
				}
				parsed, err := threat.ParseOfflineThreat(bytes.NewReader(raw), tc.source, threat.OfflineOptions{CVEs: []string{"CVE-2026-1234"}, ObservedAt: h.times[1]})
				if err != nil || !reflect.DeepEqual(parsed, completion.Feed) || len(parsed.Entries) != 1 {
					t.Fatalf("variant=%d retained feed differs from direct parse: %+v err=%v", i, parsed, err)
				}
				if tc.source == "epss" {
					if parsed.Entries[0].EPSS == nil || *parsed.Entries[0].EPSS != 0 || parsed.Entries[0].Percentile == nil || *parsed.Entries[0].Percentile != 0 {
						t.Fatal("known zero EPSS/percentile absent")
					}
				} else if !parsed.Entries[0].KEV || parsed.Entries[0].KEVDateAdded == nil {
					t.Fatal("known positive KEV absent")
				}
				if i == 0 {
					first = completion
				} else if !reflect.DeepEqual(first.Feed, completion.Feed) {
					t.Fatal("raw byte variants must have identical parsed feed")
				}

				// Real store readback checks both the success receipt and stored
				// manifest digest. Only replacing that digest must be rejected.
				ctx := context.Background()
				state, err := db.ReconcileSecurityEnrichmentRefresh(ctx, completion)
				if err != nil || state.State != "success" || state.Receipt == "" {
					t.Fatalf("variant=%d original completion not verified: %+v err=%v", i, state, err)
				}
				runs, err := db.QueryIngestRuns(ctx)
				if err != nil {
					t.Fatal(err)
				}
				matches := 0
				for _, run := range runs {
					if run.ID == completion.Attempt.RunID {
						matches++
						if run.Connector != tc.source+"_feed" || run.Cursor != state.Receipt {
							t.Fatalf("variant=%d digest-bound receipt differs: %+v", i, run)
						}
					}
				}
				if matches != 1 {
					t.Fatalf("variant=%d expected one matching receipt, got %d", i, matches)
				}
				before := jsonValue(t, runs)
				changed := completion
				changed.OriginalDigest = digests[1-i]
				conflict, err := db.ReconcileSecurityEnrichmentRefresh(ctx, changed)
				if !errors.Is(err, store.ErrIngestConflict) || conflict.State != "unknown" || conflict.Receipt != "" {
					t.Fatalf("variant=%d other bytes' digest verified same receipt: %+v err=%v", i, conflict, err)
				}
				again, err := db.ReconcileSecurityEnrichmentRefresh(ctx, completion)
				if err != nil || again.State != state.State || again.Receipt != state.Receipt {
					t.Fatalf("variant=%d digest collision check changed good receipt: %+v err=%v", i, again, err)
				}
				after, err := db.QueryIngestRuns(ctx)
				if err != nil || jsonValue(t, after) != before {
					t.Fatalf("variant=%d readback changed receipts: %+v err=%v", i, after, err)
				}
			}
		})
	}
}
