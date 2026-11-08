package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestFindingPreviewReadIsBoundAndDoesNotLoadHistory(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	ctx := context.Background()
	at := time.Date(2099, 1, 4, 0, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-a", "example/synthetic")
	insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "high", "active", at, nil)
	before, err := s.GetFindingDetail(ctx, "finding-a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetFindingPreviewSnapshot(ctx, "finding-a", at)
	if err != nil {
		t.Fatal(err)
	}
	if got.Finding.Source != "" || got.Finding.SourceFindingID != "" {
		t.Fatal("missing provenance invented")
	}
	after, err := s.GetFindingDetail(ctx, "finding-a")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read mutated stored state")
	}
	insertSecurityQueryObservation(t, s, "finding-a", "trivy", 1, at)
	got, err = s.GetFindingPreviewSnapshot(ctx, "finding-a", at)
	if err != nil || got.Finding.Source != "trivy" {
		t.Fatalf("provenance: %+v %v", got, err)
	}
	if _, err = s.GetFindingPreviewSnapshot(ctx, "missing", at); !errors.Is(err, ErrFindingNotFound) {
		t.Fatal("missing ID not distinguished")
	}
	if _, err = s.GetFindingPreviewSnapshot(ctx, "finding-a", time.Time{}); err == nil {
		t.Fatal("implicit clock allowed")
	}
	// Corrupt only a disposable synthetic row; mismatched JSON/SQL IDs must fail.
	body, err := json.Marshal(model.Finding{ID: "other", AssetID: "asset-a", Category: "vulnerability"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE findings SET body_json=? WHERE id='finding-a'`, string(body)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetFindingPreviewSnapshot(ctx, "finding-a", at); err == nil {
		t.Fatal("mismatched row binding accepted")
	}
}

func TestPreviewStoredJSONRejectsUnicodeReplacement(t *testing.T) {
	for _, raw := range []string{"{\"id\":\"\xff\"}", `{"id":"\ud800"}`, `{"id":"\udc00"}`} {
		var a model.Asset
		if err := decodePreviewStoredJSON(raw, &a); err == nil {
			t.Fatalf("replaced invalid encoding %q", raw)
		}
	}
	for _, raw := range []string{`{"id":"\ud83d\ude00"}`, `{"id":"�"}`, `{"id":"\\ud800"}`} {
		var a model.Asset
		if err := decodePreviewStoredJSON(raw, &a); err != nil {
			t.Fatalf("rejected valid encoding %q: %v", raw, err)
		}
	}
	s := newSecurityQueryTestStore(t)
	at := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-a", "example/synthetic")
	insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "high", "active", at, nil)
	for _, raw := range []string{`{"id":"finding-a","asset_id":"asset-a","category":"vulnerability","severity":"\ud800"}`, "{\"id\":\"finding-a\",\"asset_id\":\"asset-a\",\"category\":\"vulnerability\",\"severity\":\"\xff\"}"} {
		if _, err := s.db.Exec(`UPDATE findings SET body_json=? WHERE id='finding-a'`, raw); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetFindingPreviewSnapshot(context.Background(), "finding-a", at); err == nil {
			t.Fatal("DB encoding silently repaired")
		}
	}
}

func TestPreviewRejectsSelectedEnrichmentBindingAndEncodingWithoutFallback(t *testing.T) {
	for _, kind := range []string{"run", "source", "published", "observed", "unicode", "duplicate", "case-alias"} {
		t.Run(kind, func(t *testing.T) {
			s := newSecurityQueryTestStore(t)
			at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
			insertSecurityQueryAsset(t, s, "asset-a", "example/synthetic")
			insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "high", "active", at, map[string]any{"vulnerability_id": "CVE-2026-1234"})
			oldRun, oldFeed := enrichmentFixture(t, 801, "epss", at.Add(-48*time.Hour), at.Add(-48*time.Hour))
			mustEnrichment(t, s, oldRun, oldFeed)
			run, feed := enrichmentFixture(t, 802, "epss", at.Add(-24*time.Hour), at.Add(-24*time.Hour))
			mustEnrichment(t, s, run, feed)
			if _, err := s.GetFindingPreviewSnapshot(context.Background(), "finding-a", at); err != nil {
				t.Fatal(err)
			}
			var body string
			if err := s.db.QueryRow(`SELECT body_json FROM security_enrichment_observations WHERE ingest_run_id=?`, run.ID).Scan(&body); err != nil {
				t.Fatal(err)
			}
			var e model.SecurityEnrichmentEvidence
			if err := json.Unmarshal([]byte(body), &e); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "run":
				e.RunID = oldRun.ID
			case "source":
				e.Source = "kev"
			case "published":
				e.PublishedAt = e.PublishedAt.Add(-time.Hour)
			case "observed":
				e.ObservedAt = e.ObservedAt.Add(-time.Hour)
			}
			encoded, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			body = string(encoded)
			original := body
			if kind == "unicode" {
				body = strings.Replace(body, `"version":"2026-11-07"`, `"version":"\ud800"`, 1)
			}
			if kind == "duplicate" {
				body = strings.Replace(body, `"version":"2026-11-07"`, `"version":"wrong","version":"2026-11-07"`, 1)
			}
			if kind == "case-alias" {
				body = strings.Replace(body, `"version":"2026-11-07"`, `"Version":"wrong","version":"2026-11-07"`, 1)
			}
			if (kind == "unicode" || kind == "duplicate" || kind == "case-alias") && body == original {
				t.Fatal("corruption fixture was not changed")
			}
			// Immutable evidence triggers stay intact. Insert corruption into the initial
			// fixture instead of modifying a retained row or disabling a trigger.
			var rowID, identity, published, observed string
			if err = s.db.QueryRow(`SELECT id,evidence_identity,published_at,observed_at FROM security_enrichment_observations WHERE ingest_run_id=?`, run.ID).Scan(&rowID, &identity, &published, &observed); err != nil {
				t.Fatal(err)
			}
			// A separate disposable DB receives copied source rows and corrupt body.
			other := newSecurityQueryTestStore(t)
			insertSecurityQueryAsset(t, other, "asset-a", "example/synthetic")
			insertSecurityQueryFinding(t, other, "finding-a", "asset-a", "high", "active", at, map[string]any{"vulnerability_id": "CVE-2026-1234"})
			mustEnrichment(t, other, oldRun, oldFeed)
			// Supply the referenced run through the ordinary importer with an empty feed.
			empty := feed
			empty.Entries = nil
			mustEnrichment(t, other, run, empty)
			if _, err = other.db.Exec(`INSERT INTO security_enrichment_observations(id,ingest_run_id,source,cve_id,published_at,observed_at,evidence_identity,body_json) VALUES(?,?,?,?,?,?,?,?)`, rowID, run.ID, "epss", "CVE-2026-1234", published, observed, identity, body); err != nil {
				t.Fatal(err)
			}
			if _, err = other.GetFindingPreviewSnapshot(context.Background(), "finding-a", at); err == nil {
				t.Fatal("corrupt latest evidence accepted or fell back")
			}
		})
	}
}

func previewDatabaseState(t *testing.T, s *Store) map[string][]string {
	t.Helper()
	rows, err := s.db.Query(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, name := range names {
		out[name] = []string{}
		rows, err := s.db.Query(`SELECT * FROM "` + strings.ReplaceAll(name, `"`, `""`) + `"`)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			pointers := make([]any, len(columns))
			for i := range values {
				pointers[i] = &values[i]
			}
			if err = rows.Scan(pointers...); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			out[name] = append(out[name], string(data))
		}
		if err = rows.Err(); err != nil {
			t.Fatal(err)
		}
		if err = rows.Close(); err != nil {
			t.Fatal(err)
		}
		sort.Strings(out[name])
	}
	return out
}

func TestPreviewSnapshotLeavesEveryStoredTableUnchanged(t *testing.T) {
	s := newSecurityQueryTestStore(t)
	at := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	insertSecurityQueryAsset(t, s, "asset-a", "example/synthetic")
	insertSecurityQueryFinding(t, s, "finding-a", "asset-a", "high", "active", at, map[string]any{"vulnerability_id": "CVE-2026-1234"})
	insertSecurityQueryObservation(t, s, "finding-a", "trivy", 1, at)
	insertSecurityQueryEvent(t, s, "finding-a", 1, at)
	run, feed := enrichmentFixture(t, 901, "epss", at.Add(-72*time.Hour), at.Add(-72*time.Hour))
	mustEnrichment(t, s, run, feed)
	before := previewDatabaseState(t, s)
	for _, clock := range []time.Time{at, at.Add(time.Nanosecond), at.Add(-96 * time.Hour)} {
		snapshot, err := s.GetFindingPreviewSnapshot(context.Background(), "finding-a", clock)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Enrichment == nil || snapshot.Enrichment.EPSS.Fresh != clock.Equal(at) {
			t.Fatal("explicit freshness or latest evidence changed")
		}
	}
	if after := previewDatabaseState(t, s); !reflect.DeepEqual(before, after) {
		t.Fatal("read changed database rows")
	}
}
