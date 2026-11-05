package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func phase0Record() *model.AlertRecord {
	return &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "api", Number: 7, CVEID: "CVE-2026-1234", PackageName: "example", Severity: model.SeverityHigh, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, State: model.AlertStateApproved, EvalStatus: model.EvalStatusDone, Evaluation: &model.Evaluation{Recommendation: "approve"}, NotifiedAt: time.Now().UTC(), SlackMessageTS: "slack-7", DiscordMessageID: "discord-7"}
}

func TestSecurityProjectionPreservesWorkflowAndHistory(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	rec := phase0Record()
	if !s.SaveObserved(rec) {
		t.Fatal("new alert was not saved")
	}
	findings, err := s.QueryFindings(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%v err=%v", findings, err)
	}
	id := findings[0].ID
	if findings[0].TriageStatus != "new" || findings[0].SourceStatus != "active" {
		t.Fatalf("workflow leaked into finding: %+v", findings[0])
	}
	obs, _ := s.QueryObservations(ctx, id)
	events, _ := s.QueryEvents(ctx, id)
	if len(obs) != 1 || len(events) != 1 {
		t.Fatalf("initial observations=%d events=%d", len(obs), len(events))
	}
	s.Save(rec)
	obs, _ = s.QueryObservations(ctx, id)
	if len(obs) != 1 {
		t.Fatal("evaluation-only save duplicated observation")
	}
	at := time.Now().UTC()
	if _, err := s.ResolveMissingAlerts(ctx, "org", "api", nil, at); err != nil {
		t.Fatal(err)
	}
	findings, _ = s.QueryFindings(ctx)
	if findings[0].SourceStatus != "resolved" {
		t.Fatal("missing complete snapshot did not resolve finding")
	}
	if !s.SaveObserved(rec) {
		t.Fatal("reopened record was not saved")
	}
	findings, _ = s.QueryFindings(ctx)
	if findings[0].ID != id || findings[0].SourceStatus != "active" {
		t.Fatal("reopen changed identity or failed")
	}
	got, err := s.Get(rec.Alert.ID)
	if err != nil || got.State != model.AlertStateApproved || got.SlackMessageTS != "slack-7" || got.DiscordMessageID != "discord-7" || got.Evaluation == nil {
		t.Fatalf("legacy workflow lost: %+v %v", got, err)
	}
	obs, _ = s.QueryObservations(ctx, id)
	events, _ = s.QueryEvents(ctx, id)
	if len(obs) != 3 || len(events) != 3 {
		t.Fatalf("history observations=%d events=%d", len(obs), len(events))
	}
	if _, err := s.db.Exec(`UPDATE events SET actor='changed'`); err == nil {
		t.Fatal("audit events allowed updates")
	}
	if _, err := s.db.Exec(`DELETE FROM events`); err == nil {
		t.Fatal("audit events allowed deletes")
	}
}

func TestSecurityProjectionFailureRollsBackLegacyWrites(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	rec := phase0Record()
	if _, err := s.db.Exec(`CREATE TRIGGER reject_observation BEFORE INSERT ON observations BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if s.SaveObserved(rec) || s.HasByKey("org", "api", 7) {
		t.Fatal("failed projection committed legacy record")
	}
	if _, err := s.db.Exec(`DROP TRIGGER reject_observation`); err != nil {
		t.Fatal(err)
	}
	if !s.SaveObserved(rec) {
		t.Fatal("safe retry failed")
	}
	ctx := context.Background()
	before, _ := s.QueryFindings(ctx)
	if _, err := s.db.Exec(`CREATE TRIGGER reject_observation BEFORE INSERT ON observations BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	changed := rec.Alert
	changed.Summary = "changed"
	if err := s.UpdateAlertJSON("org", "api", 7, changed); err == nil {
		t.Fatal("expected projection failure")
	}
	got, _ := s.Get(rec.Alert.ID)
	if got.Alert.Summary != "" {
		t.Fatal("failed metadata update committed")
	}
	if _, err := s.ResolveMissingAlerts(ctx, "org", "api", nil, time.Now().UTC()); err == nil {
		t.Fatal("expected resolution failure")
	}
	got, _ = s.Get(rec.Alert.ID)
	if got.ResolvedAt != nil {
		t.Fatal("failed resolution committed")
	}
	after, _ := s.QueryFindings(ctx)
	if after[0].ID != before[0].ID || after[0].SourceStatus != "active" {
		t.Fatal("failed resolution changed finding")
	}
}

func TestSecurityMigrationBackfillsWithoutChangingLegacyRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := phase0Record()
	s.SaveObserved(rec)
	var before string
	if err := s.db.QueryRow(`SELECT alert_json||eval_json||state||slack_message_ts||discord_message_id FROM alert_records WHERE id=?`, rec.Alert.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP TABLE observations`, `DROP TABLE events`, `DROP TABLE findings`, `DROP TABLE assets`, `DROP TABLE ingest_runs`, `DELETE FROM app_migrations WHERE version=2`} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	for i := 0; i < 2; i++ {
		s, err = NewWithPath(path)
		if err != nil {
			t.Fatal(err)
		}
		var after string
		if err := s.db.QueryRow(`SELECT alert_json||eval_json||state||slack_message_ts||discord_message_id FROM alert_records WHERE id=?`, rec.Alert.ID).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if before != after {
			t.Fatal("migration changed legacy bytes")
		}
		findings, _ := s.QueryFindings(context.Background())
		obs, _ := s.QueryObservations(context.Background(), findings[0].ID)
		if len(findings) != 1 || len(obs) != 1 {
			t.Fatal("migration not idempotent")
		}
		_ = s.Close()
	}
}

func TestSecurityMigrationFailureIsRecoverable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid-identity.db")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := phase0Record()
	s.SaveObserved(rec)
	// Simulate an interrupted upgrade and a valid JSON row with invalid source identity.
	for _, q := range []string{`DROP TABLE observations`, `DROP TABLE events`, `DROP TABLE findings`, `DROP TABLE assets`, `DROP TABLE ingest_runs`, `DELETE FROM app_migrations WHERE version=2`, `UPDATE alert_records SET number=0`} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = NewWithPath(path); err == nil {
		t.Fatal("invalid native identity should fail safely")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM alert_records`).Scan(&n); err != nil || n != 1 {
		t.Fatal("failed migration lost legacy data")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='assets'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("failed migration left a partial schema")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM app_migrations WHERE version=2`).Scan(&n); err != nil || n != 0 {
		t.Fatal("failed migration was marked applied")
	}
	if _, err := db.Exec(`UPDATE alert_records SET number=7`); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = recovered.Close() }()
	got, err := recovered.Get(rec.Alert.ID)
	if err != nil || got.State != model.AlertStateApproved || got.Evaluation == nil || got.SlackMessageTS != "slack-7" {
		t.Fatalf("recovery lost legacy workflow: %+v %v", got, err)
	}
	findings, err := recovered.QueryFindings(context.Background())
	if err != nil || len(findings) != 1 {
		t.Fatalf("recovery projection=%v err=%v", findings, err)
	}
}

func TestOlderSourceObservationCannotRegressFinding(t *testing.T) {
	ctx := context.Background()
	s := New()
	defer func() { _ = s.Close() }()
	at := time.Now().UTC()
	newer, err := s.StartIngestRun(ctx, "dependabot", "org/api", at)
	if err != nil {
		t.Fatal(err)
	}
	alert := phase0Record().Alert
	alert.Summary = "newer"
	if err := s.ObserveDependabot(ctx, alert, newer.ID, at); err != nil {
		t.Fatal(err)
	}
	older, err := s.StartIngestRun(ctx, "dependabot", "org/api", at.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	alert.State = "fixed"
	alert.Summary = "older"
	if err := s.ObserveDependabot(ctx, alert, older.ID, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	findings, _ := s.QueryFindings(ctx)
	if findings[0].SourceStatus != "active" || !findings[0].LastSeen.Equal(at) {
		t.Fatal("out of order evidence regressed current finding")
	}
	observations, _ := s.QueryObservations(ctx, findings[0].ID)
	events, _ := s.QueryEvents(ctx, findings[0].ID)
	if len(observations) != 2 || len(events) != 1 {
		t.Fatal("older evidence was erased or emitted a false transition")
	}
}

func TestIngestRunRejectsForeignScopeAndErrorText(t *testing.T) {
	ctx := context.Background()
	s := New()
	defer func() { _ = s.Close() }()
	at := time.Now().UTC()
	run, err := s.StartIngestRun(ctx, "dependabot", "org/other", at)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ObserveDependabot(ctx, phase0Record().Alert, run.ID, at); err == nil {
		t.Fatal("foreign scope accepted")
	}
	if err := s.FinishIngestRun(ctx, run.ID, "failed", "unknown", "Authorization: secret", at); err == nil {
		t.Fatal("raw error body accepted")
	}
	findings, err := s.QueryFindings(ctx)
	if err != nil || len(findings) != 0 {
		t.Fatal("rejected observation persisted")
	}
}

func TestIngestRunAndObservationReplay(t *testing.T) {
	ctx := context.Background()
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	at := time.Now().UTC()
	run, err := s.StartIngestRun(ctx, "dependabot", "org/api", at)
	if err != nil {
		t.Fatal(err)
	}
	alert := phase0Record().Alert
	for i := 0; i < 2; i++ {
		if err := s.ObserveDependabot(ctx, alert, run.ID, at); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.FinishIngestRun(ctx, run.ID, "partial", "partial", "rate_limited", at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	findings, _ := s.QueryFindings(ctx)
	obs, _ := s.QueryObservations(ctx, findings[0].ID)
	if len(obs) != 1 || findings[0].SourceStatus != "active" {
		t.Fatal("replay duplicated or partial scan closed finding")
	}
	runs, err := s.QueryIngestRuns(ctx)
	if err != nil || len(runs) != 1 || runs[0].Result != "partial" || runs[0].Error != "rate_limited" {
		t.Fatalf("runs=%+v err=%v", runs, err)
	}
}
