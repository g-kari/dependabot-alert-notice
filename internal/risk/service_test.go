package risk

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

func TestEvaluateRecordsExpiryTransitionWithoutClockOnlyDuplicates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.db")
	db, err := store.NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := Service{Store: db}
	at := time.Date(2000, 1, 1, 12, 0, 0, 0, time.UTC)
	epss := .001
	input := model.ScoreInput{At: at, Threat: model.ThreatSnapshot{EPSS: &epss, FetchedAt: at}, Profile: model.ServiceProfile{Exposure: model.ExposureInternet}}
	for _, offset := range []time.Duration{0, time.Minute, 73 * time.Hour, 74 * time.Hour} {
		input.At = at.Add(offset)
		if _, err := service.Evaluate(context.Background(), input, "api", "owner/repo", "cve:CVE-2026-1234"); err != nil {
			t.Fatal(err)
		}
	}
	verify, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verify.Close() })
	var count int
	if err := verify.QueryRow(`SELECT COUNT(*) FROM score_history`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("want initial and expiry transitions only, got %d", count)
	}
}

func TestEvaluateDefaultClockDoesNotMutateService(t *testing.T) {
	service := Service{}
	if _, err := service.Evaluate(context.Background(), model.ScoreInput{}, "api", "owner/repo", "cve:CVE-2026-1234"); err != nil {
		t.Fatal(err)
	}
	if service.Now != nil {
		t.Fatal("Evaluate mutated shared service clock")
	}
}

func TestEvaluatePersistsAndEscalatesDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "risk.db")
	db, err := store.NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := Service{Store: db}
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	input := model.ScoreInput{At: at}
	if _, err := service.Evaluate(context.Background(), input, "api", "owner/repo", "cve:CVE-2026-1234"); err != nil {
		t.Fatal(err)
	}
	verify, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verify.Close() })
	var due string
	if err := verify.QueryRow(`SELECT due_at FROM risk_deadlines`).Scan(&due); err != nil {
		t.Fatalf("evaluation didn't persist deadline: %v", err)
	}
	input.At = at.Add(time.Minute)
	input.Profile.DataClassification = model.RiskRestricted
	input.Technical.Confidentiality = model.Interval{Low: 1, High: 1}
	if _, err := service.Evaluate(context.Background(), input, "api", "owner/repo", "cve:CVE-2026-1234"); err != nil {
		t.Fatal(err)
	}
	if err := verify.QueryRow(`SELECT due_at FROM risk_deadlines`).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if due != input.At.Add(time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("escalation target=%s", due)
	}
	input.At = at.Add(2 * time.Minute)
	input.Technical = model.TechnicalImpact{}
	if _, err := service.Evaluate(context.Background(), input, "api", "owner/repo", "cve:CVE-2026-1234"); err != nil {
		t.Fatal(err)
	}
	var retained string
	if err := verify.QueryRow(`SELECT due_at FROM risk_deadlines`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != due {
		t.Fatalf("de-escalation extended target: %s -> %s", due, retained)
	}
}
