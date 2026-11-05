package store

import (
	"context"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/scoring"
)

func TestThreatSnapshotsForReadsOnlyRequestedAdvisories(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	key := "cve:CVE-2026-12345"
	value := .75
	if err := s.UpsertThreat(ctx, "kev", []model.ThreatSnapshot{{AdvisoryKey: key, KEV: true, FetchedAt: now}, {AdvisoryKey: "cve:CVE-2026-99999", KEV: true, FetchedAt: now}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertThreat(ctx, "epss", []model.ThreatSnapshot{{AdvisoryKey: key, EPSS: &value, FetchedAt: now}}); err != nil {
		t.Fatal(err)
	}
	snapshots, err := s.ListThreatSnapshotsFor(ctx, []string{key, key})
	if err != nil || len(snapshots) != 1 || !snapshots[key].KEV || snapshots[key].EPSS == nil || *snapshots[key].EPSS != value {
		t.Fatalf("selected merged threats=%+v err=%v", snapshots, err)
	}
	snapshots, err = s.ListThreatSnapshotsFor(ctx, nil)
	if err != nil || len(snapshots) != 0 {
		t.Fatalf("empty selection should not read all threats: %+v %v", snapshots, err)
	}
}

func TestThreatMergeDoesNotRefreshOldEPSSWithKEVFetch(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	key := "cve:CVE-2026-12345"
	epss := .001
	if err := s.UpsertThreat(ctx, "epss", []model.ThreatSnapshot{{AdvisoryKey: key, EPSS: &epss, FetchedAt: now.Add(-96 * time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertThreat(ctx, "kev", []model.ThreatSnapshot{{AdvisoryKey: key, KEVKnown: true, FetchedAt: now}}); err != nil {
		t.Fatal(err)
	}
	snapshots, err := s.ListThreatSnapshotsFor(ctx, []string{key})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scoring.Calculate(model.ScoreInput{At: now, Profile: model.ServiceProfile{Exposure: model.ExposureInternet}, Threat: snapshots[key], Assessment: model.CVEAssessment{Facts: map[string]string{"required_privilege": "none"}}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Likelihood.High != 100 {
		t.Fatalf("KEV fetch revived expired EPSS: %+v snapshot=%+v", result, snapshots[key])
	}
}
