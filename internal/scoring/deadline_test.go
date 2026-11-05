package scoring

import (
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestDeadlineEscalationShortensButNeverExtends(t *testing.T) {
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	previous := at.Add(5 * 24 * time.Hour)
	got := Deadline(&previous, model.ScoreResult{Priority: "immediate"}, at, BusinessCalendar{})
	if !got.Equal(at.Add(time.Hour)) {
		t.Fatalf("escalation deadline=%v", got)
	}
	overdue := at.Add(-time.Hour)
	got = Deadline(&overdue, model.ScoreResult{Priority: "planned"}, at, BusinessCalendar{})
	if !got.Equal(overdue) {
		t.Fatalf("overdue target extended to %v", got)
	}
}
