package scoring

import (
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// BusinessCalendar defines the timezone and holidays used for response
// deadlines. An omitted holiday is treated as a normal weekday.
type BusinessCalendar struct {
	Location *time.Location
	Holidays map[string]bool // YYYY-MM-DD in Location
}

// Deadline calculates a non-extending deadline. Existing deadlines are kept
// for recalculations at the same or lower priority.
func Deadline(previous *time.Time, result model.ScoreResult, now time.Time, calendar BusinessCalendar) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	if calendar.Location == nil {
		calendar.Location = time.FixedZone("Asia/Tokyo", 9*60*60)
	}
	now = now.In(calendar.Location)
	var d time.Duration
	var candidate time.Time
	switch result.Priority {
	case "incident", "immediate":
		d = time.Hour
	case "today":
		d = 8 * time.Hour
	case "next_business_day":
		candidate = nextBusinessDay(now, calendar)
	default:
		d = 5 * 24 * time.Hour
	}
	if candidate.IsZero() {
		candidate = now.Add(d)
	}
	if previous != nil && !previous.IsZero() && previous.Before(candidate) {
		return previous.In(calendar.Location)
	}
	return candidate
}

// NextBusinessDay advances to the next weekday not present in Holidays.
func NextBusinessDay(t time.Time, calendar BusinessCalendar) time.Time {
	return nextBusinessDay(t, calendar)
}

func nextBusinessDay(t time.Time, calendar BusinessCalendar) time.Time {
	if calendar.Location == nil {
		calendar.Location = t.Location()
	}
	if calendar.Location == nil {
		calendar.Location = time.UTC
	}
	t = t.In(calendar.Location)
	for {
		t = t.AddDate(0, 0, 1)
		if t.Weekday() == time.Saturday || t.Weekday() == time.Sunday {
			continue
		}
		if calendar.Holidays != nil && calendar.Holidays[t.Format("2006-01-02")] {
			continue
		}
		return t
	}
}
