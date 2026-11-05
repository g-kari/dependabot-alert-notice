package threat

import (
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"io"
	"time"
)

// ParseEPSSCSV is a compatibility alias for ParseEPSS.
func ParseEPSSCSV(r io.Reader, fetchedAt time.Time) (map[string]model.ThreatSnapshot, error) {
	return ParseEPSS(r, fetchedAt)
}
