package threat

import (
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"time"
)

// ParseKEVJSON is a compatibility alias for ParseKEV.
func ParseKEVJSON(data []byte, fetchedAt time.Time) (map[string]model.ThreatSnapshot, error) {
	return ParseKEV(data, fetchedAt)
}
