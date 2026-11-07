package model

import "time"

// SecurityEnrichmentFeed is a validated, selected projection of a local threat feed.
type SecurityEnrichmentFeed struct {
	Source       string                    `json:"source"`
	Version      string                    `json:"version"`
	PublishedAt  time.Time                 `json:"published_at"`
	ObservedAt   time.Time                 `json:"observed_at"`
	SelectedCVEs []string                  `json:"selected_cves"`
	Entries      []SecurityEnrichmentEntry `json:"entries"`
}

// SecurityEnrichmentEntry holds positive source evidence, never inferred negatives.
type SecurityEnrichmentEntry struct {
	CVEID        string     `json:"cve_id"`
	EPSS         *float64   `json:"epss,omitempty"`
	Percentile   *float64   `json:"percentile,omitempty"`
	KEV          bool       `json:"kev,omitempty"`
	KEVDateAdded *time.Time `json:"kev_date_added,omitempty"`
}

// SecurityEnrichmentEvidence records immutable source provenance and read-time freshness.
type SecurityEnrichmentEvidence struct {
	Source       string     `json:"source"`
	Version      string     `json:"version"`
	RunID        string     `json:"run_id"`
	RawRef       string     `json:"raw_ref"`
	PublishedAt  time.Time  `json:"published_at"`
	ObservedAt   time.Time  `json:"observed_at"`
	Fresh        bool       `json:"fresh"`
	EPSS         *float64   `json:"epss,omitempty"`
	Percentile   *float64   `json:"percentile,omitempty"`
	KEV          bool       `json:"kev,omitempty"`
	KEVDateAdded *time.Time `json:"kev_date_added,omitempty"`
}

// FindingEnrichment keeps optional enrichment separate from the authoritative finding.
type FindingEnrichment struct {
	CVEID string                      `json:"cve_id"`
	EPSS  *SecurityEnrichmentEvidence `json:"epss,omitempty"`
	KEV   *SecurityEnrichmentEvidence `json:"kev,omitempty"`
}
