package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// RelatedFindingPage describes a read-only same-CVE association, not duplicate
// identity or exploitability. None indicates an anchor without a canonical CVE.
type RelatedFindingPage struct {
	FindingPage
	AnchorID     string `json:"anchor_id"`
	CVEID        string `json:"cve_id,omitempty"`
	Relationship string `json:"relationship"`
}

// QueryRelatedFindings returns distinct findings with the anchor's exact CVE.
// Anchor selection, count, provenance and enrichment share one read snapshot.
func (s *Store) QueryRelatedFindings(ctx context.Context, id string, query FindingQuery) (RelatedFindingPage, error) {
	if query.CVEID != "" {
		return RelatedFindingPage{}, fmt.Errorf("related finding query cannot override anchor CVE")
	}
	if err := validateFindingQuery(query); err != nil {
		return RelatedFindingPage{}, fmt.Errorf("validate related finding query: %w", err)
	}
	if id == "" || !validSecurityQueryText(id, 128) {
		return RelatedFindingPage{}, fmt.Errorf("get related anchor: %w", ErrFindingNotFound)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RelatedFindingPage{}, fmt.Errorf("begin related finding page: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var body, category string
	if err := tx.QueryRowContext(ctx, "SELECT body_json,category FROM findings WHERE id=?", id).Scan(&body, &category); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RelatedFindingPage{}, fmt.Errorf("get related anchor: %w", ErrFindingNotFound)
		}
		return RelatedFindingPage{}, fmt.Errorf("read related anchor: %w", err)
	}
	var anchor model.Finding
	if err := json.Unmarshal([]byte(body), &anchor); err != nil {
		return RelatedFindingPage{}, fmt.Errorf("decode related anchor: %w", err)
	}
	page := RelatedFindingPage{FindingPage: FindingPage{Items: make([]FindingView, 0), Limit: query.Limit, Offset: query.Offset}, AnchorID: id, Relationship: "none"}
	if category == "vulnerability" && anchor.Category == "vulnerability" && canonicalFindingCVE(anchor.VulnerabilityID) {
		page.CVEID = anchor.VulnerabilityID
		page.Relationship = "same_cve"
		query.CVEID = page.CVEID
		page.FindingPage, err = readFindingPage(ctx, tx, query, id)
		if err != nil {
			return RelatedFindingPage{}, fmt.Errorf("read related finding page: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return RelatedFindingPage{}, fmt.Errorf("finish related finding page: %w", err)
	}
	return page, nil
}
