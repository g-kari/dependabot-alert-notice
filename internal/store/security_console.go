package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// SecuritySourceCount counts retained findings by their latest recorded source.
type SecuritySourceCount struct {
	Source string
	Count  int
}

// SecurityOverview is a global retained snapshot, not a scan-coverage claim.
// Only the severe queue and source breakdown are materialized, with fixed bounds.
type SecurityOverview struct {
	AsOf                                                                            time.Time
	Total, Active, Critical, High, Resolved, Unknown, Assets, AssetsWithoutFindings int
	Sources                                                                         []SecuritySourceCount
	SourcesTruncated                                                                bool
	Severe                                                                          []FindingView
}

// QuerySecurityOverview reads global scalar aggregates and at most eight active
// severe findings in one snapshot. Severity ordering is not a priority score.
func (s *Store) QuerySecurityOverview(ctx context.Context, asOf time.Time) (SecurityOverview, error) {
	if !securityTime(asOf) || !securityTime(asOf.UTC()) {
		return SecurityOverview{}, fmt.Errorf("invalid overview time")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return SecurityOverview{}, fmt.Errorf("begin security overview: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	view := SecurityOverview{AsOf: asOf.UTC(), Sources: []SecuritySourceCount{}, Severe: []FindingView{}}
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(source_status='active'),0),COALESCE(SUM(source_status='active' AND severity='critical'),0),COALESCE(SUM(source_status='active' AND severity='high'),0),COALESCE(SUM(source_status='resolved'),0),COALESCE(SUM(source_status='unknown'),0) FROM findings`).Scan(&view.Total, &view.Active, &view.Critical, &view.High, &view.Resolved, &view.Unknown)
	if err != nil {
		return SecurityOverview{}, fmt.Errorf("count overview findings: %w", err)
	}
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(NOT EXISTS(SELECT 1 FROM findings f WHERE f.asset_id=a.id)),0) FROM assets a`).Scan(&view.Assets, &view.AssetsWithoutFindings)
	if err != nil {
		return SecurityOverview{}, fmt.Errorf("count overview assets: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT COALESCE((SELECT o.source FROM observations o WHERE o.finding_id=f.id ORDER BY `+securityTimeDescending("o.observed_at")+`,o.id DESC LIMIT 1),'unknown') AS source,COUNT(*) FROM findings f GROUP BY source ORDER BY source COLLATE BINARY LIMIT 65`)
	if err != nil {
		return SecurityOverview{}, fmt.Errorf("query overview sources: %w", err)
	}
	if err := readOverviewSources(rows, &view); err != nil {
		return SecurityOverview{}, err
	}
	findings, err := readSecurityPageItems[model.Finding](ctx, tx, `SELECT body_json FROM findings WHERE source_status='active' AND severity IN ('critical','high') ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END,`+securityTimeDescending("last_seen")+`,id ASC LIMIT 8`)
	if err != nil {
		return SecurityOverview{}, fmt.Errorf("read overview severe queue: %w", err)
	}
	for _, finding := range findings {
		projected, err := projectFinding(ctx, tx, finding, "")
		if err != nil {
			return SecurityOverview{}, fmt.Errorf("project overview finding: %w", err)
		}
		view.Severe = append(view.Severe, projected)
	}
	if err := tx.Commit(); err != nil {
		return SecurityOverview{}, fmt.Errorf("finish security overview: %w", err)
	}
	return view, nil
}

func readOverviewSources(rows *sql.Rows, view *SecurityOverview) error {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var count SecuritySourceCount
		if err := rows.Scan(&count.Source, &count.Count); err != nil {
			return fmt.Errorf("scan overview source: %w", err)
		}
		if len(view.Sources) < 64 {
			view.Sources = append(view.Sources, count)
		} else {
			view.SourcesTruncated = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate overview sources: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close overview sources: %w", err)
	}
	return nil
}

// ConsoleAssetQuery filters saved asset facts and recorded finding sources.
// Empty values retain all assets, including assets with no retained findings.
type ConsoleAssetQuery struct {
	Search, Provider, Account, Region, Environment, Criticality, Source string
	Limit, Offset                                                       int
}

// ConsoleAssetItem preserves saved identity and bounded scalar finding metadata.
type ConsoleAssetItem struct {
	model.Asset
	Findings, Active int
	LastObserved     time.Time
	Sources          []string
	SourcesTruncated bool
}

// ConsoleAssetPage is a filtered count and a bounded stable asset page.
type ConsoleAssetPage struct {
	Items                []ConsoleAssetItem
	Total, Limit, Offset int
}

// ConsoleAssetDetail links one saved asset to a bounded common finding page.
type ConsoleAssetDetail struct {
	Asset    model.Asset
	Findings FindingPage
}

// ErrAssetNotFound identifies a missing saved asset.
var ErrAssetNotFound = errors.New("asset not found")

// ValidateConsoleAssetQuery validates UI-only filters without changing Assets API.
func ValidateConsoleAssetQuery(query ConsoleAssetQuery) error {
	if err := validateFindingQuery(FindingQuery{Source: query.Source, Limit: query.Limit, Offset: query.Offset}); err != nil {
		return fmt.Errorf("validate asset finding source: %w", err)
	}
	if err := validateSecurityPagination(query.Limit, query.Offset); err != nil {
		return err
	}
	for _, value := range []string{query.Search, query.Provider, query.Account, query.Region, query.Environment, query.Criticality, query.Source} {
		if !validSecurityQueryText(value, 256) {
			return fmt.Errorf("invalid asset filter")
		}
	}
	return nil
}

func consoleAssetWhere(query ConsoleAssetQuery) (string, []any) {
	var clauses []string
	var args []any
	for _, filter := range []struct{ column, value string }{{"provider", query.Provider}, {"account", query.Account}, {"region", query.Region}, {"environment", query.Environment}, {"criticality", query.Criticality}} {
		if filter.value != "" {
			clauses = append(clauses, "a."+filter.column+"=?")
			args = append(args, filter.value)
		}
	}
	if query.Source != "" {
		clauses = append(clauses, `EXISTS(SELECT 1 FROM findings f JOIN observations o ON o.finding_id=f.id WHERE f.asset_id=a.id AND o.source=?)`)
		args = append(args, query.Source)
	}
	if query.Search != "" {
		literal := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(query.Search) + "%"
		var searches []string
		for _, column := range []string{"id", "type", "provider", "account", "region", "native_id", "environment", "criticality"} {
			searches = append(searches, "a."+column+` LIKE ? ESCAPE '\'`)
			args = append(args, literal)
		}
		clauses = append(clauses, "("+strings.Join(searches, " OR ")+")")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// QueryConsoleAssetsPage reads saved facts and scalar summaries in one snapshot.
// It never materializes the full inventory or infers scan coverage from findings.
func (s *Store) QueryConsoleAssetsPage(ctx context.Context, query ConsoleAssetQuery) (ConsoleAssetPage, error) {
	if err := ValidateConsoleAssetQuery(query); err != nil {
		return ConsoleAssetPage{}, fmt.Errorf("validate console assets: %w", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ConsoleAssetPage{}, fmt.Errorf("begin console assets: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	page := ConsoleAssetPage{Items: []ConsoleAssetItem{}, Limit: query.Limit, Offset: query.Offset}
	where, args := consoleAssetWhere(query)
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets a`+where, args...).Scan(&page.Total); err != nil {
		return ConsoleAssetPage{}, fmt.Errorf("count console assets: %w", err)
	}
	pageArgs := append(append([]any{}, args...), query.Limit, query.Offset)
	assets, err := readSecurityPageItems[model.Asset](ctx, tx, `SELECT a.body_json FROM assets a`+where+` ORDER BY a.id COLLATE BINARY LIMIT ? OFFSET ?`, pageArgs...)
	if err != nil {
		return ConsoleAssetPage{}, fmt.Errorf("read console assets: %w", err)
	}
	for _, asset := range assets {
		item := ConsoleAssetItem{Asset: asset}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(source_status='active'),0) FROM findings WHERE asset_id=?`, asset.ID).Scan(&item.Findings, &item.Active); err != nil {
			return ConsoleAssetPage{}, fmt.Errorf("count asset findings: %w", err)
		}
		var observed string
		err := tx.QueryRowContext(ctx, `SELECT o.observed_at FROM observations o JOIN findings f ON f.id=o.finding_id WHERE f.asset_id=? ORDER BY `+securityTimeDescending("o.observed_at")+`,o.id DESC LIMIT 1`, asset.ID).Scan(&observed)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ConsoleAssetPage{}, fmt.Errorf("read asset observation time: %w", err)
		}
		if err == nil {
			item.LastObserved, err = time.Parse(time.RFC3339Nano, observed)
			if err != nil {
				return ConsoleAssetPage{}, fmt.Errorf("parse asset observation time: %w", err)
			}
		}
		item.Sources, item.SourcesTruncated, err = readConsoleAssetSources(ctx, tx, asset.ID)
		if err != nil {
			return ConsoleAssetPage{}, err
		}
		page.Items = append(page.Items, item)
	}
	if err := tx.Commit(); err != nil {
		return ConsoleAssetPage{}, fmt.Errorf("finish console assets: %w", err)
	}
	return page, nil
}

func readConsoleAssetSources(ctx context.Context, tx *sql.Tx, id string) ([]string, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT o.source FROM observations o JOIN findings f ON f.id=o.finding_id WHERE f.asset_id=? ORDER BY o.source COLLATE BINARY LIMIT 65`, id)
	if err != nil {
		return nil, false, fmt.Errorf("query asset sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	sources := []string{}
	truncated := false
	for rows.Next() {
		var source string
		if err := rows.Scan(&source); err != nil {
			return nil, false, fmt.Errorf("scan asset source: %w", err)
		}
		if len(sources) < 64 {
			sources = append(sources, source)
		} else {
			truncated = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate asset sources: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, false, fmt.Errorf("close asset sources: %w", err)
	}
	return sources, truncated, nil
}

// GetConsoleAssetDetail reads one identity and filtered common findings in a
// consistent bounded snapshot. The caller's AssetID cannot redirect the query.
func (s *Store) GetConsoleAssetDetail(ctx context.Context, id string, query FindingQuery) (ConsoleAssetDetail, error) {
	if id == "" || !validSecurityQueryText(id, 128) {
		return ConsoleAssetDetail{}, fmt.Errorf("get console asset: %w", ErrAssetNotFound)
	}
	query.AssetID = id
	if err := validateFindingQuery(query); err != nil {
		return ConsoleAssetDetail{}, fmt.Errorf("validate asset findings: %w", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ConsoleAssetDetail{}, fmt.Errorf("begin console asset: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var body string
	if err := tx.QueryRowContext(ctx, `SELECT body_json FROM assets WHERE id=?`, id).Scan(&body); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ConsoleAssetDetail{}, fmt.Errorf("get console asset: %w", ErrAssetNotFound)
		}
		return ConsoleAssetDetail{}, fmt.Errorf("read console asset: %w", err)
	}
	var detail ConsoleAssetDetail
	if err := json.Unmarshal([]byte(body), &detail.Asset); err != nil {
		return ConsoleAssetDetail{}, fmt.Errorf("decode console asset: %w", err)
	}
	detail.Findings, err = readFindingPage(ctx, tx, query, "")
	if err != nil {
		return ConsoleAssetDetail{}, fmt.Errorf("read asset findings: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ConsoleAssetDetail{}, fmt.Errorf("finish console asset: %w", err)
	}
	return detail, nil
}
