package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ErrInvalidConnectorSnapshot identifies retained metadata that cannot safely be
// projected. It never includes raw source errors, receipts or evidence bodies.
var ErrInvalidConnectorSnapshot = errors.New("invalid connector snapshot")

// ConnectorStatusQuery selects exact, case-sensitive source/scope identities.
// AsOf evaluates the current retained snapshot, not a historical reconstruction.
type ConnectorStatusQuery struct {
	Source string
	Scope  string
	AsOf   time.Time
	Limit  int
	Offset int
}

// ConnectorRunSummary exposes only bounded receipt metadata. AgeSeconds measures
// time since completion (or start for running runs); nil means a future time.
// Future evidence must not establish current success, coverage or liveness.
type ConnectorRunSummary struct {
	ID         string     `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Result     string     `json:"result"`
	Coverage   string     `json:"coverage"`
	Future     bool       `json:"future"`
	AgeSeconds *int64     `json:"age_seconds"`
}

// ConnectorRunCounts counts retained runs, not source requests or scanned assets.
type ConnectorRunCounts struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Success int `json:"success"`
	Partial int `json:"partial"`
	Failed  int `json:"failed"`
}

// ConnectorStatus separates the newest recorded attempt from the last completed
// successful receipt. Status and Coverage describe only that latest attempt.
// Liveness cannot be inferred from a persisted running row or an old success.
type ConnectorStatus struct {
	Source        string               `json:"source"`
	Scope         string               `json:"scope"`
	Status        string               `json:"status"`
	Coverage      string               `json:"coverage"`
	Liveness      string               `json:"liveness"`
	RecordedRuns  ConnectorRunCounts   `json:"recorded_runs"`
	LatestAttempt ConnectorRunSummary  `json:"latest_attempt"`
	LastSuccess   *ConnectorRunSummary `json:"last_success"`
}

// ConnectorCoverageBoundary makes unknown inventory explicit. Observed scopes
// are not a denominator: absent scopes may be unconfigured or never collected.
type ConnectorCoverageBoundary struct {
	Basis            string `json:"basis"`
	AttemptHistory   string `json:"attempt_history"`
	ConfiguredScopes *int   `json:"configured_scopes"`
	UnscannedScopes  *int   `json:"unscanned_scopes"`
	AssetDenominator *int   `json:"asset_denominator"`
}

// ConnectorStatusPage contains a bounded page and a count of matching recorded
// source/scope pairs, all read in one immutable transaction.
type ConnectorStatusPage struct {
	AsOf     time.Time                 `json:"as_of"`
	Items    []ConnectorStatus         `json:"items"`
	Total    int                       `json:"total"`
	Limit    int                       `json:"limit"`
	Offset   int                       `json:"offset"`
	Boundary ConnectorCoverageBoundary `json:"coverage_boundary"`
}

// IsConnectorStatusSource reports whether a source belongs to the current
// ingestion contract. It does not claim that the source is configured or live.
func IsConnectorStatusSource(source string) bool {
	switch source {
	case "dependabot", "trivy", "github_code_scanning", "github_secret_scanning", "epss_offline", "kev_offline":
		return true
	default:
		return false
	}
}

// QueryConnectorStatusPage reads only scalar run metadata, never body_json,
// cursor, error or observation payloads. SQL groups retained history; Go holds
// at most Limit groups and two run summaries per group, not all historical runs.
func (s *Store) QueryConnectorStatusPage(ctx context.Context, query ConnectorStatusQuery) (ConnectorStatusPage, error) {
	if err := validateSecurityPagination(query.Limit, query.Offset); err != nil {
		return ConnectorStatusPage{}, fmt.Errorf("validate connector pagination: %w", err)
	}
	if (query.Source != "" && !IsConnectorStatusSource(query.Source)) || (query.Scope != "" && (!securityField(query.Scope, true, 256) || strings.TrimSpace(query.Scope) != query.Scope)) || !securityTime(query.AsOf) || !securityTime(query.AsOf.UTC()) {
		return ConnectorStatusPage{}, fmt.Errorf("invalid connector query")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return ConnectorStatusPage{}, fmt.Errorf("begin connector status: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	where, args := connectorStatusWhere(query)
	page := ConnectorStatusPage{
		AsOf: query.AsOf.UTC(), Limit: query.Limit, Offset: query.Offset, Items: []ConnectorStatus{},
		Boundary: ConnectorCoverageBoundary{Basis: "recorded_source_scope_pairs", AttemptHistory: "unknown"},
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (SELECT connector,scope FROM ingest_runs`+where+` GROUP BY connector,scope)`, args...).Scan(&page.Total); err != nil {
		return ConnectorStatusPage{}, fmt.Errorf("count connector scopes: %w", err)
	}
	pageArgs := append(append([]any{}, args...), query.Limit, query.Offset)
	rows, err := tx.QueryContext(ctx, `SELECT connector,scope,COUNT(*),SUM(result='running'),SUM(result='success'),SUM(result='partial'),SUM(result='failed') FROM ingest_runs`+where+` GROUP BY connector,scope ORDER BY connector COLLATE BINARY,scope COLLATE BINARY LIMIT ? OFFSET ?`, pageArgs...)
	if err != nil {
		return ConnectorStatusPage{}, fmt.Errorf("query connector scopes: %w", err)
	}
	if err := scanConnectorGroups(rows, &page.Items); err != nil {
		return ConnectorStatusPage{}, err
	}
	for i := range page.Items {
		item := &page.Items[i]
		latest, err := readConnectorRun(ctx, tx, item.Source, item.Scope, false, page.AsOf)
		if err != nil {
			return ConnectorStatusPage{}, fmt.Errorf("read latest connector attempt: %w", err)
		}
		item.LatestAttempt = *latest
		item.LastSuccess, err = readConnectorRun(ctx, tx, item.Source, item.Scope, true, page.AsOf)
		if err != nil {
			return ConnectorStatusPage{}, fmt.Errorf("read last connector success: %w", err)
		}
		item.Status, item.Coverage, item.Liveness = latest.Result, latest.Coverage, "unknown"
		if latest.Future {
			item.Status, item.Coverage = "unknown", model.IngestCoverageUnknown
		}
	}
	if err := tx.Commit(); err != nil {
		return ConnectorStatusPage{}, fmt.Errorf("finish connector status: %w", err)
	}
	return page, nil
}

func connectorStatusWhere(query ConnectorStatusQuery) (string, []any) {
	var clauses []string
	var args []any
	for _, field := range []struct{ column, value string }{{"connector", query.Source}, {"scope", query.Scope}} {
		if field.value != "" {
			clauses, args = append(clauses, field.column+"=?"), append(args, field.value)
		}
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func scanConnectorGroups(rows *sql.Rows, items *[]ConnectorStatus) error {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var item ConnectorStatus
		counts := &item.RecordedRuns
		if err := rows.Scan(&item.Source, &item.Scope, &counts.Total, &counts.Running, &counts.Success, &counts.Partial, &counts.Failed); err != nil {
			return fmt.Errorf("scan connector scope: %w", err)
		}
		if !IsConnectorStatusSource(item.Source) || !securityField(item.Scope, true, 256) || strings.TrimSpace(item.Scope) != item.Scope {
			return ErrInvalidConnectorSnapshot
		}
		*items = append(*items, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate connector scopes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close connector scopes: %w", err)
	}
	return nil
}

func readConnectorRun(ctx context.Context, tx *sql.Tx, source, scope string, successOnly bool, asOf time.Time) (*ConnectorRunSummary, error) {
	filter, order := "", securityTimeDescending("started_at")+", id DESC"
	if successOnly {
		filter = " AND result='success' AND finished_at IS NOT NULL"
		order = securityTimeDescending("finished_at") + ", " + order
	}
	var run ConnectorRunSummary
	var started string
	var finished sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT id,started_at,finished_at,result,coverage FROM ingest_runs WHERE connector=? AND scope=?`+filter+` ORDER BY `+order+` LIMIT 1`, source, scope).Scan(&run.ID, &started, &finished, &run.Result, &run.Coverage)
	if errors.Is(err, sql.ErrNoRows) && successOnly {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query connector run: %w", err)
	}
	if !securityUUID(run.ID) {
		return nil, ErrInvalidConnectorSnapshot
	}
	run.StartedAt, err = connectorStatusTime(started)
	if err != nil {
		return nil, err
	}
	anchor := run.StartedAt
	if finished.Valid {
		at, err := connectorStatusTime(finished.String)
		if err != nil || at.Before(run.StartedAt) {
			return nil, ErrInvalidConnectorSnapshot
		}
		run.FinishedAt, anchor = &at, at
	}
	switch run.Result {
	case model.IngestResultRunning:
		if run.FinishedAt != nil {
			return nil, ErrInvalidConnectorSnapshot
		}
	case model.IngestResultSuccess, model.IngestResultPartial, model.IngestResultFailed:
		if run.FinishedAt == nil {
			return nil, ErrInvalidConnectorSnapshot
		}
	default:
		return nil, ErrInvalidConnectorSnapshot
	}
	switch run.Coverage {
	case model.IngestCoverageFull, model.IngestCoveragePartial, model.IngestCoverageUnknown:
	default:
		return nil, ErrInvalidConnectorSnapshot
	}
	run.Future = anchor.After(asOf)
	if !run.Future {
		// Unix seconds avoid time.Duration saturation for valid year 1..9999.
		age := asOf.Unix() - anchor.Unix()
		if asOf.Nanosecond() < anchor.Nanosecond() {
			age--
		}
		run.AgeSeconds = &age
	}
	return &run, nil
}

func connectorStatusTime(raw string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || !securityTime(at) || raw != at.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, ErrInvalidConnectorSnapshot
	}
	return at, nil
}
