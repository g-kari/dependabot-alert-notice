package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ListPendingForTarget filters policy and severity before the per-poll limit.
// Only queue identity fields are read; descriptions/evaluations remain in DB.
func (s *Store) ListPendingForTarget(ctx context.Context, cfg config.Config, target config.Target, limit int) ([]*model.AlertRecord, error) {
	if len(cfg.Targets) == 0 {
		return nil, nil
	}
	targets := make([]config.Target, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		clean := config.Target{Owner: strings.TrimSpace(t.Owner), Repo: strings.TrimSpace(t.Repo)}
		for _, ex := range t.Excludes {
			clean.Excludes = append(clean.Excludes, strings.TrimSpace(ex))
		}
		targets = append(targets, clean)
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		return nil, fmt.Errorf("評価候補監視設定解析: %w", err)
	}
	if limit < 1 {
		limit = 10
	}
	if limit > 1000 {
		limit = 1000
	}
	query := `SELECT a.id,a.owner,a.repo,COALESCE(json_extract(a.alert_json,'$.Severity'),'') FROM alert_records a
	WHERE a.resolved_at IS NULL AND a.eval_status IN ('pending','failed') AND a.owner=? COLLATE NOCASE
	AND EXISTS (SELECT 1 FROM json_each(?) t WHERE json_extract(t.value,'$.Owner')=a.owner COLLATE NOCASE AND (json_extract(t.value,'$.Repo')='' OR json_extract(t.value,'$.Repo')=a.repo COLLATE NOCASE))
	AND NOT EXISTS (SELECT 1 FROM json_each(?) t JOIN json_each(t.value,'$.Excludes') ex WHERE json_extract(t.value,'$.Owner')=a.owner COLLATE NOCASE AND (json_extract(t.value,'$.Repo')='' OR json_extract(t.value,'$.Repo')=a.repo COLLATE NOCASE) AND ex.value=a.repo COLLATE NOCASE)`
	args := []any{strings.TrimSpace(target.Owner), string(encoded), string(encoded)}
	if target.Repo != "" {
		query += " AND a.repo=? COLLATE NOCASE"
		args = append(args, strings.TrimSpace(target.Repo))
	}
	if !cfg.Evaluator.ShouldEvaluate("low") {
		var allowed []string
		for _, level := range []string{"critical", "high", "medium"} {
			if cfg.Evaluator.ShouldEvaluate(level) {
				allowed = append(allowed, level)
			}
		}
		levels, err := json.Marshal(allowed)
		if err != nil {
			return nil, fmt.Errorf("評価重要度解析: %w", err)
		}
		query += " AND json_extract(a.alert_json,'$.Severity') IN (SELECT value FROM json_each(?))"
		args = append(args, string(levels))
	}
	query += ` ORDER BY CASE json_extract(a.alert_json,'$.Severity') WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,a.id LIMIT ?`
	args = append(args, limit)
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("監視中の評価候補取得: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var records []*model.AlertRecord
	for rows.Next() {
		rec := &model.AlertRecord{}
		if err := rows.Scan(&rec.Alert.ID, &rec.Alert.Owner, &rec.Alert.Repo, &rec.Alert.Severity); err != nil {
			return nil, fmt.Errorf("評価候補読込: %w", err)
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("評価候補走査: %w", err)
	}
	return records, nil
}
