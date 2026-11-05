package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ErrRiskInputsChanged asks a worker to discard and rebuild an outdated snapshot.
var ErrRiskInputsChanged = errors.New("risk input revision changed")

// RiskScope is a coalesced set of repositories/advisories; All requests a sweep.
type RiskScope struct {
	All        bool
	Repos      []string
	Advisories []string
}

// ListRiskInputs returns bounded scoring fields, never descriptions/evaluations.
func (s *Store) ListRiskInputs(ctx context.Context, scope RiskScope, afterID, limit int) ([]*model.AlertRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit < 1 {
		limit = 300
	}
	if limit > 1000 {
		limit = 1000
	}
	var clauses []string
	args := []any{afterID}
	if !scope.All {
		for _, repo := range scope.Repos {
			parts := strings.SplitN(strings.TrimSpace(repo), "/", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				continue
			}
			clauses = append(clauses, "(owner=? COLLATE NOCASE AND repo=? COLLATE NOCASE)")
			args = append(args, parts[0], parts[1])
		}
		for _, key := range scope.Advisories {
			if strings.HasPrefix(key, "cve:") {
				clauses = append(clauses, "UPPER(json_extract(alert_json,'$.CVEID'))=?")
				args = append(args, strings.ToUpper(strings.TrimPrefix(key, "cve:")))
			} else {
				clauses = append(clauses, "('ghsa:' || UPPER(COALESCE(json_extract(alert_json,'$.GHSAID'),'')) || ':alert:' || id)=?")
				args = append(args, key)
			}
		}
		if len(clauses) == 0 {
			return nil, nil
		}
	}
	query := `SELECT id,owner,repo,number,COALESCE(json_extract(alert_json,'$.CVEID'),''),COALESCE(json_extract(alert_json,'$.GHSAID'),''),COALESCE(json_extract(alert_json,'$.CVSSScore'),0),COALESCE(json_extract(alert_json,'$.CVSSKnown'),0),COALESCE(json_extract(alert_json,'$.CVSSVersion'),''),COALESCE(json_extract(alert_json,'$.CVSSVector'),''),notified_at,state FROM alert_records WHERE resolved_at IS NULL AND id>?`
	if !scope.All {
		query += " AND (" + strings.Join(clauses, " OR ") + ")"
	}
	query += " ORDER BY id LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("緊急度入力取得失敗: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var records []*model.AlertRecord
	for rows.Next() {
		rec := &model.AlertRecord{}
		a := &rec.Alert
		if err := rows.Scan(&a.ID, &a.Owner, &a.Repo, &a.Number, &a.CVEID, &a.GHSAID, &a.CVSSScore, &a.CVSSKnown, &a.CVSSVersion, &a.CVSSVector, &rec.NotifiedAt, &rec.State); err != nil {
			return nil, fmt.Errorf("緊急度入力読込失敗: %w", err)
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("緊急度入力走査失敗: %w", err)
	}
	return records, nil
}

// RiskRevision identifies the current in-process input generation.
func (s *Store) RiskRevision() uint64 { s.mu.RLock(); defer s.mu.RUnlock(); return s.riskRevision }

// SaveRiskEvaluationAtRevision refuses outdated calculations before writing.
func (s *Store) SaveRiskEvaluationAtRevision(ctx context.Context, revision uint64, profileID, repo, key, hash string, input model.ScoreInput, result model.ScoreResult, due time.Time, resolved bool) (*DeadlineRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.riskRevision {
		return nil, ErrRiskInputsChanged
	}
	return s.saveRiskEvaluation(ctx, profileID, repo, key, hash, input, result, due, resolved)
}

// CheckRiskRevision validates a no-write/cached sweep before publishing its cache.
func (s *Store) CheckRiskRevision(ctx context.Context, revision uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if revision != s.riskRevision {
		return ErrRiskInputsChanged
	}
	return nil
}

// SubscribeRiskChanges registers coalesced notifications. Overflow becomes a
// full sweep rather than dropping an input change. The cancellation is idempotent.
func (s *Store) SubscribeRiskChanges() (<-chan RiskScope, func()) {
	s.mu.Lock()
	ch := make(chan RiskScope, 1)
	if s.riskSubs == nil {
		s.riskSubs = make(map[chan RiskScope]struct{})
	}
	s.riskSubs[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.riskSubs[ch]; ok {
			delete(s.riskSubs, ch)
			close(ch)
		}
	}
}

func (s *Store) riskChangedLocked(scope RiskScope) {
	s.riskRevision++
	for ch := range s.riskSubs {
		select {
		case ch <- scope:
		default:
			select {
			case <-ch:
			default:
			}
			ch <- RiskScope{All: true}
		}
	}
}
