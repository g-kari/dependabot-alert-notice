package store

import (
	"fmt"
	"sync"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

type Store struct {
	mu      sync.RWMutex
	records map[int]*model.AlertRecord
	logs    []model.LogEntry
}

func New() *Store {
	return &Store{
		records: make(map[int]*model.AlertRecord),
	}
}

func (s *Store) Save(record *model.AlertRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.Alert.ID] = record
}

func (s *Store) Get(alertID int) (*model.AlertRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[alertID]
	if !ok {
		return nil, fmt.Errorf("アラートID %d が見つかりません", alertID)
	}
	return r, nil
}

func (s *Store) List() []*model.AlertRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*model.AlertRecord, 0, len(s.records))
	for _, r := range s.records {
		result = append(result, r)
	}
	return result
}

func (s *Store) Has(alertID int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.records[alertID]
	return ok
}

func (s *Store) UpdateState(alertID int, state model.AlertState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[alertID]
	if !ok {
		return fmt.Errorf("アラートID %d が見つかりません", alertID)
	}
	r.State = state
	if state == model.AlertStateMerged {
		now := time.Now()
		r.MergedAt = &now
	}
	return nil
}

func (s *Store) AddLog(entry model.LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, entry)
}

func (s *Store) ListLogs() []model.LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.LogEntry, len(s.logs))
	copy(result, s.logs)
	return result
}
