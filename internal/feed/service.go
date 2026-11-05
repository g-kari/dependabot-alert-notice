package feed

import (
	"context"
)

// Service provides a small cancellable refresh loop around an injected fetch
// function. Persistence is deliberately supplied by the caller.
type Service struct {
	Fetch   func(context.Context) error
	trigger chan struct{}
}

func (s *Service) Trigger() {
	if s.trigger == nil {
		s.trigger = make(chan struct{}, 1)
	}
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *Service) Run(ctx context.Context) error {
	if s.Fetch == nil {
		return nil
	}
	if s.trigger == nil {
		s.trigger = make(chan struct{}, 1)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.trigger:
			if err := s.Fetch(ctx); err != nil {
				return err
			}
		}
	}
}

// RefreshOnce performs one explicit refresh.
func (s *Service) RefreshOnce(ctx context.Context) error {
	if s.Fetch == nil {
		return nil
	}
	return s.Fetch(ctx)
}
