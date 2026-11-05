package main

import (
	"context"
	"errors"
	"sync"
)

func startManagedSchedulers(ctx context.Context, once bool, services ...func(context.Context)) func() {
	var workers sync.WaitGroup
	if !once {
		for _, service := range services {
			workers.Add(1)
			go func(run func(context.Context)) { defer workers.Done(); run(ctx) }(service)
		}
	}
	return workers.Wait
}
func runOnceSteps(ctx context.Context, steps ...func(context.Context) error) error {
	var failures []error
	for _, step := range steps {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if err := step(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
