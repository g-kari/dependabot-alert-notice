package updater

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestScheduleWaitsForIntervalRetriesAndStopsAfterUpdate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var calls atomic.Int32
		done := make(chan Result, 1)
		go func() {
			result, err := Schedule(ctx, time.Hour, time.Minute, func(context.Context) (Result, error) {
				call := calls.Add(1)
				if call == 1 {
					return Result{}, errors.New("offline")
				}
				return Result{Latest: "v2.0.0", Updated: call == 3}, nil
			})
			if err != nil {
				t.Errorf("schedule: %v", err)
			}
			done <- result
		}()
		synctest.Wait()
		if calls.Load() != 0 {
			t.Fatal("checked before interval")
		}
		for want := 1; want <= 3; want++ {
			time.Sleep(time.Hour)
			synctest.Wait()
			if calls.Load() != int32(want) {
				t.Fatalf("calls=%d want=%d", calls.Load(), want)
			}
		}
		if result := <-done; !result.Updated || result.Latest != "v2.0.0" {
			t.Fatalf("result=%+v", result)
		}
	})
}

func TestScheduleCancelsTimedOutAttemptsAndDoesNotOverlap(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var calls atomic.Int32
		done := make(chan error, 1)
		go func() {
			_, err := Schedule(ctx, time.Minute, 2*time.Minute, func(attempt context.Context) (Result, error) {
				calls.Add(1)
				<-attempt.Done()
				return Result{}, attempt.Err()
			})
			done <- err
		}()
		synctest.Wait()
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("overlapping calls: %d", calls.Load())
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("retry must wait a full interval after attempt: %d", calls.Load())
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatalf("retry calls=%d", calls.Load())
		}
		cancel()
		synctest.Wait()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestScheduleRejectsInvalidIntervals(t *testing.T) {
	for _, duration := range []time.Duration{0, -time.Second} {
		_, err := Schedule(context.Background(), duration, time.Minute, func(context.Context) (Result, error) { t.Fatal("unexpected call"); return Result{}, nil })
		if err == nil {
			t.Fatal("invalid interval accepted")
		}
	}
}

func TestAutomaticUpdatesRequireReleaseAndSupportedPlatform(t *testing.T) {
	for _, tt := range []struct {
		version, os, arch string
		want              bool
	}{
		{"v1.0.0", "darwin", "arm64", true},
		{"v1.0.0-preview.1", "linux", "amd64", true},
		{"dev", "darwin", "arm64", false},
		{"v1.0.0", "windows", "amd64", true},
		{"v1.0.0", "linux", "386", false},
	} {
		u := Updater{Current: tt.version, OS: tt.os, Arch: tt.arch}
		if got := u.SupportsAutomaticUpdates(); got != tt.want {
			t.Fatalf("%+v got=%t", tt, got)
		}
	}
}
