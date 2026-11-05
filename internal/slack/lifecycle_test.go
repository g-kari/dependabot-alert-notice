package slack

import (
	"context"
	"testing"
	"time"

	"github.com/slack-go/slack/socketmode"
)

func TestHandleEventsStopsWhenApplicationIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &SlackClient{socket: &socketmode.Client{Events: make(chan socketmode.Event)}}
	done := make(chan struct{})
	go func() { c.handleEvents(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event worker did not stop")
	}
}
