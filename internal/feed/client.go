package feed

import (
	"context"
	"time"
)

// Client is an injectable feed HTTP client facade.
type Client struct{ Options FetchOptions }

func NewClient(options FetchOptions) *Client { return &Client{Options: options} }

func (c *Client) Fetch(ctx context.Context, feedURL string) ([]Item, error) {
	options := c.Options
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	return Fetch(ctx, feedURL, options)
}
