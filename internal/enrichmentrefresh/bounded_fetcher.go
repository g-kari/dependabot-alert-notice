package enrichmentrefresh

import (
	"context"
	"errors"
	"net/http"
)

// HTTPSourceProfile fixes one explicitly configured source URL and payload
// encoding ("identity" or "gzip"). It does not supply provider defaults.
type HTTPSourceProfile struct {
	URL      string
	Encoding string
}

// BoundedHTTPFetcher supplies decoded parser-input bytes through an explicitly
// injected RoundTripper. No default transport, endpoint or application wiring
// is provided. This Red checkpoint is a compile-capable unavailable stub.
type BoundedHTTPFetcher struct{}

// NewBoundedHTTPFetcher declares the explicit transport and source-profile
// boundary. Validation and fetching are intentionally unavailable in this Red
// checkpoint; callers must not treat construction as an implemented adapter.
func NewBoundedHTTPFetcher(transport http.RoundTripper, sources map[string]HTTPSourceProfile) (*BoundedHTTPFetcher, error) {
	return &BoundedHTTPFetcher{}, nil
}

// Fetch is the unavailable runtime contract seam for this Red checkpoint.
func (f *BoundedHTTPFetcher) Fetch(ctx context.Context, source string) ([]byte, error) {
	return nil, errors.New("bounded transport unavailable")
}

var _ Fetcher = (*BoundedHTTPFetcher)(nil)
