package enrichmentrefresh

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

const boundedHTTPMaxEncoded = 16 << 20
const boundedHTTPMaxDecoded = 32 << 20

// HTTPSourceProfile fixes one explicitly configured source URL and payload
// encoding ("identity" or "gzip"). It does not supply provider defaults.
type HTTPSourceProfile struct {
	URL      string
	Encoding string
}

type boundedHTTPSource struct {
	url      string
	encoding string
}

// BoundedHTTPFetcher supplies decoded parser-input bytes through an explicitly
// injected raw RoundTripper. It has no default transport, endpoint or wiring.
// Limits count encoded entity-body and decoded payload bytes, not HTTP framing,
// TLS, headers or allocations/internal retries inside an injected transport.
type BoundedHTTPFetcher struct {
	transport http.RoundTripper
	sources   map[string]boundedHTTPSource
}

// NewBoundedHTTPFetcher validates and copies fixed HTTPS source profiles.
// The injected transport must return raw entity bytes, respect request context,
// and not add credentials, follow redirects or transparently decode/retry.
// An arbitrary noncooperative transport/Body cannot be forcibly stopped here.
func NewBoundedHTTPFetcher(transport http.RoundTripper, sources map[string]HTTPSourceProfile) (*BoundedHTTPFetcher, error) {
	if boundedHTTPNil(transport) || len(sources) < 1 || len(sources) > 2 {
		return nil, boundedHTTPError("invalid dependencies")
	}
	f := &BoundedHTTPFetcher{transport: transport, sources: make(map[string]boundedHTTPSource, len(sources))}
	for source, profile := range sources {
		u, err := url.Parse(profile.URL)
		if (source != "epss" && source != "kev") || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(profile.URL, "#") || (profile.Encoding != "identity" && profile.Encoding != "gzip") {
			return nil, boundedHTTPError("invalid source profile")
		}
		// NewRequest also validates a host/port without performing any I/O.
		if _, err := http.NewRequest(http.MethodGet, profile.URL, nil); err != nil {
			return nil, boundedHTTPError("invalid source profile")
		}
		f.sources[source] = boundedHTTPSource{url: profile.URL, encoding: profile.Encoding}
	}
	return f, nil
}

func boundedHTTPNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func boundedHTTPError(reason string) error {
	return fmt.Errorf("bounded threat transport: %s", reason)
}

func boundedHTTPReadError(ctx context.Context, cause error, reason string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("bounded threat transport: %w", err)
	}
	if errors.Is(cause, context.Canceled) {
		return fmt.Errorf("bounded threat transport: %w", context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return fmt.Errorf("bounded threat transport: %w", context.DeadlineExceeded)
	}
	return boundedHTTPError(reason)
}

type boundedHTTPContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r boundedHTTPContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if canceled := r.ctx.Err(); canceled != nil {
		return n, canceled
	}
	return n, err
}

type boundedHTTPBodyClose struct {
	body io.ReadCloser
	once sync.Once
	err  error
}

func (b *boundedHTTPBodyClose) close() error {
	b.once.Do(func() { b.err = b.body.Close() })
	return b.err
}

func boundedHTTPHeaders(header http.Header, name string) []string {
	var values []string
	for key, entries := range header {
		if strings.EqualFold(key, name) {
			values = append(values, entries...)
		}
	}
	return values
}

func boundedHTTPResponseLength(response *http.Response) error {
	if response.ContentLength < -1 || response.ContentLength > boundedHTTPMaxEncoded {
		return boundedHTTPError("invalid encoded length")
	}
	values := boundedHTTPHeaders(response.Header, "Content-Length")
	if len(values) == 0 {
		return nil
	}
	if len(values) != 1 || values[0] == "" {
		return boundedHTTPError("invalid encoded length")
	}
	for _, c := range values[0] {
		if c < '0' || c > '9' {
			return boundedHTTPError("invalid encoded length")
		}
	}
	length, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || length != response.ContentLength {
		return boundedHTTPError("invalid encoded length")
	}
	return nil
}

// Fetch makes exactly one RoundTrip and returns only complete, owned decoded
// bytes. It never redirects, retries, creates metadata, parses or reserializes.
// HTTP content coding must be absent/identity; gzip is a configured payload
// representation, not an automatically negotiated HTTP coding.
func (f *BoundedHTTPFetcher) Fetch(ctx context.Context, source string) (data []byte, err error) {
	if ctx == nil || f == nil || boundedHTTPNil(f.transport) {
		return nil, boundedHTTPError("invalid dependencies")
	}
	if ctx.Err() != nil {
		return nil, boundedHTTPReadError(ctx, nil, "canceled")
	}
	profile, ok := f.sources[source]
	if !ok {
		return nil, boundedHTTPError("unsupported source")
	}
	request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, profile.url, nil)
	if requestErr != nil {
		return nil, boundedHTTPError("invalid source profile")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, roundTripErr := f.transport.RoundTrip(request)
	if response != nil && !boundedHTTPNil(response.Body) {
		closer := &boundedHTTPBodyClose{body: response.Body}
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(done)
			// Fetch cleanup joins and checks this same stored Close result.
			_ = closer.close()
		})
		defer func() {
			stopped := stop()
			closeErr := closer.close()
			if !stopped {
				<-done
			}
			if closeErr != nil {
				data = nil
				if err == nil {
					err = boundedHTTPError("cannot close response")
				}
			}
			if ctx.Err() != nil {
				data = nil
				err = boundedHTTPReadError(ctx, nil, "canceled")
			}
		}()
	}
	if roundTripErr != nil {
		return nil, boundedHTTPReadError(ctx, roundTripErr, "request failed")
	}
	if ctx.Err() != nil {
		return nil, boundedHTTPReadError(ctx, nil, "canceled")
	}
	if response == nil || boundedHTTPNil(response.Body) {
		return nil, boundedHTTPError("invalid response")
	}
	if response.StatusCode != http.StatusOK {
		return nil, boundedHTTPError("unexpected status")
	}
	codings := boundedHTTPHeaders(response.Header, "Content-Encoding")
	if response.Uncompressed || len(codings) > 1 || (len(codings) == 1 && strings.TrimSpace(codings[0]) != "" && !strings.EqualFold(strings.TrimSpace(codings[0]), "identity")) {
		return nil, boundedHTTPError("unexpected content coding")
	}
	if err := boundedHTTPResponseLength(response); err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(boundedHTTPContextReader{ctx: ctx, reader: response.Body}, boundedHTTPMaxEncoded+1))
	if readErr != nil {
		return nil, boundedHTTPReadError(ctx, readErr, "cannot read response")
	}
	if len(raw) > boundedHTTPMaxEncoded || (response.ContentLength >= 0 && int64(len(raw)) != response.ContentLength) {
		return nil, boundedHTTPError("encoded length mismatch")
	}
	if ctx.Err() != nil {
		return nil, boundedHTTPReadError(ctx, nil, "canceled")
	}
	if profile.encoding == "identity" {
		return raw, nil
	}
	input := bytes.NewReader(raw) // io.ByteReader prevents read-ahead past one member.
	reader, gzipErr := gzip.NewReader(input)
	if gzipErr != nil {
		return nil, boundedHTTPError("invalid gzip payload")
	}
	reader.Multistream(false)
	decoded, decodeErr := io.ReadAll(io.LimitReader(boundedHTTPContextReader{ctx: ctx, reader: reader}, boundedHTTPMaxDecoded+1))
	closeErr := reader.Close()
	if decodeErr != nil {
		return nil, boundedHTTPReadError(ctx, decodeErr, "invalid gzip payload")
	}
	if closeErr != nil || len(decoded) > boundedHTTPMaxDecoded || input.Len() != 0 {
		return nil, boundedHTTPError("invalid gzip boundary")
	}
	// A second gzip layer is outside the configured CSV/catalog representation.
	// Never sniff and recursively decode it.
	if len(decoded) >= 2 && decoded[0] == 0x1f && decoded[1] == 0x8b {
		return nil, boundedHTTPError("nested gzip payload")
	}
	if ctx.Err() != nil {
		return nil, boundedHTTPReadError(ctx, nil, "canceled")
	}
	return decoded, nil
}

var _ Fetcher = (*BoundedHTTPFetcher)(nil)
