package enrichmentrefresh

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"testing"
)

type boundedRoundTripFunc func(*http.Request) (*http.Response, error)

func (f boundedRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type boundedContractBody struct {
	reader io.Reader
	eof    bool
	closes int
}

func (b *boundedContractBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

func (b *boundedContractBody) Close() error {
	b.closes++
	return nil
}

func assertBoundedContractFetch(t *testing.T, source, endpoint, encoding string, encoded, decoded []byte) {
	t.Helper()
	ctx := context.Background()
	want := bytes.Clone(decoded)
	body := &boundedContractBody{reader: bytes.NewReader(encoded)}
	calls := 0
	transport := boundedRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Context() != ctx || request.Method != http.MethodGet || request.URL.String() != endpoint || request.URL.User != nil || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.Header.Get("Accept-Encoding") != "identity" || (request.Body != nil && request.Body != http.NoBody) {
			t.Fatalf("request escaped fixed source/context/header contract: %+v", request)
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
			if request.Header.Get(name) != "" {
				t.Fatalf("unexpected credential header %s", name)
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			ContentLength: int64(len(encoded)), Body: body,
		}, nil
	})
	fetcher, err := NewBoundedHTTPFetcher(transport, map[string]HTTPSourceProfile{
		source: {URL: endpoint, Encoding: encoding},
	})
	if err != nil {
		t.Fatalf("explicit synthetic profile rejected: %v", err)
	}
	got, err := fetcher.Fetch(ctx, source)
	if err != nil {
		t.Fatalf("bounded contract fetch failed: %v", err)
	}
	if !bytes.Equal(got, want) || calls != 1 || !body.eof || body.closes != 1 {
		t.Fatalf("incomplete bytes/EOF/close/one-call result: bytes=%d calls=%d eof=%v closes=%d", len(got), calls, body.eof, body.closes)
	}
	// Returned bytes must be owned independently of the supplied body storage.
	if len(encoded) != 0 {
		encoded[0] ^= 0xff
	}
	if !bytes.Equal(got, want) {
		t.Fatal("returned parser-input bytes alias the supplied body storage")
	}
}

func TestBoundedHTTPFetcherContractIdentityReturnsCompleteSyntheticInput(t *testing.T) {
	// Authored projection-minimal catalog JSON, not retrieved provider data.
	data := []byte(`{"catalogVersion":"synthetic-transport.1","dateReleased":"2026-11-10T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-11-09"}]}`)
	assertBoundedContractFetch(t, "kev", "https://fixture.invalid/synthetic/kev.json", "identity", data, data)
}

func TestBoundedHTTPFetcherContractSingleGzipReturnsDecodedSyntheticInput(t *testing.T) {
	// Authored metadata-bearing CSV accepted by the existing offline parser.
	data := []byte("#model_version:synthetic-transport,score_date:2026-11-10\ncve,epss,percentile\nCVE-2026-1234,0,0\n")
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	assertBoundedContractFetch(t, "epss", "https://fixture.invalid/synthetic/epss.csv.gz", "gzip", encoded.Bytes(), data)
}
