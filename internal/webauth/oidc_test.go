package webauth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/webauth"
)

const oidcClient = "synthetic-console-rp"
const oidcNonce = "synthetic-outstanding-login-nonce"

var oidcNow = time.Date(2026, time.November, 14, 12, 0, 0, 0, time.UTC)

type oidcFixture struct {
	key      *ecdsa.PrivateKey
	jwk      map[string]any
	jwks     []byte
	verifier *webauth.OIDCVerifier
}

func newOIDCFixture(t testing.TB) oidcFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := make([]byte, 32), make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": "synthetic-key", "x": encodePart(x), "y": encodePart(y)}
	jwks := oidcJSON(t, map[string]any{"keys": []any{jwk}})
	verifier, err := webauth.NewOIDCVerifier(oidcClient, jwks)
	if err != nil {
		t.Fatal(err)
	}
	return oidcFixture{key: key, jwk: jwk, jwks: jwks, verifier: verifier}
}

func oidcJSON(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func encodePart(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func oidcHeader() map[string]any {
	return map[string]any{"alg": "ES256", "kid": "synthetic-key"}
}

func oidcClaims() map[string]any {
	return map[string]any{"iss": webauth.OIDCIssuer, "aud": oidcClient, "sub": "pairwise-subject-A", "iat": oidcNow.Unix() - 60, "exp": oidcNow.Unix() + 3540, "auth_time": oidcNow.Unix() - 120, "jti": "synthetic-assertion-id", "nonce": oidcNonce}
}

func (fixture oidcFixture) signRaw(t testing.TB, header, payload []byte) string {
	t.Helper()
	input := encodePart(header) + "." + encodePart(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, fixture.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + encodePart(signature)
}

func (fixture oidcFixture) sign(t testing.TB, header, claims map[string]any) string {
	t.Helper()
	return fixture.signRaw(t, oidcJSON(t, header), oidcJSON(t, claims))
}

func rejectOIDC(t testing.TB, verifier *webauth.OIDCVerifier, token, nonce string, now time.Time) {
	t.Helper()
	identity, err := verifier.VerifyIDToken(token, nonce, now)
	if identity != (webauth.VerifiedIdentity{}) || !errors.Is(err, webauth.ErrOIDC) || err.Error() != "invalid 0g0-id identity assertion" {
		t.Fatalf("want zero identity and fixed error, got identity=%v error=%v", identity != (webauth.VerifiedIdentity{}), err)
	}
}

func TestOIDCVerifiesOnlyFixedClientIdentityAndNoSession(t *testing.T) {
	fixture := newOIDCFixture(t)
	claims := oidcClaims()
	claims["role"], claims["roles"], claims["github_permissions"] = "admin", []string{"admin"}, "write"
	claims["azp"], claims["nbf"] = oidcClient, oidcNow.Unix()
	header := oidcHeader()
	header["typ"] = "JWT"
	identity, err := fixture.verifier.VerifyIDToken(fixture.sign(t, header, claims), oidcNonce, oidcNow)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject() != "pairwise-subject-A" || identity.ClientID() != oidcClient || identity.Issuer() != webauth.OIDCIssuer || !identity.AuthenticatedAt().Equal(oidcNow.Add(-120*time.Second)) || !identity.IssuedAt().Equal(oidcNow.Add(-60*time.Second)) || !identity.ExpiresAt().Equal(oidcNow.Add(3540*time.Second)) {
		t.Fatal("verified identity did not preserve the exact trusted assertion")
	}
	identityType, sessionType := reflect.TypeFor[webauth.VerifiedIdentity](), reflect.TypeFor[webauth.SessionSnapshot]()
	if identityType.AssignableTo(sessionType) || identityType.ConvertibleTo(sessionType) {
		t.Fatal("identity can bypass the unimplemented current-status/session boundary")
	}
	for i := range identityType.NumField() {
		if identityType.Field(i).IsExported() {
			t.Fatal("identity exposes mutable assertion fields")
		}
	}
	// Unknown/stale/mismatched current status has no conversion path at all.
	// This verifier intentionally supplies no current-status or session API.
	var injected webauth.VerifiedIdentity
	if err := json.Unmarshal([]byte(`{"subject":"pairwise-subject-A","role":"admin"}`), &injected); err != nil {
		t.Fatal(err)
	}
	if injected != (webauth.VerifiedIdentity{}) || string(oidcJSON(t, identity)) != "{}" {
		t.Fatal("JSON injected or exposed trusted identity fields")
	}
	policy, err := webauth.NewPolicy(webauth.OIDCIssuer, []webauth.Grant{{Subject: identity.Subject(), Scope: "asset:one", Role: webauth.Admin}})
	if err != nil {
		t.Fatal(err)
	}
	if policy.Allows(webauth.SessionSnapshot{}, "asset:one", webauth.Read, oidcNow) {
		t.Fatal("a verified assertion alone authorized a session")
	}
}

func TestOIDCRejectsClaimConfusionAndInvalidTimes(t *testing.T) {
	fixture := newOIDCFixture(t)
	tests := []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing issuer", func(c map[string]any) { delete(c, "iss") }},
		{"foreign issuer", func(c map[string]any) { c["iss"] = "https://foreign.invalid" }},
		{"issuer normalization", func(c map[string]any) { c["iss"] = webauth.OIDCIssuer + "/" }},
		{"issuer is client", func(c map[string]any) { c["iss"] = oidcClient }},
		{"missing audience", func(c map[string]any) { delete(c, "aud") }},
		{"foreign client", func(c map[string]any) { c["aud"] = "other-rp" }},
		{"issuer is audience", func(c map[string]any) { c["aud"] = webauth.OIDCIssuer }},
		{"single audience array unsupported", func(c map[string]any) { c["aud"] = []string{oidcClient} }},
		{"multi audience unsupported", func(c map[string]any) { c["aud"] = []string{oidcClient, "other-rp"} }},
		{"foreign azp", func(c map[string]any) { c["azp"] = "other-rp" }},
		{"null azp", func(c map[string]any) { c["azp"] = nil }},
		{"missing subject", func(c map[string]any) { delete(c, "sub") }},
		{"nonstring subject", func(c map[string]any) { c["sub"] = 1 }},
		{"padded subject", func(c map[string]any) { c["sub"] = " subject" }},
		{"control subject", func(c map[string]any) { c["sub"] = "subject\x00" }},
		{"oversized subject", func(c map[string]any) { c["sub"] = strings.Repeat("a", 257) }},
		{"missing nonce", func(c map[string]any) { delete(c, "nonce") }},
		{"wrong nonce", func(c map[string]any) { c["nonce"] = "another-login" }},
		{"null nonce", func(c map[string]any) { c["nonce"] = nil }},
		{"oversized nonce", func(c map[string]any) { c["nonce"] = strings.Repeat("a", 513) }},
		{"missing jti", func(c map[string]any) { delete(c, "jti") }},
		{"missing issued time", func(c map[string]any) { delete(c, "iat") }},
		{"missing expiry", func(c map[string]any) { delete(c, "exp") }},
		{"missing authentication", func(c map[string]any) { delete(c, "auth_time") }},
		{"future issued", func(c map[string]any) { c["iat"] = oidcNow.Unix() + 1 }},
		{"future authentication", func(c map[string]any) { c["auth_time"] = oidcNow.Unix() + 1 }},
		{"authentication after issued", func(c map[string]any) { c["auth_time"] = oidcNow.Unix() - 59 }},
		{"expired", func(c map[string]any) { c["exp"] = oidcNow.Unix() - 1 }},
		{"expiry equality", func(c map[string]any) { c["exp"] = oidcNow.Unix() }},
		{"empty lifetime", func(c map[string]any) { c["exp"] = c["iat"] }},
		{"excessive lifetime", func(c map[string]any) { c["exp"] = oidcNow.Unix() + 3541 }},
		{"fractional time", func(c map[string]any) { c["iat"] = 1.25 }},
		{"string time", func(c map[string]any) { c["iat"] = "123" }},
		{"null time", func(c map[string]any) { c["iat"] = nil }},
		{"negative time", func(c map[string]any) { c["iat"] = -1 }},
		{"zero time", func(c map[string]any) { c["iat"] = 0 }},
		{"overflow time", func(c map[string]any) { c["exp"] = json.RawMessage(`9223372036854775808`) }},
		{"out of calendar time", func(c map[string]any) { c["exp"] = int64(253402300800) }},
		{"exponent time unsupported", func(c map[string]any) { c["iat"] = json.RawMessage(`1e9`) }},
		{"future nbf", func(c map[string]any) { c["nbf"] = oidcNow.Unix() + 1 }},
		{"malformed nbf", func(c map[string]any) { c["nbf"] = "now" }},
		{"RP access token", func(c map[string]any) {
			delete(c, "auth_time")
			delete(c, "nonce")
			c["cid"], c["scope"], c["sub"] = oidcClient, "openid", "internal-user-uuid"
		}},
		{"access token cid with added identity claims", func(c map[string]any) { c["cid"] = oidcClient }},
		{"access token scope with added identity claims", func(c map[string]any) { c["scope"] = "openid" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := oidcClaims()
			test.change(claims)
			rejectOIDC(t, fixture.verifier, fixture.sign(t, oidcHeader(), claims), oidcNonce, oidcNow)
		})
	}
}

func TestOIDCRejectsHeadersSignaturesAndMalformedInput(t *testing.T) {
	fixture := newOIDCFixture(t)
	for _, change := range []map[string]any{
		{"alg": "none"}, {"alg": "HS256"}, {"alg": "ES384"}, {"alg": nil}, {"Alg": "ES256"}, {"kid": "unknown"}, {"kid": nil}, {"kid": 1},
		{"typ": "at+jwt"}, {"typ": nil}, {"crit": []string{}}, {"b64": false}, {"jku": "https://foreign.invalid/jwks"}, {"jwk": fixture.jwk}, {"x5u": "https://foreign.invalid/cert"}, {"x5c": []string{}},
	} {
		header := oidcHeader()
		for key, value := range change {
			header[key] = value
		}
		rejectOIDC(t, fixture.verifier, fixture.sign(t, header, oidcClaims()), oidcNonce, oidcNow)
	}
	for _, raw := range []string{
		`{"alg":"ES256","alg":"ES256","kid":"synthetic-key"}`,
		`{"alg":"ES256","\u0061lg":"ES256","kid":"synthetic-key"}`,
		`{"alg":"ES256","kid":"synthetic-key","kid":"unknown"}`,
		`{"alg":"ES256","kid":"synthetic-key"} {}`,
		`[]`, `null`, `{`, strings.Repeat(" ", 1025),
	} {
		rejectOIDC(t, fixture.verifier, fixture.signRaw(t, []byte(raw), oidcJSON(t, oidcClaims())), oidcNonce, oidcNow)
	}
	claimsJSON := oidcJSON(t, oidcClaims())
	for _, raw := range [][]byte{
		append([]byte(`{"sub":"other",`), claimsJSON[1:]...),
		append([]byte(`{"iss":"other",`), claimsJSON[1:]...),
		append([]byte(`{"aud":"other",`), claimsJSON[1:]...),
		append([]byte(`{"nonce":"other",`), claimsJSON[1:]...),
		[]byte(`[]`), []byte(`null`), []byte(`{`), append(append([]byte{}, claimsJSON...), []byte(` {}`)...),
		[]byte(strings.Repeat(" ", 8193)), []byte{'{', '"', 0xff, '"', ':', '1', '}'},
		[]byte(strings.ReplaceAll(string(claimsJSON), "pairwise-subject-A", `\ud800`)),
	} {
		rejectOIDC(t, fixture.verifier, fixture.signRaw(t, oidcJSON(t, oidcHeader()), raw), oidcNonce, oidcNow)
	}
	valid := fixture.sign(t, oidcHeader(), oidcClaims())
	parts := strings.Split(valid, ".")
	for _, raw := range []string{
		"", "a.b", valid + ".extra", strings.Repeat("x", 16385),
		parts[0] + "=." + parts[1] + "." + parts[2],
		parts[0] + "." + parts[1] + "=." + parts[2],
		parts[0] + "." + parts[1] + "." + parts[2] + "=",
		parts[0] + "." + parts[1] + "." + encodePart(make([]byte, 64)),
		parts[0] + "." + parts[1] + "." + encodePart(make([]byte, 63)),
		parts[0] + "." + parts[1] + "." + encodePart(make([]byte, 65)),
		parts[0] + "." + parts[1] + ".MA==", // ASN.1/padded signature is not JOSE R||S.
		parts[0] + "." + parts[1] + "." + parts[2][:10] + "\n" + parts[2][10:],
		parts[0] + "." + parts[1] + "." + parts[2][:85] + "B", // Non-canonical unused bits.
	} {
		rejectOIDC(t, fixture.verifier, raw, oidcNonce, oidcNow)
	}
	otherKey := newOIDCFixture(t)
	rejectOIDC(t, fixture.verifier, otherKey.sign(t, oidcHeader(), oidcClaims()), oidcNonce, oidcNow)
	for _, nonce := range []string{"", "wrong", " padded", "control\x00", strings.Repeat("n", 513)} {
		rejectOIDC(t, fixture.verifier, valid, nonce, oidcNow)
	}
	for _, now := range []time.Time{{}, time.Unix(0, 0), time.Unix(253402300800, 0), oidcNow.Add(-61 * time.Second)} {
		rejectOIDC(t, fixture.verifier, valid, oidcNonce, now)
	}
	for _, verifier := range []*webauth.OIDCVerifier{nil, {}} {
		rejectOIDC(t, verifier, valid, oidcNonce, oidcNow)
	}
}

func TestOIDCTrustedJWKSRejectsAmbiguousAndUnsupportedKeys(t *testing.T) {
	fixture := newOIDCFixture(t)
	for _, change := range []map[string]any{
		{"kty": "RSA"}, {"crv": "P-384"}, {"use": "enc"}, {"alg": "HS256"}, {"kid": ""}, {"kid": nil},
		{"x": ""}, {"x": encodePart(make([]byte, 31))}, {"x": encodePart(make([]byte, 32)), "y": encodePart(make([]byte, 32))}, {"x": fixture.jwk["x"].(string) + "="},
		{"d": "private-key-must-not-be-accepted"}, {"key_ops": []string{"sign"}}, {"key_ops": []string{"verify", "verify"}}, {"key_ops": nil}, {"x5u": "https://foreign.invalid/key"},
	} {
		key := make(map[string]any)
		for name, value := range fixture.jwk {
			key[name] = value
		}
		for name, value := range change {
			key[name] = value
		}
		verifier, err := webauth.NewOIDCVerifier(oidcClient, oidcJSON(t, map[string]any{"keys": []any{key}}))
		if verifier != nil || !errors.Is(err, webauth.ErrOIDC) {
			t.Fatalf("unsupported key %v was accepted", change)
		}
	}
	keyJSON := oidcJSON(t, fixture.jwk)
	duplicateKeyMember := append([]byte(`{"kid":"second",`), keyJSON[1:]...)
	for _, raw := range [][]byte{
		[]byte(`{}`), []byte(`{"keys":null}`), []byte(`{"keys":[]}`), []byte(`{"keys":{}}`), []byte(`[]`), []byte(`null`),
		[]byte(`{"keys":[],"keys":[]}`), []byte(`{"keys":[],"jku":"https://foreign.invalid"}`),
		oidcJSON(t, map[string]any{"keys": []any{fixture.jwk, fixture.jwk}}),
		oidcJSON(t, map[string]any{"keys": []any{json.RawMessage(duplicateKeyMember)}}),
		oidcJSON(t, map[string]any{"keys": make([]any, 17)}),
		append(append([]byte{}, fixture.jwks...), []byte(` {}`)...), []byte(strings.Repeat(" ", 32769)),
	} {
		verifier, err := webauth.NewOIDCVerifier(oidcClient, raw)
		if verifier != nil || !errors.Is(err, webauth.ErrOIDC) {
			t.Fatal("malformed, duplicate or oversized JWKS was accepted")
		}
	}
	for _, client := range []string{"", webauth.OIDCIssuer, " padded", "control\x00", strings.Repeat("c", 257)} {
		if verifier, err := webauth.NewOIDCVerifier(client, fixture.jwks); verifier != nil || !errors.Is(err, webauth.ErrOIDC) {
			t.Fatal("invalid client context was accepted")
		}
	}
}

func TestOIDCVerifierCopiesKeysAndSupportsConcurrentReaders(t *testing.T) {
	fixture := newOIDCFixture(t)
	fixture.jwk["key_ops"] = []string{"verify"}
	rotated := newOIDCFixture(t)
	rotated.jwk["kid"] = "rotated-key"
	raw := oidcJSON(t, map[string]any{"keys": []any{fixture.jwk, rotated.jwk}})
	verifier, err := webauth.NewOIDCVerifier(oidcClient, raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		raw[i] = 0
	}
	header := oidcHeader()
	header["kid"] = "rotated-key"
	tokens := []string{fixture.sign(t, oidcHeader(), oidcClaims()), rotated.sign(t, header, oidcClaims())}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for _, token := range tokens {
				if _, err := verifier.VerifyIDToken(token, oidcNonce, oidcNow); err != nil {
					t.Errorf("copied/rotated key verification failed: %v", err)
				}
			}
		})
	}
	workers.Wait()
	for _, now := range []time.Time{oidcNow.Add(-60 * time.Second), oidcNow.Add(3540*time.Second - time.Nanosecond), oidcNow.In(time.FixedZone("synthetic", 9*3600))} {
		if _, err := verifier.VerifyIDToken(tokens[0], oidcNonce, now); err != nil {
			t.Fatalf("valid boundary instant %v rejected: %v", now, err)
		}
	}
}

func FuzzOIDCUntrustedCompactInputCannotCreateIdentity(f *testing.F) {
	fixture := newOIDCFixture(f)
	for _, token := range []string{"", "a.b.c", "e30.e30.AA", "null", strings.Repeat("x", 16385)} {
		f.Add(token)
	}
	f.Fuzz(func(t *testing.T, token string) {
		identity, err := fixture.verifier.VerifyIDToken(token, oidcNonce, oidcNow)
		if err == nil || identity != (webauth.VerifiedIdentity{}) {
			t.Fatal("untrusted input acquired an identity without the synthetic signing key")
		}
	})
}

func TestOIDCVerifiesIndependentWebCryptoES256Vector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "oidc-es256-webcrypto.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		JWKS  json.RawMessage `json:"jwks"`
		Token string          `json:"token"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	verifier, err := webauth.NewOIDCVerifier(oidcClient, vector.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := verifier.VerifyIDToken(vector.Token, oidcNonce, oidcNow)
	if err != nil || identity.Subject() != "independent-webcrypto-pairwise-subject" {
		t.Fatalf("independent WebCrypto signature was not verified: %v", err)
	}
	parts := strings.Split(vector.Token, ".")
	claims := oidcClaims()
	claims["sub"] = "tampered-identity"
	rejectOIDC(t, verifier, parts[0]+"."+encodePart(oidcJSON(t, claims))+"."+parts[2], oidcNonce, oidcNow)
}
