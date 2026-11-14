package webauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"
)

// OIDCIssuer pins this adapter to the reviewed 0g0-id issuer. No discovery or
// token-controlled issuer/key URL is fetched by this package.
const OIDCIssuer = "https://id.0g0.xyz"

const (
	maxIDTokenBytes = 16384
	maxJWKSBytes    = 32768
	maxNumericDate  = int64(253402300799)
)

// ErrOIDC is a fixed error that never contains a token, claim or key.
var ErrOIDC = errors.New("invalid 0g0-id identity assertion")

// OIDCVerifier is an immutable, offline verifier for the reviewed 0g0-id ES256
// ID-token profile, not a general JWT implementation. Its zero value denies all.
// Keys must come from a trusted, independently obtained JWKS snapshot.
type OIDCVerifier struct {
	clientID string
	keys     map[string]*ecdsa.PublicKey
}

// VerifiedIdentity is a verified authentication assertion, not an authorized
// session. Only VerifyIDToken can populate its private fields. It deliberately
// has no roles, connector credentials, or claims-derived account/session status.
type VerifiedIdentity struct {
	issuer          string
	clientID        string
	subject         string
	authenticatedAt time.Time
	issuedAt        time.Time
	expiresAt       time.Time
}

// Subject returns the opaque, client-specific pairwise subject.
func (identity VerifiedIdentity) Subject() string { return identity.subject }

// ClientID returns the exact audience verified for this assertion.
func (identity VerifiedIdentity) ClientID() string { return identity.clientID }

// Issuer returns the exact trusted issuer, or an empty string for a zero identity.
func (identity VerifiedIdentity) Issuer() string { return identity.issuer }

// AuthenticatedAt returns the verified authentication time.
func (identity VerifiedIdentity) AuthenticatedAt() time.Time { return identity.authenticatedAt }

// IssuedAt returns the verified assertion issue time.
func (identity VerifiedIdentity) IssuedAt() time.Time { return identity.issuedAt }

// ExpiresAt returns the assertion expiry, not an authorized session lifetime.
func (identity VerifiedIdentity) ExpiresAt() time.Time { return identity.expiresAt }

// NewOIDCVerifier copies at most 16 trusted EC/P-256 signing keys for one fixed
// client. It rejects ambiguous key IDs, private keys and unsupported key metadata.
// Rotating keys requires replacing the verifier; tokens cannot add or fetch keys.
func NewOIDCVerifier(clientID string, trustedJWKS []byte) (*OIDCVerifier, error) {
	if !validIdentifier(clientID, 256) || clientID == OIDCIssuer || len(trustedJWKS) > maxJWKSBytes {
		return nil, ErrOIDC
	}
	object, ok := jsonObject(trustedJWKS)
	if !ok || len(object) != 1 {
		return nil, ErrOIDC
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(object["keys"], &entries); err != nil || len(entries) == 0 || len(entries) > 16 {
		return nil, ErrOIDC
	}
	v := &OIDCVerifier{clientID: clientID, keys: make(map[string]*ecdsa.PublicKey, len(entries))}
	for _, entry := range entries {
		kid, key, valid := signingKey(entry)
		if !valid {
			return nil, ErrOIDC
		}
		if _, exists := v.keys[kid]; exists {
			return nil, ErrOIDC
		}
		v.keys[kid] = key
	}
	return v, nil
}

// VerifyIDToken verifies a compact ID token using a mandatory server-owned
// expected nonce and explicit clock. The nonce must belong to the outstanding
// login transaction; this function does not generate, store or consume it.
// It returns only identity: signature validity does not prove current status.
func (v *OIDCVerifier) VerifyIDToken(token, expectedNonce string, now time.Time) (VerifiedIdentity, error) {
	if v == nil || v.clientID == "" || len(v.keys) == 0 || !validClock(now) || !validIdentifier(expectedNonce, 512) || len(token) > maxIDTokenBytes {
		return VerifiedIdentity{}, ErrOIDC
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return VerifiedIdentity{}, ErrOIDC
	}
	headerBytes, ok := compactPart(parts[0], 1024)
	if !ok {
		return VerifiedIdentity{}, ErrOIDC
	}
	header, ok := jsonObject(headerBytes)
	if !ok || !onlyFields(header, "alg", "kid", "typ") || stringClaim(header, "alg", 16) != "ES256" {
		return VerifiedIdentity{}, ErrOIDC
	}
	if _, present := header["typ"]; present && stringClaim(header, "typ", 16) != "JWT" {
		return VerifiedIdentity{}, ErrOIDC
	}
	key := v.keys[stringClaim(header, "kid", 256)]
	signature, ok := compactPart(parts[2], 64)
	if key == nil || !ok || len(signature) != 64 {
		return VerifiedIdentity{}, ErrOIDC
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		return VerifiedIdentity{}, ErrOIDC
	}
	payloadBytes, ok := compactPart(parts[1], 8192)
	if !ok {
		return VerifiedIdentity{}, ErrOIDC
	}
	claims, ok := jsonObject(payloadBytes)
	if !ok || stringClaim(claims, "iss", 2048) != OIDCIssuer || stringClaim(claims, "aud", 256) != v.clientID {
		return VerifiedIdentity{}, ErrOIDC
	}
	// The reviewed provider emits a single string audience. Multi-audience tokens
	// are deliberately unsupported; an optional azp must identify this same RP.
	if _, present := claims["azp"]; present && stringClaim(claims, "azp", 256) != v.clientID {
		return VerifiedIdentity{}, ErrOIDC
	}
	// Access tokens have a different subject and protocol purpose. Never accept
	// them as ID tokens, including an access token with extra identity claims.
	if _, present := claims["cid"]; present {
		return VerifiedIdentity{}, ErrOIDC
	}
	if _, present := claims["scope"]; present {
		return VerifiedIdentity{}, ErrOIDC
	}
	subject := stringClaim(claims, "sub", 256)
	tokenID := stringClaim(claims, "jti", 256)
	nonce := stringClaim(claims, "nonce", 512)
	iat, issued := numericDate(claims, "iat")
	exp, expires := numericDate(claims, "exp")
	authTime, authenticated := numericDate(claims, "auth_time")
	if subject == "" || tokenID == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(expectedNonce)) != 1 || !issued || !expires || !authenticated {
		return VerifiedIdentity{}, ErrOIDC
	}
	if authTime > iat || iat > now.Unix() || exp <= iat || exp-iat > 3600 || now.Unix() >= exp {
		return VerifiedIdentity{}, ErrOIDC
	}
	if _, present := claims["nbf"]; present {
		nbf, valid := numericDate(claims, "nbf")
		if !valid || nbf > now.Unix() || nbf >= exp {
			return VerifiedIdentity{}, ErrOIDC
		}
	}
	return VerifiedIdentity{
		issuer:          OIDCIssuer,
		clientID:        v.clientID,
		subject:         subject,
		authenticatedAt: time.Unix(authTime, 0).UTC(),
		issuedAt:        time.Unix(iat, 0).UTC(),
		expiresAt:       time.Unix(exp, 0).UTC(),
	}, nil
}

func signingKey(raw []byte) (string, *ecdsa.PublicKey, bool) {
	key, ok := jsonObject(raw)
	if !ok || !onlyFields(key, "kty", "crv", "x", "y", "kid", "use", "alg", "key_ops") || stringClaim(key, "kty", 16) != "EC" || stringClaim(key, "crv", 16) != "P-256" || stringClaim(key, "use", 16) != "sig" || stringClaim(key, "alg", 16) != "ES256" {
		return "", nil, false
	}
	if operations, present := key["key_ops"]; present {
		var ops []string
		if err := json.Unmarshal(operations, &ops); err != nil || len(ops) != 1 || ops[0] != "verify" {
			return "", nil, false
		}
	}
	kid := stringClaim(key, "kid", 256)
	x, xOK := compactPart(stringClaim(key, "x", 64), 32)
	y, yOK := compactPart(stringClaim(key, "y", 64), 32)
	if kid == "" || !xOK || !yOK || len(x) != 32 || len(y) != 32 {
		return "", nil, false
	}
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		return "", nil, false
	}
	return kid, public, true
}

func compactPart(value string, limit int) ([]byte, bool) {
	if value == "" || len(value) > (limit*8+5)/6 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return decoded, err == nil && len(decoded) <= limit && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// jsonObject rejects duplicate top-level names, trailing data and non-objects.
// Only exact, case-sensitive names are used by claim/header/key accessors.
func jsonObject(raw []byte) (map[string]json.RawMessage, bool) {
	if !utf8.Valid(raw) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	object := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		name, valid := token.(string)
		if err != nil || !valid {
			return nil, false
		}
		if _, exists := object[name]; exists {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		object[name] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return object, true
}

func onlyFields(object map[string]json.RawMessage, allowed ...string) bool {
	for field := range object {
		found := false
		for _, name := range allowed {
			if field == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func stringClaim(object map[string]json.RawMessage, name string, limit int) string {
	var value string
	if err := json.Unmarshal(object[name], &value); err != nil || !validIdentifier(value, limit) || strings.ContainsRune(value, utf8.RuneError) {
		return ""
	}
	return value
}

func numericDate(object map[string]json.RawMessage, name string) (int64, bool) {
	var value int64
	err := json.Unmarshal(object[name], &value)
	return value, err == nil && value > 0 && value <= maxNumericDate
}

func validClock(now time.Time) bool {
	return !now.IsZero() && now.Unix() > 0 && now.Unix() <= maxNumericDate
}
