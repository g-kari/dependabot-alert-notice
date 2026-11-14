# Offline 0g0-id identity verifier

This is a second, **unwired** code slice for K275. It does not enable Web login
or protect an existing route. The [local role/scope policy](web-auth-contract.md)
is unchanged. Do not expose the console publicly based on this change.

## Narrow reviewed provider profile

`internal/webauth.NewOIDCVerifier(clientID, trustedJWKS)` constructs an immutable,
standard-library-only verifier for the exact issuer `https://id.0g0.xyz` and one
server-configured client ID. The caller must independently obtain and trust the
JWKS snapshot. No discovery, JWKS fetching, HTTP, environment lookup, credentials,
key registration or persistent access is implemented. Rotation replaces the
verifier explicitly; an unknown `kid` fails closed without a refresh request.

The implementation follows the source contract at 0g0-id commit
[`bc92472145904bbb3125b9ee61bb2b68b52f39ae`](https://github.com/g-kari/0g0-id/tree/bc92472145904bbb3125b9ee61bb2b68b52f39ae):

- [Metadata](https://github.com/g-kari/0g0-id/blob/bc92472145904bbb3125b9ee61bb2b68b52f39ae/packages/shared/src/lib/oidc-metadata.ts)
  declares code flow, S256 PKCE, pairwise subjects and ES256.
- [JWT signing](https://github.com/g-kari/0g0-id/blob/bc92472145904bbb3125b9ee61bb2b68b52f39ae/packages/shared/src/lib/jwt.ts)
  emits ID-token `auth_time`, optional `nonce`, single string `aud`, `iat`, `exp`
  (one hour), `jti`, and the ES256/`kid` protected header.
- [Issuance](https://github.com/g-kari/0g0-id/blob/bc92472145904bbb3125b9ee61bb2b68b52f39ae/workers/id/src/utils/token-pair.ts)
  uses a client-specific pairwise subject for ID tokens. RP access tokens instead
  use an internal subject and `cid`/optional `scope`; they are not ID tokens.

These are reviewed source facts, not verification of the deployed IdP or a client
registration. This is not a general-purpose JOSE/OIDC library. The deliberately
narrow profile rejects unsupported formats rather than inferring compatibility.

## Validation contract

`VerifyIDToken(token, expectedNonce, now)` requires a server-owned expected nonce
for the outstanding login transaction and an explicit clock. Nonce generation,
transaction binding, storage, single-use consumption and replay prevention remain
future integration requirements. Supplying a nonce copied from an untrusted token
would not meet this contract, and calling this pure function twice is not replay
protection.

The verifier enforces:

- Compact JWS only, canonical unpadded base64url, ES256 and exact known `kid`;
  P-256 public keys and a 64-byte JOSE `R || S` signature, not ASN.1 DER.
- A trusted JWKS of at most 32 KiB and 16 keys, exact `EC`/`P-256`/`ES256`/`sig`
  metadata and on-curve 32-byte coordinates. Duplicate IDs, private key members,
  unsupported metadata and `key_ops` other than an optional single `verify` deny.
- Only protected `alg`, `kid` and optional `typ: JWT`. All other headers, including
  `crit`, `b64`, remote key/certificate URLs and embedded keys, deny.
- Exact issuer and single **string** audience matching the configured client.
  Audience arrays are unsupported even with one entry. Optional `azp` must equal
  the same client. No issuer/client normalization or fallback is performed.
- Nonempty bounded string subject, `jti` and matching nonce. `cid` or `scope`
  presence denies, so reviewed access tokens cannot substitute for ID tokens.
- Positive integer-second `iat`, `exp`, `auth_time` (and optional `nbf`), bounded
  through year 9999. No fractional/exponent/string/null dates or clock leeway.
  Authentication cannot follow issue time; issue time and `nbf` cannot be future;
  expiry must be after issue time and strictly after now, at most one hour later.
- At most 16 KiB total token, 1 KiB decoded header, 8 KiB decoded payload, bounded
  identifiers; malformed JSON, duplicate top-level names (including escaped
  equivalents), trailing JSON, non-objects and invalid UTF-8 deny. Unused payload
  claims are ignored and never used to grant roles or connector permissions.

Errors are fixed and contain no tokens, subjects, claims or keys. No new external
dependency, module/lockfile change or CI relaxation is required.

The relevant protocol rules are [OIDC Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation),
[RFC 7518 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4), and
[RFC 7515 4.1.11](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11).

## Identity is not a session

Success returns `VerifiedIdentity` with private fields and read-only accessors.
It is neither assignable nor convertible to `SessionSnapshot`. No conversion or
session-creation API exists. Caller-provided JSON cannot populate its fields.
IdP roles and GitHub permissions do not enter it or change the local grant policy.

A valid signature and lifetime do **not** establish current account availability,
ban state, session revocation or logout. Unknown, stale or subject-mismatched
current status must not advance to session issuance or authorization. In this
slice, there is no status lookup or session issuance path at all, even after
successful verification. A future trusted authenticator must establish the real
provider status contract and exact issuer/client/subject/session binding before
constructing `SessionSnapshot`; this document does not invent a status freshness
window or claim that status fetching is implemented.

In particular, the reviewed [introspection code](https://github.com/g-kari/0g0-id/blob/bc92472145904bbb3125b9ee61bb2b68b52f39ae/workers/id/src/routes/token/introspect.ts)
requires client Basic authentication; its JWT branch verifies audience against
the IdP origin rather than the usual RP client ID. The refresh-token branch has
its own ownership, revocation, expiry and ban checks. Neither route is called or
assumed to validate an RP ID token here. Refresh does not automatically supply a
new ID token. Live status/session integration remains a separate unresolved step.

## Synthetic verification and remaining work

Synthetic tests cover successful assertions, strict claim/header/key/time/size
rejection, access-token confusion, signature/key mismatch, duplicate JSON and key
IDs, immutable key snapshots, concurrent readers and fuzz seeds. A fixed public-only
WebCrypto-generated ES256 vector independently checks JOSE signature compatibility;
`internal/webauth/testdata/generate_oidc_vector.mjs` can regenerate that synthetic
fixture without retaining its private key. Tests do not contact the IdP or GitHub.

Go formatting, vet, race tests, build and regressions are checked by the existing
GitHub Check workflow for the exact PR head. No local Go toolchain is used in the
restricted cloud workspace.

Still absent: authorization-code/token exchange, PKCE/state/nonce transaction
management, callback/router/listener wiring, session storage, secure cookies,
CSRF/origin checks, current status/logout, route capability mapping, live IdP
verification, production feature configuration and client registration. Web login
and GitHub/data connector authentication remain independent. K275 remains open.
