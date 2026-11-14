# Web identity and local authorization contract

## First code slice, not a login feature

`internal/webauth` defines a pure local role/scope policy for a future **0g0-id**
Web session. It is not wired into `internal/web.Server`, the CLI, or configuration.
Existing loopback defaults, routes and behavior are unchanged. This package alone
provides no authentication or protection for existing routes. Do not expose the
console on a non-loopback address based on this change.

The provider choice is fixed to 0g0-id. Its actual protocol, trusted issuer,
audience, subject semantics, verification keys and revocation contract still need
verification. No endpoint, JWT claim, discovery document, callback or role claim is
assumed. The issuer in this first contract is an exact opaque trusted identifier,
not a URL the package will fetch.

## Two independent trust boundaries

1. **Web identity:** a future server-side authenticator verifies the 0g0-id
   protocol, issuer, audience, stable subject, session lifetime and current
   revocation. Only then may it construct `SessionSnapshot`. Request headers,
   unverified tokens, client JSON and GitHub account names cannot populate that
   trusted snapshot directly. This package checks structural/session time
   invariants but does not prove authentication.
2. **Data connectors:** GitHub and later data sources independently manage their
   connection choice, credential, access scope, availability and revocation.
   Existing [GitHub credential contexts](github-auth-context.md) remain unchanged.
   A Web login does not create, supply, inherit or refresh a connector credential.
   A missing or revoked connector is not proof that a Web session is invalid.

There is no credential or connector-state field in `SessionSnapshot`, `Grant` or
`Policy`. This slice performs no I/O, reads no environment variables and neither
creates nor revokes credentials. Its synthetic tests do not contact 0g0-id or GitHub.

## Local policy and exact scope

`NewPolicy` receives a trusted issuer and at most 1024 explicit local bindings.
Each binding associates one exact subject with one exact server-owned scope and
one of `viewer`, `analyst` or `admin`. Duplicates are errors, including duplicate
bindings that name the same role. Empty bindings deny all access. The policy
copies bindings and is immutable, so concurrent checks do not observe caller edits.

The scope key is opaque, bounded and case-sensitive. No parent inheritance,
wildcards or default scope exist. A handler must resolve its object into the
server-owned scope rather than trust a scope submitted by a client. A role on one
asset grants nothing on another. Subjects and issuers are never normalized or
matched by email, display name or GitHub login.

| Local capability | Viewer | Analyst | Admin |
| --- | --- | --- | --- |
| Scoped read | Yes | Yes | Yes |
| Local triage / investigation | No | Yes | Yes |
| Prepare remediation proposal / request exception | No | Yes | Yes |
| Manage local connection / operation configuration | No | No | Yes |
| Approve or execute external changes, merge, issue credentials, deploy | No | No | No |

The last row is deliberately not a capability this policy can grant. Unknown
operations deny for every role. A local allow result is necessary but insufficient
for a command: object scope, CSRF, input/revision validation, action-specific
approval and audit remain required. In particular, requesting an exception does
not approve risk acceptance, and proposing remediation does not execute it.

`Allows` uses an explicit clock. Missing time, future authentication, missing or
invalid lifetime, expiry equality, revoked sessions, foreign provider/issuer,
unknown subject/scope and nil/zero policies deny. Roles are looked up on every
call in the current policy, not cached inside the session. A caller must safely
replace its policy snapshot on local role changes and recheck at execution time.

## Verification and remaining integration

Synthetic tests cover the role/operation matrix, exact issuer/subject/scope,
empty/invalid/duplicate/bounded policy input, time boundaries, revocation,
immutable bindings, role removal, concurrent readers and unknown-operation fuzz
seeds. They do not establish the truth of an input identity or exercise a live IdP.

Before enabling Web authentication, implement and verify separately:

- The actual 0g0-id verifier and server-side session store, login/callback/state
  validation, secure cookies, expiry, logout and revocation.
- The complete route-to-capability and object-scope mapping, including legacy
  POST, SSE, TUI controls, settings, approval and manual refresh routes. Never
  treat a generic read grant as permission for every GET endpoint.
- CSRF and origin checks, safe errors and audit, object non-disclosure, repeated
  and interrupted login flows, and explicit request/response bounds.
- Separate connector connection/status/disconnection UI and tests proving that
  connector loss does not invalidate the Web session or elevate Web privileges.
- Production issuer/client configuration, TLS and public exposure as a separately
  authorized deployment step. No live credentials or persistent access are
  provisioned by this code slice.

K275 remains open until the actual authentication and route integration are
implemented and verified. This authorization primitive is not a completed login,
RBAC rollout, connector setup or production acceptance.
