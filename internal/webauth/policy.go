// Package webauth defines the local authorization boundary for a future 0g0-id
// Web session. It does not authenticate tokens, issue sessions, or connect to an
// identity provider. Callers must supply a session already verified by a trusted
// server-side authenticator and its current revocation state.
package webauth

import (
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Provider is the selected Web identity provider, not a data-source connector.
const Provider = "0g0-id"

// Role is a local, scope-specific role. IdP claims cannot assign this role.
type Role string

const (
	// Viewer may read the exact scope to which it is bound.
	Viewer Role = "viewer"
	// Analyst may also record local investigation and triage decisions.
	Analyst Role = "analyst"
	// Admin may also manage local connection configuration and operations.
	Admin Role = "admin"
)

// Operation names a local capability, not approval for an external action.
type Operation string

const (
	// Read permits scoped read-only access.
	Read Operation = "read"
	// Triage permits local Finding triage, subject to its command validation.
	Triage Operation = "triage"
	// Investigate permits local case management.
	Investigate Operation = "investigate"
	// ProposeRemediation permits preparing a proposal, never executing it.
	ProposeRemediation Operation = "propose_remediation"
	// RequestException permits submitting an exception request, not approval.
	RequestException Operation = "request_exception"
	// ManageConnections permits local connection configuration, not issuing credentials.
	ManageConnections Operation = "manage_connections"
	// ManageOperations permits local operational configuration, not production changes.
	ManageOperations Operation = "manage_operations"
)

// SessionSnapshot is trusted input from a future server-side authenticator.
// It must never be decoded directly from a request, header, cookie, or unverified
// token. The authenticator must verify the provider protocol, issuer, audience,
// subject, session validity and current revocation before constructing it.
// Roles, source credentials and IdP role claims deliberately have no field here.
type SessionSnapshot struct {
	Provider        string
	Issuer          string
	Subject         string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Revoked         bool
}

// Grant binds a local role to an exact subject and scope under the policy issuer.
// Scope is an opaque server-owned resource key, not a URL or a wildcard pattern.
// The caller must resolve the requested object to this scope before authorization.
type Grant struct {
	Subject string
	Scope   string
	Role    Role
}

// Policy is an immutable local role-binding snapshot safe for concurrent readers.
// Replacing it with a newly constructed policy removes old grants immediately;
// sessions do not cache roles. Its zero value denies every request.
type Policy struct {
	issuer string
	grants map[binding]Role
}

type binding struct {
	subject string
	scope   string
}

// ErrPolicy is deliberately fixed and does not expose subjects or configuration.
var ErrPolicy = errors.New("invalid Web authorization policy")

// NewPolicy copies and validates at most 1024 exact local role bindings.
// The issuer is an exact, opaque trusted identifier until the 0g0-id protocol is
// verified; no discovery URL, token format, normalization or network I/O is inferred.
// An empty grants list creates a deny-all policy. Duplicate bindings fail closed.
func NewPolicy(issuer string, grants []Grant) (*Policy, error) {
	if !validIdentifier(issuer, 2048) || len(grants) > 1024 {
		return nil, ErrPolicy
	}
	p := &Policy{issuer: issuer, grants: make(map[binding]Role, len(grants))}
	for _, grant := range grants {
		if !validIdentifier(grant.Subject, 256) || !validScope(grant.Scope) || !validRole(grant.Role) {
			return nil, ErrPolicy
		}
		key := binding{subject: grant.Subject, scope: grant.Scope}
		if _, exists := p.grants[key]; exists {
			return nil, ErrPolicy
		}
		p.grants[key] = grant.Role
	}
	return p, nil
}

// Allows evaluates a verified session against the current local policy and an
// explicit clock. It fails closed on missing, expired, revoked, foreign or
// malformed sessions and unknown operations. It does not authenticate the input.
// The caller must also enforce CSRF, object scope, command invariants, audit and
// any action-specific approval. An allow result cannot authorize a merge, an
// external write, a new credential, or a production change.
func (p *Policy) Allows(session SessionSnapshot, scope string, operation Operation, now time.Time) bool {
	if p == nil || p.issuer == "" || now.IsZero() || !validScope(scope) {
		return false
	}
	if session.Provider != Provider || session.Issuer != p.issuer || !validIdentifier(session.Subject, 256) || session.Revoked {
		return false
	}
	if session.AuthenticatedAt.IsZero() || session.ExpiresAt.IsZero() || !session.AuthenticatedAt.Before(session.ExpiresAt) {
		return false
	}
	if now.Before(session.AuthenticatedAt) || !now.Before(session.ExpiresAt) {
		return false
	}
	role, exists := p.grants[binding{subject: session.Subject, scope: scope}]
	if !exists {
		return false
	}
	switch operation {
	case Read:
		return validRole(role)
	case Triage, Investigate, ProposeRemediation, RequestException:
		return role == Analyst || role == Admin
	case ManageConnections, ManageOperations:
		return role == Admin
	default:
		return false
	}
}

func validRole(role Role) bool {
	return role == Viewer || role == Analyst || role == Admin
}

func validScope(scope string) bool {
	return validIdentifier(scope, 256) && !strings.ContainsAny(scope, "*?")
}

func validIdentifier(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
