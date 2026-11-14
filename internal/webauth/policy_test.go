package webauth_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/webauth"
)

var fixedNow = time.Date(2026, time.November, 13, 12, 0, 0, 0, time.UTC)

func verifiedSession() webauth.SessionSnapshot {
	return webauth.SessionSnapshot{
		Provider:        webauth.Provider,
		Issuer:          "synthetic-0g0-id-issuer",
		Subject:         "subject-A",
		AuthenticatedAt: fixedNow.Add(-time.Hour),
		ExpiresAt:       fixedNow.Add(time.Hour),
	}
}

func policyFor(t *testing.T, grants ...webauth.Grant) *webauth.Policy {
	t.Helper()
	p, err := webauth.NewPolicy(verifiedSession().Issuer, grants)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoleOperationMatrix(t *testing.T) {
	roles := []webauth.Role{webauth.Viewer, webauth.Analyst, webauth.Admin}
	operations := []struct {
		operation webauth.Operation
		allowed   [3]bool
	}{
		{webauth.Read, [3]bool{true, true, true}},
		{webauth.Triage, [3]bool{false, true, true}},
		{webauth.Investigate, [3]bool{false, true, true}},
		{webauth.ProposeRemediation, [3]bool{false, true, true}},
		{webauth.RequestException, [3]bool{false, true, true}},
		{webauth.ManageConnections, [3]bool{false, false, true}},
		{webauth.ManageOperations, [3]bool{false, false, true}},
		{"", [3]bool{}},
		{"merge", [3]bool{}},
		{"approve", [3]bool{}},
		{"external_write", [3]bool{}},
		{"issue_credential", [3]bool{}},
		{"deploy", [3]bool{}},
		{"READ", [3]bool{}},
	}
	for i, role := range roles {
		for _, row := range operations {
			t.Run(string(role)+"/"+string(row.operation), func(t *testing.T) {
				p := policyFor(t, webauth.Grant{Subject: "subject-A", Scope: "asset:one", Role: role})
				if got := p.Allows(verifiedSession(), "asset:one", row.operation, fixedNow); got != row.allowed[i] {
					t.Fatalf("role %q operation %q: got %v, want %v", role, row.operation, got, row.allowed[i])
				}
			})
		}
	}
}

func TestSessionAndClockValidationFailsClosed(t *testing.T) {
	p := policyFor(t, webauth.Grant{Subject: "subject-A", Scope: "asset:one", Role: webauth.Admin})
	tests := []struct {
		name   string
		change func(*webauth.SessionSnapshot)
	}{
		{"empty", func(s *webauth.SessionSnapshot) { *s = webauth.SessionSnapshot{} }},
		{"missing provider", func(s *webauth.SessionSnapshot) { s.Provider = "" }},
		{"GitHub is not Web identity", func(s *webauth.SessionSnapshot) { s.Provider = "github" }},
		{"case-sensitive provider", func(s *webauth.SessionSnapshot) { s.Provider = "0G0-ID" }},
		{"missing issuer", func(s *webauth.SessionSnapshot) { s.Issuer = "" }},
		{"foreign issuer", func(s *webauth.SessionSnapshot) { s.Issuer += "/" }},
		{"case-sensitive issuer", func(s *webauth.SessionSnapshot) { s.Issuer = strings.ToUpper(s.Issuer) }},
		{"missing subject", func(s *webauth.SessionSnapshot) { s.Subject = "" }},
		{"foreign subject", func(s *webauth.SessionSnapshot) { s.Subject = "subject-B" }},
		{"case-sensitive subject", func(s *webauth.SessionSnapshot) { s.Subject = "subject-a" }},
		{"padded subject", func(s *webauth.SessionSnapshot) { s.Subject += " " }},
		{"control subject", func(s *webauth.SessionSnapshot) { s.Subject += "\n" }},
		{"invalid UTF8 subject", func(s *webauth.SessionSnapshot) { s.Subject = string([]byte{0xff}) }},
		{"oversized subject", func(s *webauth.SessionSnapshot) { s.Subject = strings.Repeat("a", 257) }},
		{"revoked", func(s *webauth.SessionSnapshot) { s.Revoked = true }},
		{"missing authentication time", func(s *webauth.SessionSnapshot) { s.AuthenticatedAt = time.Time{} }},
		{"missing expiry", func(s *webauth.SessionSnapshot) { s.ExpiresAt = time.Time{} }},
		{"future authentication", func(s *webauth.SessionSnapshot) { s.AuthenticatedAt = fixedNow.Add(time.Nanosecond) }},
		{"expired", func(s *webauth.SessionSnapshot) { s.ExpiresAt = fixedNow.Add(-time.Nanosecond) }},
		{"expiry equality", func(s *webauth.SessionSnapshot) { s.ExpiresAt = fixedNow }},
		{"empty lifetime", func(s *webauth.SessionSnapshot) { s.ExpiresAt = s.AuthenticatedAt }},
		{"negative lifetime", func(s *webauth.SessionSnapshot) { s.ExpiresAt = s.AuthenticatedAt.Add(-time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := verifiedSession()
			test.change(&s)
			if p.Allows(s, "asset:one", webauth.Read, fixedNow) {
				t.Fatal("invalid session was allowed")
			}
		})
	}
	if p.Allows(verifiedSession(), "asset:one", webauth.Read, time.Time{}) {
		t.Fatal("missing explicit clock was allowed")
	}
	s := verifiedSession()
	if !p.Allows(s, "asset:one", webauth.Read, s.AuthenticatedAt) {
		t.Fatal("authentication time equality must be valid")
	}
	if !p.Allows(s, "asset:one", webauth.Read, s.ExpiresAt.Add(-time.Nanosecond)) {
		t.Fatal("instant before expiry must be valid")
	}
	if !p.Allows(s, "asset:one", webauth.Read, fixedNow.In(time.FixedZone("synthetic", 9*3600))) {
		t.Fatal("equal instant in a different timezone must be valid")
	}
}

func TestExactScopeAndNoImplicitGrant(t *testing.T) {
	p := policyFor(t,
		webauth.Grant{Subject: "subject-A", Scope: "asset:one", Role: webauth.Admin},
		webauth.Grant{Subject: "subject-A", Scope: "asset:two", Role: webauth.Viewer},
		webauth.Grant{Subject: "subject-B", Scope: "asset:three", Role: webauth.Admin},
	)
	for _, scope := range []string{"", "asset:One", "asset:one/child", "asset:", "asset:*", "asset:?", " asset:one", "asset:three", "console"} {
		if p.Allows(verifiedSession(), scope, webauth.Read, fixedNow) {
			t.Fatalf("scope %q received an implicit grant", scope)
		}
	}
	if !p.Allows(verifiedSession(), "asset:two", webauth.Read, fixedNow) || p.Allows(verifiedSession(), "asset:two", webauth.Triage, fixedNow) {
		t.Fatal("Admin role in another scope changed the Viewer grant")
	}
	policies := []*webauth.Policy{nil, {}, policyFor(t)}
	for i, empty := range policies {
		if empty.Allows(verifiedSession(), "asset:one", webauth.Read, fixedNow) {
			t.Fatalf("empty policy %d allowed a request", i)
		}
	}
}

func TestPolicyValidationIsBoundedAndSecretFree(t *testing.T) {
	valid := webauth.Grant{Subject: "subject-A", Scope: "asset:one", Role: webauth.Viewer}
	tests := []struct {
		name   string
		issuer string
		grants []webauth.Grant
	}{
		{"empty issuer", "", nil},
		{"padded issuer", " issuer", nil},
		{"control issuer", "issuer\x00", nil},
		{"invalid UTF8 issuer", string([]byte{0xff}), nil},
		{"oversized issuer", strings.Repeat("i", 2049), nil},
		{"empty subject", "issuer", []webauth.Grant{{Scope: "asset", Role: webauth.Viewer}}},
		{"empty scope", "issuer", []webauth.Grant{{Subject: "subject", Role: webauth.Viewer}}},
		{"wildcard scope", "issuer", []webauth.Grant{{Subject: "subject", Scope: "*", Role: webauth.Viewer}}},
		{"glob scope", "issuer", []webauth.Grant{{Subject: "subject", Scope: "asset:?", Role: webauth.Viewer}}},
		{"oversized scope", "issuer", []webauth.Grant{{Subject: "subject", Scope: strings.Repeat("s", 257), Role: webauth.Viewer}}},
		{"unknown role", "issuer", []webauth.Grant{{Subject: "subject", Scope: "asset", Role: "owner"}}},
		{"case-sensitive role", "issuer", []webauth.Grant{{Subject: "subject", Scope: "asset", Role: "Admin"}}},
		{"duplicate binding", "issuer", []webauth.Grant{valid, valid}},
		{"conflicting binding", "issuer", []webauth.Grant{valid, {Subject: valid.Subject, Scope: valid.Scope, Role: webauth.Admin}}},
		{"too many grants", "issuer", make([]webauth.Grant, 1025)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := webauth.NewPolicy(test.issuer, test.grants)
			if p != nil || !errors.Is(err, webauth.ErrPolicy) || err.Error() != "invalid Web authorization policy" {
				t.Fatalf("expected nil policy and fixed error, got policy=%v error=%v", p != nil, err)
			}
		})
	}
}

func TestPolicyCopiesBindingsAndRechecksCurrentRoles(t *testing.T) {
	grants := []webauth.Grant{{Subject: "subject-A", Scope: "asset:one", Role: webauth.Viewer}}
	p := policyFor(t, grants...)
	grants[0].Role = webauth.Admin
	grants[0].Scope = "asset:other"
	if !p.Allows(verifiedSession(), "asset:one", webauth.Read, fixedNow) || p.Allows(verifiedSession(), "asset:one", webauth.Triage, fixedNow) || p.Allows(verifiedSession(), "asset:other", webauth.Read, fixedNow) {
		t.Fatal("changing caller-owned grants changed the immutable policy")
	}
	s := verifiedSession()
	promoted := policyFor(t, webauth.Grant{Subject: s.Subject, Scope: "asset:one", Role: webauth.Analyst})
	if !promoted.Allows(s, "asset:one", webauth.Triage, fixedNow) {
		t.Fatal("current local binding was not applied")
	}
	removed := policyFor(t)
	if removed.Allows(s, "asset:one", webauth.Read, fixedNow) {
		t.Fatal("session retained removed local privileges")
	}
}

func TestConcurrentEvaluationDoesNotMutateInputs(t *testing.T) {
	p := policyFor(t, webauth.Grant{Subject: "subject-A", Scope: "asset:one", Role: webauth.Viewer})
	s := verifiedSession()
	before := s
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 100 {
				if !p.Allows(s, "asset:one", webauth.Read, fixedNow) || p.Allows(s, "asset:one", webauth.Triage, fixedNow) {
					t.Error("concurrent evaluation changed the result")
					return
				}
			}
		})
	}
	workers.Wait()
	if s != before {
		t.Fatal("authorization mutated the session")
	}
}

func FuzzUnknownOperationCannotAcquirePrivileges(f *testing.F) {
	for _, operation := range []string{"", "merge", "READ", "read\x00", "issue_credential"} {
		f.Add(operation)
	}
	p, err := webauth.NewPolicy(verifiedSession().Issuer, []webauth.Grant{{Subject: "subject-A", Scope: "asset:one", Role: webauth.Admin}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, value string) {
		operation := webauth.Operation(value)
		switch operation {
		case webauth.Read, webauth.Triage, webauth.Investigate, webauth.ProposeRemediation, webauth.RequestException, webauth.ManageConnections, webauth.ManageOperations:
			return
		}
		if p.Allows(verifiedSession(), "asset:one", operation, fixedNow) {
			t.Fatalf("unknown operation %q acquired a privilege", operation)
		}
	})
}
