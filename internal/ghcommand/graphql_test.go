package ghcommand

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const fixtureDependabotUpdatesQuery = `query {
		repository(owner: "org", name: "repo") {
			vulnerabilityAlerts(first: 100, states: OPEN) {
				nodes {
					number
					dependabotUpdate {
						error { errorType title body }
						pullRequest { number }
					}
				}
			}
		}
	}`

func TestDependabotUpdatesQueryUsesFixedReadGrammar(t *testing.T) {
	query, err := DependabotUpdatesQuery("org", "repo")
	if err != nil || query != fixtureDependabotUpdatesQuery {
		t.Fatalf("query=%q err=%v; want the existing Dependabot read query", query, err)
	}
	for _, tc := range []struct{ owner, repo string }{
		{"a-9", "_repo.test-1"},
		{strings.Repeat("a", 39), strings.Repeat("b", 100)},
	} {
		query, err := DependabotUpdatesQuery(tc.owner, tc.repo)
		if err != nil || !validDependabotUpdatesField("query="+query) {
			t.Fatalf("owner=%q repo=%q: query=%q err=%v", tc.owner, tc.repo, query, err)
		}
	}
	for _, tc := range []struct{ owner, repo string }{
		{"", "repo"}, {"org", ""}, {"org/extra", "repo"}, {"org", "other/repo"},
		{"org", "."}, {"org", ".."}, {"org", "repo\n"}, {"org\n", "repo"},
		{`org") { name } } mutation { fixture } #`, "repo"},
		{"org", `repo") { name } } mutation { fixture } #`},
		{"org", `escaped\"repo`}, {"org", "日本語"},
		{strings.Repeat("a", 40), "repo"}, {"org", strings.Repeat("b", 101)},
	} {
		query, err := DependabotUpdatesQuery(tc.owner, tc.repo)
		if !errors.Is(err, ErrCommand) || query != "" {
			t.Fatalf("owner=%q repo=%q: query=%q err=%v; want empty query and bounded rejection", tc.owner, tc.repo, query, err)
		}
	}
}

func TestExplicitContextRejectsArbitraryGraphQLBeforeAnyExecution(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"mutation", []string{"api", "graphql", "-f", "query=mutation { deleteRepository(input: {repositoryId: \"fixture\"}) { clientMutationId } }"}},
		{"arbitrary read", []string{"api", "graphql", "-f", "query=query { viewer { login } }"}},
		{"appended mutation", []string{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery + "\nmutation { fixture }"}},
		{"changed selection", []string{"api", "graphql", "-f", "query=" + strings.Replace(fixtureDependabotUpdatesQuery, "pullRequest { number }", "pullRequest { id }", 1)}},
		{"owner injection", []string{"api", "graphql", "-f", "query=" + strings.Replace(fixtureDependabotUpdatesQuery, `owner: "org"`, `owner: "org") { name } } mutation { fixture } #`, 1)}},
		{"repo injection", []string{"api", "graphql", "-f", "query=" + strings.Replace(fixtureDependabotUpdatesQuery, `name: "repo"`, `name: "repo") { name } } mutation { fixture } #`, 1)}},
		{"invalid owner", []string{"api", "graphql", "-f", "query=" + strings.Replace(fixtureDependabotUpdatesQuery, `owner: "org"`, `owner: "other.invalid/org"`, 1)}},
		{"invalid repo", []string{"api", "graphql", "-f", "query=" + strings.Replace(fixtureDependabotUpdatesQuery, `name: "repo"`, `name: ".."`, 1)}},
		{"missing query", []string{"api", "graphql"}},
		{"alternate endpoint", []string{"api", "/graphql", "-f", "query=" + fixtureDependabotUpdatesQuery}},
		{"endpoint query string", []string{"api", "graphql?state=open", "-f", "query=" + fixtureDependabotUpdatesQuery}},
		{"query string body", []string{"api", "graphql?query=mutation"}},
		{"duplicate query", []string{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery, "-f", "query=mutation { fixture }"}},
		{"extra body", []string{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery, "-f", "variables={}"}},
		{"input body", []string{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery, "--input", "/fixture/body"}},
		{"pagination override", []string{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery, "--paginate"}},
		{"response override", []string{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery, "--jq", "length"}},
		{"field body", []string{"api", "graphql", "-F", "query=" + fixtureDependabotUpdatesQuery}},
		{"foreign host", []string{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery, "--hostname", "other.invalid"}},
		{"foreign URL", []string{"api", "https://other.invalid/graphql", "-f", "query=" + fixtureDependabotUpdatesQuery}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN", ExpectedLogin: "alice"}, []string{"APP_TOKEN=synthetic-token"})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			c.execute = func(context.Context, string, []string, []string) ([]byte, []byte, error) {
				calls++
				return []byte("alice"), nil, nil
			}
			out, err := c.Output(context.Background(), tc.args...)
			if !errors.Is(err, ErrCommand) || len(out) != 0 || calls != 0 {
				t.Fatalf("args=%q: err=%v, output=%q, executions=%d; want bounded rejection before identity/operation", tc.args, err, out, calls)
			}
		})
	}
}

func TestExplicitContextPreservesAllSeventeenApplicationCommandSites(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"contributors", []string{"api", "repos/org/repo/contributors?per_page=100"}},
		{"rate limit", []string{"api", "rate_limit", "--jq", "[.rate.remaining, .rate.reset] | @tsv"}},
		{"homepage", []string{"repo", "view", "org/repo", "--json", "homepageUrl", "--jq", ".homepageUrl"}},
		{"default branch", []string{"repo", "view", "org/repo", "--json", "defaultBranchRef", "--jq", ".defaultBranchRef.name"}},
		{"archive state", []string{"repo", "view", "org/repo", "--json", "isArchived", "--jq", ".isArchived"}},
		{"org alerts", []string{"api", "/orgs/org/dependabot/alerts?state=open&per_page=100&severity=critical,high", "--paginate"}},
		{"repository metadata", []string{"repo", "list", "org", "--json", "name,isArchived,pushedAt,defaultBranchRef,homepageUrl", "--limit", "1000"}},
		{"repo alerts", []string{"api", "/repos/org/repo/dependabot/alerts?state=open&per_page=100", "--paginate"}},
		{"dependabot updates", []string{"api", "graphql", "-f", "query=" + fixtureDependabotUpdatesQuery}},
		{"dependabot PR lookup", []string{"pr", "list", "--repo", "org/repo", "--author", "app/dependabot", "--state", "open", "--json", "number,title", "--limit", "100"}},
		{"merge", []string{"pr", "merge", "7", "--repo", "org/repo", "--squash", "--delete-branch", "--auto"}},
		{"connectivity repo", []string{"api", "/repos/org/repo/dependabot/alerts?state=open", "--jq", "length"}},
		{"connectivity org", []string{"api", "/orgs/org/dependabot/alerts?state=open", "--jq", "length"}},
		{"connectivity repo list", []string{"repo", "list", "org", "--json", "name", "--jq", ".[].name", "--limit", "1000"}},
		{"connectivity fallback repo", []string{"api", "/repos/org/other/dependabot/alerts?state=open", "--jq", "length"}},
		{"release lookup", []string{"api", "repos/org/repo/releases/latest"}},
		{"release download", []string{"release", "download", "v1", "--repo", "org/repo", "--pattern", "a.tar.gz", "--pattern", "checksums.txt", "--dir", "relative path"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewWithEnvironment(fixtureExecutable(), Settings{Mode: "token_env", TokenEnv: "APP_TOKEN", ExpectedLogin: "alice"}, []string{"APP_TOKEN=synthetic-token"})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			c.execute = func(_ context.Context, _ string, args, env []string) ([]byte, []byte, error) {
				calls++
				if !contains(env, "GH_TOKEN=synthetic-token") {
					t.Fatal("lost selected authentication")
				}
				if calls == 1 {
					if !reflect.DeepEqual(args, []string{"api", "user", "--hostname", "github.com", "--jq", ".login"}) {
						t.Fatalf("missing identity preflight: %q", args)
					}
					return []byte("alice"), nil, nil
				}
				if args[0] == "api" && !reflect.DeepEqual(args[len(args)-2:], []string{"--hostname", "github.com"}) {
					t.Fatalf("API host not pinned: %q", args)
				}
				return []byte("ok"), nil, nil
			}
			out, err := c.Output(context.Background(), tc.args...)
			if err != nil || string(out) != "ok" || calls != 2 {
				t.Fatalf("args=%q: err=%v output=%q executions=%d; want identity and operation", tc.args, err, out, calls)
			}
		})
	}
}
