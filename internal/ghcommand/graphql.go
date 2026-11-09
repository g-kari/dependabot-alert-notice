package ghcommand

import "strings"

const dependabotUpdatesPrefix = `query {
		repository(owner: "`

const dependabotUpdatesSeparator = `", name: "`

const dependabotUpdatesSuffix = `") {
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

// DependabotUpdatesQuery builds the fixed read-only query used by alert reads.
// Validated repository components cannot contain GraphQL syntax or escapes.
func DependabotUpdatesQuery(owner, repo string) (string, error) {
	if _, err := qualifiedRepo(owner + "/" + repo); err != nil {
		return "", ErrCommand
	}
	return dependabotUpdatesPrefix + owner + dependabotUpdatesSeparator + repo + dependabotUpdatesSuffix, nil
}

func validDependabotUpdatesField(value string) bool {
	components, ok := strings.CutPrefix(value, "query="+dependabotUpdatesPrefix)
	if !ok {
		return false
	}
	components, ok = strings.CutSuffix(components, dependabotUpdatesSuffix)
	if !ok {
		return false
	}
	owner, repo, ok := strings.Cut(components, dependabotUpdatesSeparator)
	if !ok {
		return false
	}
	query, err := DependabotUpdatesQuery(owner, repo)
	return err == nil && value == "query="+query
}
