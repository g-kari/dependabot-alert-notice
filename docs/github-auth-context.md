# GitHub CLI authentication context

The application can select GitHub authentication independently of the account
currently active in an interactive console. This covers Dependabot reads, metadata,
GraphQL, PR lookup and merge, connectivity checks, and manual/periodic release updates.
It does not change GitHub account permissions or the existing approval/repository policy.

## Explicit mode

Use a credential already supplied to the application's process environment. Store
only its environment-variable **name**, not the token value, in the configuration:

```yaml
github_auth:
  mode: token_env
  host: github.com
  token_env: SECURITY_NOTICE_GITHUB_TOKEN
  expected_login: your-existing-login # Optional; user tokens only.
```

The application does not issue, extract, refresh, save or register credentials. It
does not run `gh auth login`, `gh auth switch` or `gh auth token`. This change does
not add a token-entry screen or copy an interactive shell's credential into a service.
The service and interactive app must each already receive the selected environment
variable from their authorized launch environment. Restart after changing it.

Each operation freezes the selected token, executable and child environment. A
missing, empty, ambiguous or malformed selected token is an error; there is no
fallback to another console account. The child receives only a bounded platform/
network environment plus the selected GitHub credential, never Slack or AI tokens.
Shared GH host/debug/config variables are not inherited. A private temporary gh
configuration directory and neutral working directory are removed after the command.
Executable paths are pinned before changing directories. Bare executable names are
resolved only from captured absolute PATH entries; an explicit relative `gh_path`
is resolved against the app's original working directory.

Only the application's existing command shapes are accepted. API endpoints and
repository names are validated, API calls use `--hostname github.com`, and repository
operations use a qualified GitHub.com repository. Foreign hosts, PR URLs, alternate
host/repository flags, credential headers, authentication and extension commands are
rejected before execution. This first version does not support GitHub Enterprise hosts.
GraphQL accepts only the fixed Dependabot update read query with validated owner and
repository names. Arbitrary queries, mutations and additional request bodies are rejected.

When `expected_login` is supplied, the same frozen credential calls GitHub's `/user`
endpoint before each operation. A mismatch or unverifiable login stops the operation.
Cancellation and deadline errors remain detectable by callers during this check.
GitHub App installation tokens cannot generally establish a user login this way:
omit `expected_login` for them; no installation identity is inferred. Connectivity's
account probe also uses `/user` and can report an unverified login for such tokens
even when a repository operation is permitted. Fine-grained token permissions and
SSO authorization remain requirements of the already-provided credential.

Token values are absent from YAML, config/TUI/API responses, arguments, logs and error
messages. External failure output becomes bounded error categories. Success output
has the selected credential redacted before application parsing. `expected_login`
and the variable name are ordinary configuration metadata and can appear in settings.

## Compatibility mode

An absent `github_auth` block or `mode: inherited` preserves legacy CLI authentication
and prints a startup warning. Connectivity labels it **inherited**, not isolated.
Do not add `token_env`, `host` or `expected_login` to inherited mode. Keeping this mode
does **not** remove console-account dependence.

`--check-update` and `--update` now read the selected configuration as well. A missing
default `config.yaml` keeps legacy update compatibility with a warning. An explicitly
specified missing `--config` fails instead of falling back. `--update-gh-path` changes
the executable only; it does not override the selected authentication. Periodic
updates bind the same authentication snapshot for release lookup and download.

Setup/bootstrap shell scripts and release CI keep their existing separate workflows.
Claude/Codex authentication, repository/module names and release asset contracts are
unchanged. Synthetic tests do not contact GitHub, read real credentials or run `gh`.
