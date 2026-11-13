# Hermes Proxy evaluator

DevSecOps Console can send a Dependabot evaluation to Hermes through its local OpenAI-compatible subscription proxy. The app makes HTTP requests itself; it does not invoke Codex, Claude, or the `hermes` executable for each evaluation.

## Setup

1. Confirm a Hermes upstream is ready with `hermes proxy status`.
2. Start the proxy in a separate process: `hermes proxy start`. Its default endpoint is `http://127.0.0.1:8645/v1`.
3. In DevSecOps Console settings, select **Hermes Proxy**, choose an available model (default `Hermes-4-70B`), and keep the local endpoint unless the proxy is configured on another allowed loopback address.
4. Use the connectivity check. It requests `GET /v1/models`; it does not perform inference.

Example configuration:

```yaml
evaluator:
  provider: hermes
  hermes_model: Hermes-4-70B
  hermes_base_url: http://127.0.0.1:8645/v1
```

The proxy accepts any bearer token and attaches the real provider credential itself. The app sends a non-secret placeholder; it does not store an API key. The endpoint is restricted to loopback HTTP on port 8645 to avoid turning the setting into a remote-request/SSRF path.

## Data and execution boundary

- The app sends the alert fields used by `buildPrompt` to the Hermes subscription proxy. That proxy forwards model inference to its configured upstream. Use this provider only if that data flow is acceptable.
- This is the subscription proxy (raw model inference), **not** the Hermes Agent API server. The request includes no tools, and the proxy does not run Hermes skills, memory, or shell commands.
- Hermes evaluations do not invoke a Codex/Claude CLI and do not require an evaluator container. Existing Claude/Codex evaluation paths and their sandbox behavior remain unchanged.
- `auto_eval` remains opt-in. When enabled, matching alerts are sent to the selected upstream on polling; no evaluation was run as part of adding this provider.
- An offline proxy or failed request returns an evaluation error; the app does not silently fall back to another provider.

This uses Go's standard `net/http` client with the OpenAI-compatible Chat Completions route, so there is no additional SDK dependency to install in the app environment. The Hermes proxy itself must be running locally.

Official Hermes documentation: [Subscription Proxy](https://hermes-agent.nousresearch.com/docs/user-guide/features/subscription-proxy).
