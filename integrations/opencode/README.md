# OpenCode ELIOT integration

`ELIOT_GOVERNOR_EXE` must use slash-normalized Windows syntax such as
`C:/path/to/eliot-governor.exe`. OpenCode substitutes environment variables
before parsing JSONC, so raw backslashes would become invalid JSON escapes.

Supervised launches set an ELIOT-owned isolated `XDG_CONFIG_HOME`. OpenCode's
host-managed data/auth root is unchanged, while unrelated user MCP definitions
are excluded from the bounded invocation. Interactive launches keep the normal
merged user configuration.

For an ephemeral bundle smoke, set `ELIOT_GOVERNOR_EXE` to the absolute release
binary and `OPENCODE_CONFIG_DIR` to this directory, then launch the installed
OpenCode CLI. OpenCode merges this additive directory with existing settings;
this bundle does not set a provider, model, agent, or credential.

For ordinary persistent discovery, use
`eliot-governor host install --host opencode`. It installs one local MCP server,
one compact always-on bootstrap instruction, four on-demand portable skills,
and a bounded lifecycle plugin while preserving provider/auth and unrelated
JSONC. Without an attached ELIOT task the plugin is passive. Use
`host uninstall --host opencode` for receipt-backed rollback; merely omitting
`OPENCODE_CONFIG_DIR` only disables an ephemeral bundle smoke.

## Persistent host-event bridge

The plugin prefers one authenticated ELIOT loopback bridge when both variables
are present:

```text
ELIOT_OPENCODE_BRIDGE_URL=http://127.0.0.1:<reserved-port>/
ELIOT_OPENCODE_BRIDGE_TOKEN=<scoped-short-lived-token>
```

The URL must use literal IPv4 or IPv6 loopback, an explicit port, and the server
root. Credentials, query strings, fragments, DNS names, and non-HTTP schemes are
rejected. Events are posted to `/v1/host-events` with
`Idempotency-Key: <event_id>`. One transient retry preserves the same identity.
After any HTTP attempt the plugin never falls through to the legacy process
transport because the first request may already have reached durable admission.

When the HTTP bridge is not configured, the existing bounded one-shot process
bridge remains a compatibility fallback. It receives only an explicit
environment allowlist. Attached mutating tools fail closed without an explicit
usable gate decision; passive observations degrade without blocking OpenCode.
The payload includes identities, event/tool kind, changed path, and argument
names only—never prompts, tool argument values, command text, model output,
file contents, stdout/stderr, environment values, headers, cookies, or secrets.
