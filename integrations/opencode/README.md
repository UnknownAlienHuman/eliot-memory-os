# OpenCode ELIOT integration

`ELIOT_AGENT_BRIDGE_EXE` and `ELIOT_AGENT_BRIDGE_DECLARATION` must use
slash-normalized Windows syntax such as `C:/path/to/eliot-agent-bridge.exe`
and `C:/path/to/agent-bridge/client-declaration-v2.json`. OpenCode substitutes
environment variables before parsing JSONC, so raw backslashes would become
invalid JSON escapes.

Supervised launches set an ELIOT-owned isolated `XDG_CONFIG_HOME`. OpenCode's
host-managed data/auth root is unchanged, while unrelated user MCP definitions
are excluded from the bounded invocation. Interactive launches keep the normal
merged user configuration.

For an ephemeral bundle smoke, set `ELIOT_AGENT_BRIDGE_EXE` to the absolute
release bridge binary and `ELIOT_AGENT_BRIDGE_DECLARATION` to the
installation-owned `agent-bridge/client-declaration-v2.json` shipped beside
it, and `OPENCODE_CONFIG_DIR` to this directory, then launch the installed
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

The plugin prefers one authenticated ELIOT loopback bridge when all three
variables are present:

```text
ELIOT_OPENCODE_BRIDGE_URL=http://127.0.0.1:<reserved-port>/
ELIOT_OPENCODE_BRIDGE_TOKEN=<scoped-short-lived-token>
ELIOT_OPENCODE_BRIDGE_SERVER_IDENTITY=<installation-pinned-server-identity>
```

The URL must use literal IPv4 or IPv6 loopback, an explicit port, and the server
root. Credentials, query strings, fragments, DNS names, and non-HTTP schemes are
rejected. The server identity is the introduction's own pinned identity,
materialized only into the exact approved OpenCode process; a configuration
without it is not an admitted installation path and the plugin refuses instead
of disclosing the token.

### First contact

Plain loopback location is not server identity, so the token is never the first
protected byte on the connection. Each protected request is preceded by one
identity probe: `POST /v1/host-events` carrying `X-ELIOT-Bridge-Challenge` (32
client-minted random bytes, lowercase hex), an empty body, and no
`Authorization` or `Idempotency-Key` header. The bridge answers with the
versioned `eliot.opencode.bridge-identity.v1` record — challenge, installation,
pinned endpoint, server identity, introduction digest, bridge generation and an
`identity_proof` that is HMAC-SHA256 over exactly those fields keyed by the
pinned server identity. The plugin recomputes the proof, and only then sends the
request credential. A process that merely bound the reserved port receives a
challenge and no secret, cannot answer the probe, and never sees the token; the
fresh per-contact challenge also means a recorded probe/answer pair authenticates
no later contact. The same endpoint and the same exclusively pre-bound loopback
listener serve both the probe and the request; no second port is opened.

Events are posted to `/v1/host-events` with
`Idempotency-Key: <event_id>`. One transient retry preserves the same identity.
After any HTTP attempt the plugin never falls through to the legacy process
transport because the first request may already have reached durable admission.

### Serving side

The route is served by the real bridge process, not a Node fake: the
`host-events` front door of `eliot-agent-bridge` attaches through the ordinary
managed attach path, reads the User Broker's own minted introduction from the
launch projection the physical owner materialized into that exact process
(`ELIOT_OPENCODE_BRIDGE_INTRODUCTION`, carrying the versioned introduction and
the broker-observed session facts it was minted under), resolves the
introduction's own opaque credential handle through the owner's live
`OpenCodeRouteCredentials` boundary, binds the reserved loopback port
exclusively, and serves for the life of the process. The introduction is not
ambient configuration: it is revalidated (version, shape, issue/expiry window,
digest binding, and the introduction/facts join) before it is installed, and
every admitted event and every committed decision re-proves its Authority
Epoch, `StateFence` nonce and bridge generation against that process's live
attach binding, which no environment entry can forge. A composition with no
current projection binds no port and refuses closed.

When the HTTP bridge is not configured, the existing bounded one-shot process
bridge remains a compatibility fallback. The spawned process inherits only
allowlisted environment variables (names and values, enumerated as
`BRIDGE_ENV_KEYS` in `plugins/eliot.js`); the event payload below carries
none. Attached mutating tools fail closed without an explicit usable gate
decision; passive observations degrade without blocking OpenCode.
The payload includes identities, event/tool kind, changed path, argument names,
and versioned effect digests only—never prompts, tool argument values, command
text, model output, file contents, stdout/stderr, environment values, headers,
cookies, or secrets. Exact read-only tools return a deterministic skipped
receipt and send the corresponding observation through the same host-event
bridge; aliases and unknown tools fail closed.
