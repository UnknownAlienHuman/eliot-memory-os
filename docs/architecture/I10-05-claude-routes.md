## I10.5. Claude routes

Claude local Agent SDK and Claude Managed Agents are separate adapters and fingerprints.

### Local Agent SDK sidecar

**Priority:** P1. Official SDK surface is Python/TypeScript, therefore Rust integration uses an immutable supervised sidecar:

```text
versioned NDJSON/JSON-RPC bridge;
no durable DB or task authority;
exact SDK/runtime versions and native session locator;
tools, permissions, events, cancellation and usage receipts;
secrets materialized only inside the sidecar process.
```

Local transcript/session semantics are not treated as server-managed durability. Agent Teams/native subagents remain experiments behind child-policy probes.

### Managed Agents

**Priority:** P1 remote beta, explicit opt-in.

Separate profile records beta contract, API billing, retention/deletion, environment, session lifecycle, vault references and event stream. A local Claude session cannot be silently continued as a Managed Agent session; it becomes a `Rehydrated` attempt.

