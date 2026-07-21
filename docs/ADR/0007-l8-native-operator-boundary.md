# ADR 0007: Thin Windows-native operator over the Governor semantic API

## Status

Accepted for Phase L8.

## Decision

Rejected:

- a second visual control plane or state owner;
- a browser dashboard, WebView, localhost UI, or HTTP sidecar;
- a UI-owned workflow or policy engine;
- direct SurrealDB administration or database credentials in the client;
- an independent authoritative client cache.

Allowed and required:

- one thin Windows-native WinUI 3 client;
- the existing `ActiveRuntimeManifest`/runtime-publication discovery contract;
- the existing authenticated, generation-bound Windows named pipe;
- Governor-produced typed projections and typed operator commands;
- reconnect after runtime/auth rotation and explicit rejection of stale auth;
- canonical mutation receipts from the existing WriterActor boundary.

The native client renders `OperatorSnapshot` and submits `OperatorCommand`. Route,
memory, approval, autonomy, verification, and completion rules remain in Rust. The
client never displays hidden chain-of-thought.

## Causal reason

Inspectability and operator control are useful only if they observe and command the
same authority that agents use. Moving durable state or business rules into the UI
would create two competing truths and invalidate restart, receipt, and verifier
semantics.

## Donor-system conclusion

Letta ADE, LangGraph Studio/persistence, Mem0, Codex Windows, and agent-framework
debug UIs demonstrate useful inspection, persistence, and orchestration patterns.
They do not prove ELIOT's stronger behavioral claims. Those still require controlled
evidence that current truth is separated from recalled memory, negative memory
changes a later choice safely, completion is verifier-backed, and cross-session
experience produces a measurable decision delta.
