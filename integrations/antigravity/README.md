# Antigravity ELIOT integration

ELIOT launches the installed `agy` CLI only through the Governor-managed,
read-only plan boundary. The worker receives one exact governed worktree,
write-set, model route, timeout, and prompt, then returns a candidate unified
diff for controller review. It does not mutate the worktree directly.

The bundle never contains, copies, reads, or changes provider credentials or
account configuration. Managed launches disable CLI auto-update, hide account
details, journal the attempt before dispatch, contain the process tree in a
Windows Job Object, and compare the worktree plus forbidden global roots before
accepting any candidate output.

An unknown external outcome is non-redispatchable. A retry is permitted only
when `host invocation-status` proves that dispatch never occurred, no provider
budget was consumed, and `redispatch_allowed` is true.

## Slice B terminal-reconciliation freeze (issue #9, base dfa3547e)

Slice B freezes the antigravity route only; it implements no adapter, bridge,
reducer, or admission. The persistent route
`antigravity.exec.persistent-ndjson` (profile
`antigravity.local.supervised-stream`, class `later-local-sidecar`) and the
preflight contract `eliot.antigravity-runtime-preflight.v1` record the exact
runtime, adapter, bridge, Governor, protocol, Session, Attempt, Task, and route
identities named in `route-profile.json` and
`runtime-preflight.contract.json`.

Raw host events are the legacy `HostEventEnvelope` quarantine boundary
(`crates/agent/eliot-agent-api/src/lib.rs:754`, issue #371 T4 S6, untouched).
Normalized host events are the closed `NormalizedHostEventEnvelope` schema
`eliot-agent-api/host-event-v7`
(`crates/agent/eliot-agent-api/src/host_event.rs:51,719`) with nonzero
sequence, `EventCursor`, bounded predecessors, `RawSourceRecord`,
`HostEventNormalizationReceipt` (`proof_ceiling` `Observation`), typed
`ClockReading`, and delivery `DurableOrdered`/`BestEffortOrdered`/`Replay`.
Ordering follows `EventEnvelope`
(`crates/foundation/eliot-protocol/src/lib.rs:646`) with `AckPhase`
`RECEIVED`/`DURABLE`/`NORMALIZED`/`APPLIED` and `EventDisposition`
`accepted`/`duplicate`/`rejected`/`conflict`; per-stream cursors advance only
on phase reach, duplicates are idempotent, conflicts are rejected. Attempt
transitions follow `AttemptState`
(`crates/agent/eliot-agent-api/src/lib.rs:610`) with terminal
`Completed`/`Failed`/`UnknownOutcome`/`Cancelled`/`Quarantined` held immutable.

Terminal reducer inputs — `ProviderTerminalObserved`, `CandidateResultAvailable`,
`Error`/`CancellationObserved`/`Usage`/`Checkpoint`, `SessionLifecycle`,
`AdmittedRouteReceipt` (#369), `ProviderExecutionBinding` (#361),
candidate-only `AgentResult` disposition, and I7.9 finish inputs — are recorded
as independent inputs with coverage `documented_not_observed`. A stale UI/CLI
projection, an earlier `Error` event, and the final canonical disposition keep
distinct sequences/cursors/refs until reduction. The reducer itself is an
explicit MGR02 handoff; the CLI projection in `crates/surfaces/eliot-cli`
(`antigravity_terminal` module) shows Supervisor/API/CLI same-identity and
same-disposition agreement as projection only, with no semantic defaults and no
reduction. If a wire-field change is ever required, it belongs to F-APPP #708
and is out of scope here: this slice edits no type crate and stops with an
exact `file:line` instead.
