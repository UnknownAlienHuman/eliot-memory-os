# `eliot-agent-claude` governed adapter contract

Owning issue: [#1112 — governed Claude Agent SDK sidecar adapter](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/1112).

Current source base: `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`.

The package currently supplies only the Wave-1 bounded NDJSON contract and native skeleton. It explicitly excludes supervised launch, credentials, SDK execution, normalized events, cancellation, cleanup, reconciliation, route admission and Product proof. `CLAUDE_SIDECAR_ADAPTER_ID` has no production composition caller. Issue #874 is the downstream native-worker factory/registry owner; it does not own repairing this package.

## Mandatory documentation

Run `scripts/docs_read.py` for every actual mutable path, then directly read:

- [`I7.1 — Eliot Bridge Protocol`](../../../docs/architecture/I07-01-eliot-bridge-protocol-ebp1.md#i71-eliot-bridge-protocol-ebp1)
- [`I7.20 — Agent-facing error contract`](../../../docs/architecture/I07-20-agent-facing-error-contract.md#i720-agent-facing-error-contract)
- [`I7.23 — Raw and normalized host events`](../../../docs/architecture/I07-23-raw-and-normalized-host-events.md#i723-raw-and-normalized-host-events)
- [`I9.9 — AgentSwarm launch and no-lost-child contract`](../../../docs/architecture/I09-09-agentswarm-launch-and-no-lost-child-contract.md#i99-agentswarm-launch-and-no-lost-child-contract)
- [`I10.11 — External model bridges`](../../../docs/architecture/I10-11-external-model-bridges.md#i1011-external-model-bridges)
- [`I10.15 — Agent execution fabric and durable swarm`](../../../docs/architecture/I10-15-agent-execution-fabric-and-durable-swarm.md#i1015-agent-execution-fabric-and-durable-swarm)
- [`I14.13 — Idle drain and cancellation`](../../../docs/architecture/I14-13-idle-drain-and-cancellation.md#i1413-idle-drain-and-cancellation)
- [`I14.14 — Module hot replacement`](../../../docs/architecture/I14-14-module-hot-replacement.md#i1414-module-hot-replacement)
- [`I15.2 — Principal and Session binding`](../../../docs/architecture/I15-02-principal-and-session-binding.md#i152-principal-and-session-binding)
- [`I15.4 — Secrets`](../../../docs/architecture/I15-04-secrets.md#i154-secrets)
- [`I15.10 — Sandboxing`](../../../docs/architecture/I15-10-sandboxing.md#i1510-sandboxing)

Shared provider prerequisites remain #361 and #368–#371. Native-worker execution admission is #22; adapter registry composition is #874.

## What to implement

Complete a provider-neutral Claude sidecar adapter/factory over the existing bounded NDJSON contracts, executable only through the governed native-worker/ProcessExecutor contour. Preserve candidate-only outputs and exact provider-neutral operation/turn/result/event identities.

## How

- Reuse accepted provider-neutral execution-unit, identity/fence, route receipt, normalized event and candidate-result contracts. Do not create Claude-specific Task, attempt, authority, canonical or Finish owners.
- Construct the adapter only from an authenticated current provider binding and immutable sidecar artifact/config/protocol generation.
- Resolve credentials through exact User Broker/provider credential references. Raw keys, cookies and session secrets are forbidden in argv, NDJSON, inherited environment, logs, state, diagnostics and model context.
- Execute only through shared ProcessExecutor/Job Object ownership. No shell, ambient executable discovery, caller program path or arbitrary environment expansion.
- Treat `ClaudeSidecarLaunchPlan` as a validated inert request projection. Kernel/native-worker admission supplies the actual executable identity, root, resource ceiling and effective capabilities.
- Bind request, streaming event, cancellation and terminal candidate to one logical decision, attempt and operation. Validate frame/version/order/size before allocation or forwarding.
- Preserve stdout, stderr, process lineage and material provider events as immutable evidence or explicit bounded omission handles before normalization.
- Keep accepted, started, streaming, terminal candidate, cancelled, timed out, failed, delivery unknown and reconciliation required distinct.
- After possible provider execution or result delivery, reconcile the same operation. Never launch another sidecar, switch model/route or create another attempt to escape uncertainty.
- Fence the exact attempt and descendant process/resource/credential leases on cancellation, parent loss, provider revocation or generation replacement.

## Acceptance criteria

- A real non-test adapter/factory and production #874 consumer exist.
- A valid authenticated execution unit starts one exact sidecar process generation; invalid/stale/mismatched admission starts none.
- Host input cannot select arbitrary executable, shell, credential, principal/session, task/scope/fence, model/route, authority or effect ceiling.
- Request/event/cancel/result identity is exact across NDJSON, process receipts and provider-neutral records.
- Invalid frame, version, ordering or bounds fail before provider-side semantic work.
- stdout/stderr/exit/resource/descendant outcomes are retained or explicitly omitted through immutable handles.
- Cancel, timeout and crash leave no unaccounted descendant or credential/resource lease.
- Exact replay is idempotent; changed same-identity prompt, route/model, permission, launch contract or result conflicts.
- Unknown provider/result outcome blocks blind retry and alternate-route substitution until exact reconciliation.
- Normalized events retain raw-evidence lineage and cannot manufacture progress or completion.
- Provider output remains candidate-only and cannot write canonical state, issue authority, self-promote or decide Task Finish.
- Package contract, framing, malformed input, process, cancellation, redaction, replay and reconciliation tests pass.

## Verification

```bash
cargo fmt --all -- --check
cargo check --locked -p eliot-agent-claude -p eliot-native-worker-core -p eliot-native-worker --all-targets
cargo test --locked -p eliot-agent-claude -p eliot-native-worker-core -p eliot-native-worker --all-targets
cargo clippy --locked -p eliot-agent-claude -p eliot-native-worker-core -p eliot-native-worker --all-targets -- -D warnings
cargo tree --locked -p eliot-agent-claude --edges normal
git diff --check
```

After package proof, run one approved sidecar attempt plus cancellation, timeout, malformed frame, credential revocation, output-delivery loss and exact reconciliation. This does not close #22, #874 or Product proof #11.
