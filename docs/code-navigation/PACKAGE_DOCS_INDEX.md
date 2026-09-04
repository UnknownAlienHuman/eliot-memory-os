<!-- generated: eliot-package-doc-index-v1 -->
# Workspace package ↔ documentation index

This committed file is a deterministic navigation projection, not architectural
or source authority. Its denominator comes only from the root
[`Cargo.toml`](../../Cargo.toml). Package-to-document mappings come from
[`logical-blocks.toml`](logical-blocks.toml), the canonical
[`HANDLE_INDEX.md`](../architecture/HANDLE_INDEX.md), and inherited
`AGENTS.md` contracts. Do not edit it by hand.

```powershell
python scripts/code_navigation.py sync-index --root .
python scripts/code_navigation.py check --root .
```

## Coverage

- Workspace members: **128**.
- Default members: **6**.
- Logical responsibility blocks: **15**.
- Inherited package-family contracts: **3**.

## Package-family contracts

| Package path | Inherited contract |
|---|---|
| `crates/**` | [`crates/AGENTS.md`](../../crates/AGENTS.md) |
| `bins/**` | [`bins/AGENTS.md`](../../bins/AGENTS.md) |
| `workspace/tools/**` | [`workspace/tools/AGENTS.md`](../../workspace/tools/AGENTS.md) |

## Logical responsibility blocks

| Block | Governing handles |
|---|---|
| `foundation-contracts` | [`A2.3`](../architecture/HANDLE_INDEX.md)<br>[`I2.8`](../architecture/HANDLE_INDEX.md) |
| `governor-semantic-control` | [`I5.19`](../architecture/HANDLE_INDEX.md) |
| `host-kernel-runtime` | [`I1.8`](../architecture/HANDLE_INDEX.md) |
| `canonical-storage` | [`I5.19`](../architecture/HANDLE_INDEX.md) |
| `agent-fabric` | [`I10.15`](../architecture/HANDLE_INDEX.md) |
| `instrument-code-intelligence` | [`I10.8.17`](../architecture/HANDLE_INDEX.md)<br>[`I18.18`](../architecture/HANDLE_INDEX.md) |
| `smart-memory-context` | [`I12.13`](../architecture/HANDLE_INDEX.md)<br>[`I17.11`](../architecture/HANDLE_INDEX.md) |
| `security-privacy` | [`I15.9`](../architecture/HANDLE_INDEX.md) |
| `research-acquisition` | [`I21.1`](../architecture/HANDLE_INDEX.md) |
| `supervision-meta` | [`I8.3`](../architecture/HANDLE_INDEX.md)<br>[`I14.25`](../architecture/HANDLE_INDEX.md) |
| `operator-surfaces` | [`I11.1`](../architecture/HANDLE_INDEX.md) |
| `module-runtimes` | [`I2.10`](../architecture/HANDLE_INDEX.md) |
| `legacy-migration-facades` | [`I19.14`](../architecture/HANDLE_INDEX.md) |
| `workspace-governance` | [`I2.8`](../architecture/HANDLE_INDEX.md)<br>[`I18.3`](../architecture/HANDLE_INDEX.md) |
| `documentation-authority` | [`I0.14`](../architecture/HANDLE_INDEX.md)<br>[`I19.15`](../architecture/HANDLE_INDEX.md) |

## Workspace packages

| Package manifest | Admission | Logical blocks |
|---|---|---|
| [`bins/eliot`](../../bins/eliot/Cargo.toml) | `default` | `operator-surfaces` |
| [`bins/eliot-agent-bridge`](../../bins/eliot-agent-bridge/Cargo.toml) | `workspace` | `agent-fabric` |
| [`bins/eliot-doctor`](../../bins/eliot-doctor/Cargo.toml) | `workspace` | `supervision-meta` |
| [`bins/eliot-dreamer`](../../bins/eliot-dreamer/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`bins/eliot-host`](../../bins/eliot-host/Cargo.toml) | `default` | `host-kernel-runtime` |
| [`bins/eliot-kernel`](../../bins/eliot-kernel/Cargo.toml) | `default` | `host-kernel-runtime` |
| [`bins/eliot-mod-research`](../../bins/eliot-mod-research/Cargo.toml) | `workspace` | `research-acquisition` |
| [`bins/eliot-native-worker`](../../bins/eliot-native-worker/Cargo.toml) | `workspace` | `module-runtimes` |
| [`bins/eliot-notify`](../../bins/eliot-notify/Cargo.toml) | `workspace` | `operator-surfaces` |
| [`bins/eliot-store-surreal`](../../bins/eliot-store-surreal/Cargo.toml) | `default` | `canonical-storage` |
| [`bins/eliot-testd`](../../bins/eliot-testd/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`bins/eliot-user-broker`](../../bins/eliot-user-broker/Cargo.toml) | `workspace` | `operator-surfaces` |
| [`bins/eliot-wasm-host`](../../bins/eliot-wasm-host/Cargo.toml) | `workspace` | `module-runtimes` |
| [`bins/eliot-watchdog`](../../bins/eliot-watchdog/Cargo.toml) | `default` | `supervision-meta` |
| [`bins/eliotd`](../../bins/eliotd/Cargo.toml) | `default` | `governor-semantic-control` |
| [`crates/agent/eliot-agent-acp`](../../crates/agent/eliot-agent-acp/Cargo.toml) | `workspace` | `agent-fabric` |
| [`crates/agent/eliot-agent-api`](../../crates/agent/eliot-agent-api/Cargo.toml) | `workspace` | `agent-fabric` |
| [`crates/agent/eliot-agent-claude`](../../crates/agent/eliot-agent-claude/Cargo.toml) | `workspace` | `agent-fabric` |
| [`crates/agent/eliot-agent-codex`](../../crates/agent/eliot-agent-codex/Cargo.toml) | `workspace` | `agent-fabric` |
| [`crates/agent/eliot-agent-contracts`](../../crates/agent/eliot-agent-contracts/Cargo.toml) | `workspace` | `agent-fabric` |
| [`crates/agent/eliot-agent-coordinator`](../../crates/agent/eliot-agent-coordinator/Cargo.toml) | `workspace` | `agent-fabric` |
| [`crates/agent/eliot-agent-opencode`](../../crates/agent/eliot-agent-opencode/Cargo.toml) | `workspace` | `agent-fabric` |
| [`crates/agent/eliot-swarm`](../../crates/agent/eliot-swarm/Cargo.toml) | `workspace` | `agent-fabric` |
| [`crates/eliot-app`](../../crates/eliot-app/Cargo.toml) | `workspace` | `legacy-migration-facades` |
| [`crates/eliot-engine`](../../crates/eliot-engine/Cargo.toml) | `workspace` | `legacy-migration-facades` |
| [`crates/eliot-store`](../../crates/eliot-store/Cargo.toml) | `workspace` | `legacy-migration-facades` |
| [`crates/eliot-types`](../../crates/eliot-types/Cargo.toml) | `workspace` | `legacy-migration-facades` |
| [`crates/eliot-windows-ipc`](../../crates/eliot-windows-ipc/Cargo.toml) | `workspace` | `legacy-migration-facades` |
| [`crates/foundation/eliot-bootstrap`](../../crates/foundation/eliot-bootstrap/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-contracts`](../../crates/foundation/eliot-contracts/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-evaluation-contracts`](../../crates/foundation/eliot-evaluation-contracts/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-evidence`](../../crates/foundation/eliot-evidence/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-observation-contracts`](../../crates/foundation/eliot-observation-contracts/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-protocol`](../../crates/foundation/eliot-protocol/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-receipts`](../../crates/foundation/eliot-receipts/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-rules`](../../crates/foundation/eliot-rules/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-runtime-contracts`](../../crates/foundation/eliot-runtime-contracts/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-security-contracts`](../../crates/foundation/eliot-security-contracts/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/foundation/eliot-test-support`](../../crates/foundation/eliot-test-support/Cargo.toml) | `workspace` | `foundation-contracts` |
| [`crates/governor/eliot-authority`](../../crates/governor/eliot-authority/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-budget`](../../crates/governor/eliot-budget/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-canonical`](../../crates/governor/eliot-canonical/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-change-monitor`](../../crates/governor/eliot-change-monitor/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-config`](../../crates/governor/eliot-config/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-coordination`](../../crates/governor/eliot-coordination/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-finish`](../../crates/governor/eliot-finish/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-governor`](../../crates/governor/eliot-governor/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-maintenance`](../../crates/governor/eliot-maintenance/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-module-registry`](../../crates/governor/eliot-module-registry/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-observation`](../../crates/governor/eliot-observation/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-problem`](../../crates/governor/eliot-problem/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-read`](../../crates/governor/eliot-read/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-session`](../../crates/governor/eliot-session/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-skill`](../../crates/governor/eliot-skill/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-task`](../../crates/governor/eliot-task/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/governor/eliot-workscope`](../../crates/governor/eliot-workscope/Cargo.toml) | `workspace` | `governor-semantic-control` |
| [`crates/instrument/eliot-artifact`](../../crates/instrument/eliot-artifact/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-build-test-graph`](../../crates/instrument/eliot-build-test-graph/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-code-cortex`](../../crates/instrument/eliot-code-cortex/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-code-graph`](../../crates/instrument/eliot-code-graph/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-diagnostic`](../../crates/instrument/eliot-diagnostic/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-empirical-profile`](../../crates/instrument/eliot-empirical-profile/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-graph-api`](../../crates/instrument/eliot-graph-api/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-instrument-api`](../../crates/instrument/eliot-instrument-api/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-instrument-cargo`](../../crates/instrument/eliot-instrument-cargo/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-instrument-dotnet`](../../crates/instrument/eliot-instrument-dotnet/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-instrument-nextest`](../../crates/instrument/eliot-instrument-nextest/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-instrument-runner`](../../crates/instrument/eliot-instrument-runner/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-instrument-rustc`](../../crates/instrument/eliot-instrument-rustc/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-instrument-rustfmt`](../../crates/instrument/eliot-instrument-rustfmt/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-instrument-scip`](../../crates/instrument/eliot-instrument-scip/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-observability`](../../crates/instrument/eliot-observability/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-process-executor`](../../crates/instrument/eliot-process-executor/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-product-evaluation`](../../crates/instrument/eliot-product-evaluation/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-reports`](../../crates/instrument/eliot-reports/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-test-selection`](../../crates/instrument/eliot-test-selection/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-testd-core`](../../crates/instrument/eliot-testd-core/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/instrument/eliot-verifier`](../../crates/instrument/eliot-verifier/Cargo.toml) | `workspace` | `instrument-code-intelligence` |
| [`crates/kernel/eliot-host-control-endpoint`](../../crates/kernel/eliot-host-control-endpoint/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-host-service`](../../crates/kernel/eliot-host-service/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-host-state`](../../crates/kernel/eliot-host-state/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-installation`](../../crates/kernel/eliot-installation/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-ipc`](../../crates/kernel/eliot-ipc/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-kernel-core`](../../crates/kernel/eliot-kernel-core/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-kernel-service`](../../crates/kernel/eliot-kernel-service/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-ors`](../../crates/kernel/eliot-ors/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-platform`](../../crates/kernel/eliot-platform/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-platform-windows`](../../crates/kernel/eliot-platform-windows/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-process`](../../crates/kernel/eliot-process/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/kernel/eliot-runtime`](../../crates/kernel/eliot-runtime/Cargo.toml) | `workspace` | `host-kernel-runtime` |
| [`crates/meta/eliot-doctor-core`](../../crates/meta/eliot-doctor-core/Cargo.toml) | `workspace` | `supervision-meta` |
| [`crates/meta/eliot-improvement`](../../crates/meta/eliot-improvement/Cargo.toml) | `workspace` | `supervision-meta` |
| [`crates/meta/eliot-runtime-status`](../../crates/meta/eliot-runtime-status/Cargo.toml) | `workspace` | `supervision-meta` |
| [`crates/modules/eliot-native-worker-core`](../../crates/modules/eliot-native-worker-core/Cargo.toml) | `workspace` | `module-runtimes` |
| [`crates/modules/eliot-wasm-runtime`](../../crates/modules/eliot-wasm-runtime/Cargo.toml) | `workspace` | `module-runtimes` |
| [`crates/research/eliot-research-exchange`](../../crates/research/eliot-research-exchange/Cargo.toml) | `workspace` | `research-acquisition` |
| [`crates/research/eliot-research-exchange-api`](../../crates/research/eliot-research-exchange-api/Cargo.toml) | `workspace` | `research-acquisition` |
| [`crates/research/eliot-researcher`](../../crates/research/eliot-researcher/Cargo.toml) | `workspace` | `research-acquisition` |
| [`crates/security/eliot-erasure`](../../crates/security/eliot-erasure/Cargo.toml) | `workspace` | `security-privacy` |
| [`crates/security/eliot-influence`](../../crates/security/eliot-influence/Cargo.toml) | `workspace` | `security-privacy` |
| [`crates/security/eliot-source-assurance`](../../crates/security/eliot-source-assurance/Cargo.toml) | `workspace` | `security-privacy` |
| [`crates/smart/eliot-context`](../../crates/smart/eliot-context/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/smart/eliot-cue-contracts`](../../crates/smart/eliot-cue-contracts/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/smart/eliot-cues`](../../crates/smart/eliot-cues/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-core`](../../crates/smart/eliot-dreamer-core/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/smart/eliot-epistemic`](../../crates/smart/eliot-epistemic/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/smart/eliot-memory`](../../crates/smart/eliot-memory/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/smart/eliot-memory-curation`](../../crates/smart/eliot-memory-curation/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/smart/eliot-system-experience`](../../crates/smart/eliot-system-experience/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/smart/eliot-understanding`](../../crates/smart/eliot-understanding/Cargo.toml) | `workspace` | `smart-memory-context` |
| [`crates/storage/eliot-backup`](../../crates/storage/eliot-backup/Cargo.toml) | `workspace` | `canonical-storage` |
| [`crates/storage/eliot-blob`](../../crates/storage/eliot-blob/Cargo.toml) | `workspace` | `canonical-storage` |
| [`crates/storage/eliot-blob-api`](../../crates/storage/eliot-blob-api/Cargo.toml) | `workspace` | `canonical-storage` |
| [`crates/storage/eliot-ecxf`](../../crates/storage/eliot-ecxf/Cargo.toml) | `workspace` | `canonical-storage` |
| [`crates/storage/eliot-store-api`](../../crates/storage/eliot-store-api/Cargo.toml) | `workspace` | `canonical-storage` |
| [`crates/storage/eliot-store-memory`](../../crates/storage/eliot-store-memory/Cargo.toml) | `workspace` | `canonical-storage` |
| [`crates/storage/eliot-store-surreal-adapter`](../../crates/storage/eliot-store-surreal-adapter/Cargo.toml) | `workspace` | `canonical-storage` |
| [`crates/supervision/eliot-watchdog-core`](../../crates/supervision/eliot-watchdog-core/Cargo.toml) | `workspace` | `supervision-meta` |
| [`crates/surfaces/eliot-agent-bridge-core`](../../crates/surfaces/eliot-agent-bridge-core/Cargo.toml) | `workspace` | `agent-fabric`<br>`operator-surfaces` |
| [`crates/surfaces/eliot-cli`](../../crates/surfaces/eliot-cli/Cargo.toml) | `workspace` | `operator-surfaces` |
| [`crates/surfaces/eliot-controlboard`](../../crates/surfaces/eliot-controlboard/Cargo.toml) | `workspace` | `operator-surfaces` |
| [`crates/surfaces/eliot-mcp`](../../crates/surfaces/eliot-mcp/Cargo.toml) | `workspace` | `operator-surfaces` |
| [`crates/surfaces/eliot-notify-core`](../../crates/surfaces/eliot-notify-core/Cargo.toml) | `workspace` | `operator-surfaces` |
| [`crates/surfaces/eliot-skills`](../../crates/surfaces/eliot-skills/Cargo.toml) | `workspace` | `operator-surfaces` |
| [`crates/surfaces/eliot-user-broker-core`](../../crates/surfaces/eliot-user-broker-core/Cargo.toml) | `workspace` | `operator-surfaces` |
| [`workspace/tools/eliot-campaign-executor`](../../workspace/tools/eliot-campaign-executor/Cargo.toml) | `workspace` | `workspace-governance` |
| [`workspace/tools/eliot-live-canary`](../../workspace/tools/eliot-live-canary/Cargo.toml) | `workspace` | `workspace-governance` |
| [`workspace/tools/eliot-runtime-compiler`](../../workspace/tools/eliot-runtime-compiler/Cargo.toml) | `workspace` | `workspace-governance` |

## Proof boundary

A clean index proves static workspace membership, inherited routing
contracts, logical-block coverage, resolvable documentation handles, and
byte-for-byte projection equality for the exact checkout. It does not prove
compilation, runtime wiring, semantic ownership, service health, or Product
acceptance.
