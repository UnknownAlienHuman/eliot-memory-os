# ELIOT verified documentation read bundle

Route receipt: `sha256:582e50501572bdfc456f8fc2884f5dcbb95f0321f603fed6ee1a6585e244c0f9`

Normative pair: `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`

> Every item below was verified against the route immediately before rendering.

---

## Required item `AGENTS.md`

SHA-256: `f53cfced00a959fb044ed257cecdab9fb993cd12a42ec19e8d2b1f5f45ba1026`; bytes: `2157`.

# Repository agent instructions

## Working scope

- Follow the requested scope. Explicit user instructions take priority over repository defaults.
- Use current `main` as the source and documentation authority. Check `git status --short --branch` and `git rev-parse HEAD` before editing.
- Preserve unrelated changes. For parallel work, use isolated worktrees and one writer per file; the root agent handles synchronization and integration.
- Read the nearest `AGENTS.md`, the owning issue/PR when present, and documentation relevant to the change.
- Project navigation: [workflow](WORKFLOW.md), [active workstreams](workstreams/ACTIVE.toml), [architecture contract](docs/ARCHITECTURE_CONTRACT.md).

<!-- eliot-doc-routing:start -->
## Documentation before editing

Before changing code, configuration, tests, workflows, or normative prose, run from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for each changed path family, or use `--changed-from origin/main` for the complete branch delta.
Read every required item in the verified bundle before editing. Rerun the reader when scope changes; resolve missing or stale routes before proceeding.
Keep the generated receipt, bundle hash, and reading attestation in the work record or PR, following the [reading protocol](docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->

## Verification and delivery

- Run the smallest check that covers the change: `just quick` for documentation/configuration, or the relevant package/edge proof for Rust. Repeat checks only after relevant changes or failures.
- Report what changed, which checks ran, and any failures, skipped checks, or remaining uncertainty. Match completion claims to observed evidence.
- GitHub Actions use `workflow_dispatch` only. Change workflows only when requested; run ordinary checks locally.
- Commit only task files. Keep credentials, local state, build output, `.eliot/`, `.codebase-memory/`, generated reports, and downloaded research out of Git.

---

## Required item `Cargo.toml`

SHA-256: `059d695bb78b44b0dd8a5113336caa2d01e4f17e14ea468d9c51969efff8483f`; bytes: `16436`.

````toml
[workspace]
members = [
  "bins/eliot-agent-bridge",
  "bins/eliot-wasm-host",
  "crates/eliot-app",
  "crates/eliot-engine",
  "crates/eliot-store",
  "crates/eliot-types",
  "crates/eliot-windows-ipc",
  "crates/agent/eliot-agent-api",
  "crates/agent/eliot-agent-acp",
  "crates/agent/eliot-agent-coordinator",
  "crates/agent/eliot-agent-contracts",
  "crates/agent/eliot-agent-claude",
  "crates/agent/eliot-agent-codex",
  "crates/agent/eliot-agent-opencode",
  "crates/agent/eliot-swarm",
  "crates/foundation/eliot-bootstrap",
  "crates/foundation/eliot-conformance-contracts",
  "crates/foundation/eliot-contracts",
  "crates/foundation/eliot-evaluation-contracts",
  "crates/foundation/eliot-evidence",
  "crates/foundation/eliot-observation-contracts",
  "crates/foundation/eliot-protocol",
  "crates/foundation/eliot-receipts",
  "crates/foundation/eliot-rules",
  "crates/foundation/eliot-runtime-contracts",
  "crates/foundation/eliot-security-contracts",
  "crates/foundation/eliot-test-support",
  "crates/governor/eliot-authority",
  "crates/governor/eliot-budget",
  "crates/governor/eliot-config",
  "crates/governor/eliot-problem",
  "crates/governor/eliot-workscope",
  "crates/storage/eliot-store-api",
  "crates/storage/eliot-store-memory",
  "crates/storage/eliot-store-surreal-adapter",
  "crates/storage/eliot-blob-api",
  "crates/storage/eliot-blob",
  "crates/instrument/eliot-graph-api",
  "crates/instrument/eliot-instrument-api",
  "crates/instrument/eliot-process-executor",
  "crates/kernel/eliot-host-state",
  "crates/kernel/eliot-host-control-endpoint",
  "crates/kernel/eliot-ipc",
  "crates/kernel/eliot-kernel-core",
  "crates/kernel/eliot-ors",
  "crates/kernel/eliot-platform",
  "crates/kernel/eliot-platform-windows",
  "crates/kernel/eliot-process",
  "crates/kernel/eliot-runtime",
  "crates/modules/eliot-native-worker-core",
  "crates/modules/eliot-wasm-runtime",
  "crates/security/eliot-source-assurance",
  "crates/surfaces/eliot-agent-bridge-core",
  "crates/surfaces/eliot-cli",
  "crates/surfaces/eliot-controlboard",
  "crates/surfaces/eliot-mcp",
  "crates/surfaces/eliot-notify-core",
  "crates/surfaces/eliot-skills",
  "crates/surfaces/eliot-user-broker-core",
  "crates/kernel/eliot-host-service",
  "crates/kernel/eliot-installation",
  "crates/kernel/eliot-kernel-service",
  "crates/storage/eliot-backup",
  "crates/storage/eliot-ecxf",
  "crates/governor/eliot-canonical",
  "crates/governor/eliot-change-monitor",
  "crates/governor/eliot-coordination",
  "crates/governor/eliot-finish",
  "crates/governor/eliot-governor",
  "crates/governor/eliot-maintenance",
  "crates/governor/eliot-module-registry",
  "crates/governor/eliot-observation",
  "crates/governor/eliot-read",
  "crates/governor/eliot-session",
  "crates/governor/eliot-skill",
  "crates/governor/eliot-task",
  "crates/instrument/eliot-artifact",
  "crates/instrument/eliot-build-test-graph",
  "crates/instrument/eliot-code-cortex",
  "crates/instrument/eliot-code-graph",
  "crates/instrument/eliot-diagnostic",
  "crates/instrument/eliot-empirical-profile",
  "crates/instrument/eliot-instrument-cargo",
  "crates/instrument/eliot-instrument-dotnet",
  "crates/instrument/eliot-instrument-nextest",
  "crates/instrument/eliot-instrument-runner",
  "crates/instrument/eliot-instrument-rustc",
  "crates/instrument/eliot-instrument-rustfmt",
  "crates/instrument/eliot-instrument-scip",
  "crates/instrument/eliot-observability",
  "crates/instrument/eliot-product-evaluation",
  "crates/instrument/eliot-r13-harness",
  "crates/instrument/eliot-reports",
  "crates/instrument/eliot-test-selection",
  "crates/instrument/eliot-testd-core",
  "crates/instrument/eliot-verifier",
  "crates/meta/eliot-doctor-core",
  "crates/meta/eliot-improvement",
  "crates/meta/eliot-runtime-status",
  "crates/security/eliot-erasure",
  "crates/security/eliot-influence",
  "crates/smart/eliot-context",
  "crates/smart/eliot-cues",
  "crates/smart/eliot-dreamer-core",
  "crates/smart/eliot-epistemic",
  "crates/smart/eliot-memory-curation",
  "crates/supervision/eliot-watchdog-core",
  "crates/research/eliot-research-exchange",
  "crates/research/eliot-research-exchange-api",
  "crates/research/eliot-researcher",
  "bins/eliot",
  "bins/eliot-doctor",
  "bins/eliot-dreamer",
  "bins/eliot-host",
  "bins/eliot-kernel",
  "bins/eliot-mod-research",
  "bins/eliot-native-worker",
  "bins/eliot-notify",
  "bins/eliot-store-surreal",
  "bins/eliot-testd",
  "bins/eliot-user-broker",
  "bins/eliot-watchdog",
  "bins/eliotd",
  "workspace/tools/eliot-runtime-compiler",
  "workspace/tools/eliot-campaign-executor",
  "workspace/tools/eliot-live-canary",
  "crates/smart/eliot-context-contracts",
  "crates/smart/eliot-cue-contracts",
  "crates/smart/eliot-dreamer-contracts",
  "crates/smart/eliot-dreamer-cycle",
  "crates/smart/eliot-epistemic-contracts",
  "crates/smart/eliot-learning-contracts",
  "crates/smart/eliot-memory-curation-contracts",
  "crates/smart/eliot-memory-curation-screen",
  "crates/smart/eliot-dreamer-classification",
  "crates/smart/eliot-dreamer-relation",
  "crates/smart/eliot-dreamer-episode",
  "crates/smart/eliot-dreamer-concept",
  "crates/smart/eliot-dreamer-procedure",
  "crates/smart/eliot-cue-normalizer",
  "crates/smart/eliot-cue-binding",
  "crates/smart/eliot-cue-index",
  "crates/smart/eliot-cue-activation",
  "crates/smart/eliot-context-candidates",
  "crates/smart/eliot-context-admission",
  "crates/smart/eliot-context-assembly",
  "crates/smart/eliot-reactive-context-plan",
  "crates/smart/eliot-context-measurement",
  "crates/smart/eliot-dreamer-conflict-analysis",
  "crates/smart/eliot-dreamer-development-diagnosis",
  "crates/smart/eliot-dreamer-maintenance-plan",
  "crates/smart/eliot-dreamer-configuration-plan",
  "crates/smart/eliot-dreamer-orchestration-plan",
  "crates/smart/eliot-dreamer-bundle",  # agent_order 4
  "crates/smart/eliot-dreamer-candidate-validation",  # agent_order 5
  "crates/smart/eliot-dreamer-claim-grounding",  # agent_order 14
  "crates/smart/eliot-dreamer-research-synthesis",  # agent_order 6
  "crates/smart/eliot-dreamer-rival-model",  # agent_order 16
  "crates/smart/eliot-dreamer-probe-plan",  # agent_order 17
  "crates/smart/eliot-dreamer-orientation",  # agent_order 6
  "crates/smart/eliot-dreamer-failure",  # agent_order 26
  "crates/smart/eliot-dreamer-structure-repair",  # agent_order 27
  "crates/smart/eliot-dreamer-reconsolidation",  # agent_order 28
  "crates/smart/eliot-dreamer-accessibility",  # agent_order 29
  "crates/smart/eliot-dreamer-memory-repair",  # agent_order 30
  "crates/smart/eliot-dreamer-curation",  # agent_order 31
  "crates/smart/eliot-dreamer-clarification",  # agent_order 7
  "crates/smart/eliot-dreamer-architecture-brief",  # agent_order 8
  "crates/smart/eliot-dreamer-implementation-brief",  # agent_order 9
]

# Capability cells declared by `[package.metadata.eliot]` with `agent_order`
# and no source yet. Excluding them keeps every per-crate cargo command
# working while a cell is being implemented; without an entry here or in
# `members`, cargo refuses with "current package believes it's in a
# workspace when it's not" and the cell cannot be built or tested at all.
#
# Wave admission (#829/T8-A0) is the single serialized root turn for proved
# contract cells: package-local proof first, then this one owner moves each
# from `exclude` to `members`. Leaves never self-promote. See I2.3 and I2.11.
# Single-cell admission (#806/T8-A806) follows the same serialized turn for
# eliot-dreamer-cycle (standalone nonmember; never in `exclude`).
exclude = [
  "crates/smart/eliot-learning-state-view",  # agent_order 33
  "crates/smart/eliot-learning-delta",  # agent_order 34
  "crates/smart/eliot-learning-overlay",  # agent_order 35
  "crates/meta/eliot-learning-activation-assessment",  # agent_order 36
]
default-members = [
  "bins/eliot",
  "bins/eliot-host",
  "bins/eliot-kernel",
  "bins/eliot-store-surreal",
  "bins/eliot-watchdog",
  "bins/eliotd",
]
resolver = "3"

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.94"
license = "MIT"

[workspace.dependencies]
anyhow = "1.0.102"
base64 = "0.22.1"
blake3 = "1.8.5"
clap = { version = "4.6.1", features = ["derive", "env"] }
ed25519-dalek = { version = "=3.0.0", default-features = false, features = ["alloc", "fast", "zeroize"] }
eliot-agent-api = { path = "crates/agent/eliot-agent-api", version = "0.1.0" }
eliot-agent-coordinator = { path = "crates/agent/eliot-agent-coordinator", version = "0.1.0" }
eliot-agent-contracts = { path = "crates/agent/eliot-agent-contracts", version = "0.1.0" }
eliot-engine = { path = "crates/eliot-engine", version = "0.1.0" }
eliot-store = { path = "crates/eliot-store", version = "0.1.0" }
eliot-types = { path = "crates/eliot-types", version = "0.1.0" }
eliot-windows-ipc = { path = "crates/eliot-windows-ipc", version = "0.1.0" }
eliot-bootstrap = { path = "crates/foundation/eliot-bootstrap", version = "0.1.0" }
eliot-conformance-contracts = { path = "crates/foundation/eliot-conformance-contracts", version = "0.1.0" }
eliot-contracts = { path = "crates/foundation/eliot-contracts", version = "0.1.0" }
eliot-evaluation-contracts = { path = "crates/foundation/eliot-evaluation-contracts", version = "0.1.0" }
eliot-evidence = { path = "crates/foundation/eliot-evidence", version = "0.1.0" }
eliot-observation-contracts = { path = "crates/foundation/eliot-observation-contracts", version = "0.1.0" }
eliot-protocol = { path = "crates/foundation/eliot-protocol", version = "0.1.0" }
eliot-receipts = { path = "crates/foundation/eliot-receipts", version = "0.1.0" }
eliot-rules = { path = "crates/foundation/eliot-rules", version = "0.1.0" }
eliot-runtime-contracts = { path = "crates/foundation/eliot-runtime-contracts", version = "0.1.0" }
eliot-security-contracts = { path = "crates/foundation/eliot-security-contracts", version = "0.1.0" }
eliot-authority = { path = "crates/governor/eliot-authority", version = "0.1.0" }
eliot-budget = { path = "crates/governor/eliot-budget", version = "0.1.0" }
eliot-config = { path = "crates/governor/eliot-config", version = "0.1.0" }
eliot-problem = { path = "crates/governor/eliot-problem", version = "0.1.0" }
eliot-workscope = { path = "crates/governor/eliot-workscope", version = "0.1.0" }
eliot-store-api = { path = "crates/storage/eliot-store-api", version = "0.1.0" }
eliot-store-surreal-adapter = { path = "crates/storage/eliot-store-surreal-adapter", version = "0.1.0" }
eliot-blob-api = { path = "crates/storage/eliot-blob-api", version = "0.1.0" }
eliot-blob = { path = "crates/storage/eliot-blob", version = "0.1.0" }
eliot-graph-api = { path = "crates/instrument/eliot-graph-api", version = "0.1.0" }
eliot-instrument-api = { path = "crates/instrument/eliot-instrument-api", version = "0.1.0" }
eliot-process-executor = { path = "crates/instrument/eliot-process-executor", version = "0.1.0" }
eliot-host-state = { path = "crates/kernel/eliot-host-state", version = "0.1.0" }
eliot-host-control-endpoint = { path = "crates/kernel/eliot-host-control-endpoint", version = "0.1.0" }
eliot-ipc = { path = "crates/kernel/eliot-ipc", version = "0.1.0" }
eliot-kernel-core = { path = "crates/kernel/eliot-kernel-core", version = "0.1.0" }
eliot-ors = { path = "crates/kernel/eliot-ors", version = "0.1.0" }
eliot-agent-bridge-core = { path = "crates/surfaces/eliot-agent-bridge-core", version = "0.1.0" }
eliot-cli = { path = "crates/surfaces/eliot-cli", version = "0.1.0" }
eliot-controlboard = { path = "crates/surfaces/eliot-controlboard", version = "0.1.0" }
eliot-mcp = { path = "crates/surfaces/eliot-mcp", version = "0.1.0" }
eliot-notify-core = { path = "crates/surfaces/eliot-notify-core", version = "0.1.0" }
eliot-skills = { path = "crates/surfaces/eliot-skills", version = "0.1.0" }
eliot-user-broker-core = { path = "crates/surfaces/eliot-user-broker-core", version = "0.1.0" }
eliot-platform = { path = "crates/kernel/eliot-platform", version = "0.1.0" }
eliot-platform-windows = { path = "crates/kernel/eliot-platform-windows", version = "0.1.0" }
eliot-process = { path = "crates/kernel/eliot-process", version = "0.1.0" }
eliot-runtime = { path = "crates/kernel/eliot-runtime", version = "0.1.0" }
eliot-native-worker-core = { path = "crates/modules/eliot-native-worker-core", version = "0.1.0" }
eliot-wasm-runtime = { path = "crates/modules/eliot-wasm-runtime", version = "0.1.0" }
eliot-source-assurance = { path = "crates/security/eliot-source-assurance", version = "0.1.0" }
eliot-host-service = { path = "crates/kernel/eliot-host-service", version = "0.1.0" }
eliot-installation = { path = "crates/kernel/eliot-installation", version = "0.1.0" }
eliot-kernel-service = { path = "crates/kernel/eliot-kernel-service", version = "0.1.0" }
eliot-canonical = { path = "crates/governor/eliot-canonical", version = "0.1.0" }
eliot-change-monitor = { path = "crates/governor/eliot-change-monitor", version = "0.1.0" }
eliot-coordination = { path = "crates/governor/eliot-coordination", version = "0.1.0" }
eliot-finish = { path = "crates/governor/eliot-finish", version = "0.1.0" }
eliot-governor = { path = "crates/governor/eliot-governor", version = "0.1.0" }
eliot-maintenance = { path = "crates/governor/eliot-maintenance", version = "0.1.0" }
eliot-module-registry = { path = "crates/governor/eliot-module-registry", version = "0.1.0" }
eliot-observation = { path = "crates/governor/eliot-observation", version = "0.1.0" }
eliot-session = { path = "crates/governor/eliot-session", version = "0.1.0" }
eliot-skill = { path = "crates/governor/eliot-skill", version = "0.1.0" }
eliot-task = { path = "crates/governor/eliot-task", version = "0.1.0" }
eliot-testd-core = { path = "crates/instrument/eliot-testd-core", version = "0.1.0" }
eliot-doctor-core = { path = "crates/meta/eliot-doctor-core", version = "0.1.0" }
eliot-runtime-status = { path = "crates/meta/eliot-runtime-status", version = "0.1.0" }
eliot-context = { path = "crates/smart/eliot-context", version = "0.1.0" }
eliot-watchdog-core = { path = "crates/supervision/eliot-watchdog-core", version = "0.1.0" }
eliot-research-exchange = { path = "crates/research/eliot-research-exchange", version = "0.1.0" }
eliot-research-exchange-api = { path = "crates/research/eliot-research-exchange-api", version = "0.1.0" }
eliot-researcher = { path = "crates/research/eliot-researcher", version = "0.1.0" }
futures-util = { version = "0.3.32", features = ["sink"] }
wasmtime = { version = "=47.0.4", default-features = false, features = ["component-model", "cranelift", "runtime", "std"] }
wat = "=1.256.0"
jsonc-parser = { version = "0.33.0", features = ["cst", "serde_json"] }
redb = "4.1.0"
schemars = { version = "1.2.1", features = ["derive", "uuid1"] }
secrecy = { version = "0.10.3", features = ["serde"] }
serde = { version = "1.0.228", features = ["derive"] }
serde_json = { version = "1.0.150", features = ["float_roundtrip"] }
sha2 = "0.10.9"
thiserror = "2.0.18"
time = { version = "0.3.51", features = ["local-offset", "serde", "serde-well-known"] }
tokio = { version = "1.52.3", features = [
  "fs",
  "io-util",
  "macros",
  "net",
  "process",
  "rt-multi-thread",
  "signal",
  "sync",
  "time",
] }
tokio-tungstenite = { version = "0.28.0", default-features = false, features = [
  "connect",
] }
toml = "1.1.2"
tracing = "0.1.44"
tracing-subscriber = { version = "0.3.23", features = ["env-filter", "fmt"] }
uuid = { version = "1.23.4", features = ["serde", "v4", "v7"] }
windows-service = "0.8.1"
windows = { version = "0.61.3", default-features = false, features = [
  "Win32_System_Com",
  "Win32_System_Ole",
  "Win32_System_TaskScheduler",
  "Win32_System_Variant",
] }
windows-sys = { version = "0.61.2", features = [
  "Win32_Foundation",
  "Win32_Security",
  "Win32_Security_Authorization",
  "Win32_Security_Credentials",
  "Win32_Storage_FileSystem",
  "Win32_System_JobObjects",
  "Win32_System_IO",
  "Win32_System_Ioctl",
  "Win32_System_Pipes",
  "Win32_System_Threading",
] }

[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "allow"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
dbg_macro = "warn"
expect_used = "warn"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
module_name_repetitions = "allow"
must_use_candidate = "allow"
print_stderr = "warn"
print_stdout = "warn"
unwrap_used = "warn"
````

---

## Required item `WORKFLOW.md`

SHA-256: `ba1119920d47f33b99ee51332d8951b009fc04ebe8512fb64966c6afbd9ff070`; bytes: `7991`.

# Development workflow

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Repeat `--path` for every mutable path family, or use `--changed-from
origin/main` for the complete branch delta, including deletions. Open the
verified bundle and read every required item before mutation. A route alone is
navigation, not reading evidence.

Record the route receipt ID, read receipt ID, matched routes, required handles,
fragment paths and SHA-256 values, verified bundle SHA-256, and explicit reading
attestation in the work unit or pull request. Optional fragments are loaded only
when the current decision crosses their stated boundary. A legacy `ELIOT_*`
compatibility map is never an acceptable read receipt.

If no non-baseline route matches, a required item is stale or missing, or scope
expands beyond the receipt, stop and rerun or repair the route; silence is not
permission. See [`docs/architecture/READING_PROTOCOL.md`](docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


## One authority surface

`main` is the current product source and documentation authority. Issues define
work; branches and worktrees execute it; pull requests integrate it. Reports,
audits, research dumps, local state, and generated evidence are not parallel
sources of truth.

Upstream synchronization is root-owned and controller-only. While online agents
are active, the root controller performs the coordinated upstream fetch
approximately hourly, and also at an explicit integration boundary when needed,
then publishes an authority receipt recording:
- remote URL;
- upstream ref (`refs/heads/main` / `origin/main`);
- commit SHA;
- sync result;
- timestamp (UTC).

Workers and managers never fetch or pull directly, and must not switch,
fast-forward, or update the controller/authority checkout or authority branches.
Issue worktrees and branches are provisioned from the published SHA; ordinary
issue-branch creation remains allowed in isolated worktrees. They verify their
local worktree and base revision against the published authority receipt without
updating refs.

Canonical navigation:

- Architecture authority: `docs/ARCHITECTURE_CONTRACT.md`;
- exact pair identity: `docs/normative-pair.toml`;
- product/source map: `docs/PROJECT_MAP.md`;
- documentation map: `docs/README.md`;
- active programmes: `workstreams/ACTIVE.toml`;
- repository agent rules: `AGENTS.md`.

## Work lifecycle

```text
open issue with owner, causal property, scope, proof, and non-goals
→ root/controller sync and publish authority receipt (remote URL, ref, SHA, result, timestamp)
→ verify local worktree and base commit against authority receipt (no fetch/pull by workers)
→ create a fresh issue-numbered branch from verified base commit
→ claim one mutable path scope
→ route, verify, and read the bounded documentation bundle
→ implement and run Module/Edge/Product proof as applicable
→ report read-only agent operations; escalate to manager audit on drift/anomaly
→ open PR to main with read receipt, authority receipt, and attestation
→ integrate by squash after current-main and proof checks
→ close issue and retire the branch
```

Normal branch form:

```text
<kind>/<issue-number>-<short-slug>
```

Allowed kinds: `work`, `fix`, `docs`, `chore`, `refactor`, `test`.
Provider-generated names, random adjective names, personal namespaces, and dated
campaign branches are not accepted for new work.

## Branch validity

A standard issue-numbered branch is valid only when:

1. the branch issue is open and describes the current causal change;
2. the branch was created from the verified base commit matching the published
   authority receipt;
3. verified base commit remains an ancestor before further mutation and merge;
4. its PR is open when one exists;
5. the declared mutable path scope has no other writer.

`workstreams/ACTIVE.toml` lists programmes, shared routing inputs, and any rare
explicit exception. It intentionally does not duplicate every ephemeral issue
branch; the issue and PR own that current state. There are no active long-lived
or nonstandard implementation branches.

Do not repair a superseded branch in place. Start a fresh branch and carry only
the reviewed change. A merged, closed, abandoned, or superseded branch is
retired. Branch content never outranks `main`, even when it contains newer dates
or more prose.

## Worktrees and writers

Use one worktree per mutating branch. Record the primary path scope in the issue
or PR. Two agents may read the same files, but they do not mutate the same scope
concurrently. Contract changes land before dependent implementation waves, and
the integration owner revalidates consumers after the contract change.

## Agent operations and audit escalation

Agent operations operate under strict least-privilege governance:

- **Read-only Antigravity operations reporting**: Antigravity is used for
  read-only operational reporting, session state inspection, routing receipts,
  and diagnostic telemetry. It does not possess completion, truth-promotion,
  or patch-application authority, and must never be invoked recursively.
- **Mandatory manager audit escalation**: Managers must immediately trigger a
  bounded audit and assign an independent, different verifier when any of the
  following conditions occur:
  - *Scope drift*: mutation outside the assigned mutable path scope or issue
    boundaries;
  - *Forbidden commands*: attempts to execute uncoordinated `git fetch`,
    `git pull`, `git push`, unauthorized network calls, or workflow mutations;
  - *Unsupported claims*: assertions of completion or conformance lacking exact
    evidence;
  - *Missing tests*: code changes without matching unit, regression, or edge
    proofs;
  - *Provider/session anomalies*: Governor denials, session instability, stale
    projections, or anomalous tool outputs.

## Documentation and evidence placement

Keep in Git:

- current canonical Architecture and Implementation;
- stable operator/developer documentation;
- ADRs for accepted load-bearing decisions;
- generated projections only when an active consumer and regeneration check
  exist;
- bounded reusable workstream briefs and routing metadata.

Do not keep in the active tree:

- historical audits, recovery programmes, progress logs, or one-off reports;
- donor research packages or reverse-engineering dumps;
- copies of documentation owned by Eliot Search or Eliot Research;
- swarm conversations/results;
- local databases, code-graph snapshots, runtime state, or credentials;
- generated documentation bundles or read receipts.

Investigation findings belong in the owning issue/PR. Large generated evidence
belongs in CI artifacts or an external content-addressed store. Retired content
remains recoverable from Git history; it is not copied into an `archive/`
directory that agents may mistake for current authority.

## Integration and proof

A PR states:

- owning issue/workstream;
- exact base and candidate revisions;
- published authority receipt reference (remote URL, ref, SHA, result, timestamp);
- changed causal property and path scope;
- documentation route/read receipt, bundle hash, handles, and agent attestation;
- proof executed and proof ceiling;
- affected edges and Product Pulse, or why they are not applicable;
- migration/rollback/removal consequences;
- residual unknowns.

Ordinary PR CI checks current source shape and compilation. The expensive full
workspace test/Clippy/build gate is a separately invoked source-candidate or
release operation, not a tax on every local change. A green check is not product
acceptance: source, build, runtime, store, and Product Proof remain separate
evidence dimensions.

---

## Required item `docs/ARCHITECTURE_CONTRACT.md`

SHA-256: `d1e4c393cd7c953d8e41725eae404882236b13493ace74e4513c4cd894a9e846`; bytes: `5523`.

# Architecture authority

This file is the repository authority and navigation contract. It is not a
third normative book.

## Accepted sharded normative pair

The 2026-08-28 adopted Architecture semantic byte stream is unchanged.
The Implementation byte stream is updated to incorporate the owner-approved
I9.4 amendment (#1980 / #1983). Each stream is reconstructed deterministically
from ordered fragments and verified against its reconstructed SHA-256 digest.

| Authority | Canonical manifest and entry | Revision | Edition | Reconstructed SHA-256 |
|---|---|---|---|---|
| Intent, theory, invariants, and Hard Boundaries | [`docs/architecture/architecture/manifest.json`](architecture/architecture/manifest.json) · [bounded index](architecture/architecture/README.md) | `4.5-draft` | `2026-08-28` | `C6932EAF26935E752EEFB4DE591AFC91EA1A7180BE5A8FF0005554B8029BAC1A` |
| Target owners, contracts, defaults, failure behavior, and migration | [`docs/architecture/implementation/manifest.json`](architecture/implementation/manifest.json) · [bounded index](architecture/implementation/README.md) | `0.29-draft` | `2026-08-28` | `40B0908A637F46BA6C7C51DB08E008673F9232ED74D510D3A4F38489D05D4E89` |

The machine-bindable adoption receipt is [`docs/normative-pair.toml`](normative-pair.toml). Its pair key is `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`, computed deterministically from the unchanged Architecture digest and the updated Implementation digest.

The historical paths [`docs/architecture/ELIOT_ARCHITECTURE.md`](architecture/ELIOT_ARCHITECTURE.md) and [`docs/architecture/ELIOT_IMPLEMENTATION.md`](architecture/ELIOT_IMPLEMENTATION.md) are compact compatibility maps. They preserve incoming file and heading links,
but agents must not load them as the documentation payload.

Use [`docs/architecture/READING_PROTOCOL.md`](architecture/READING_PROTOCOL.md),
[`docs/architecture/ROUTES.md`](architecture/ROUTES.md), and
[`docs/architecture/HANDLE_INDEX.md`](architecture/HANDLE_INDEX.md) for bounded routing.

Architecture still prevails over Implementation on semantic conflict. A layout
migration does not promote target behavior to current support; product status
remains `NOT_ACCEPTED / UNVERIFIED` until exact Product Proof exists.

## Preserved pre-sharding authority contract

> The following text is retained as migration evidence. Where it calls the
> two former monolith paths canonical files, the sharded authority section
> above supersedes only that repository-layout statement.

# Architecture authority

This file is the repository authority and navigation contract. It is not a
third normative book.

## Accepted normative pair

On 2026-08-28 the Architecture Owner adopted the exact English pair below as
ELIOT's sole current normative pair.

| Authority | Canonical repository file | Revision | Edition | SHA-256 |
|---|---|---|---|---|
| Intent, theory, invariants, and Hard Boundaries | [`docs/architecture/ELIOT_ARCHITECTURE.md`](architecture/ELIOT_ARCHITECTURE.md) | `4.5-draft` | `2026-08-28` | `C6932EAF26935E752EEFB4DE591AFC91EA1A7180BE5A8FF0005554B8029BAC1A` |
| Target owners, contracts, defaults, failure behavior, and migration | [`docs/architecture/ELIOT_IMPLEMENTATION.md`](architecture/ELIOT_IMPLEMENTATION.md) | `0.29-draft` | `2026-08-28` | `7805BF238FE91819ABA50D7E13AA86A8B977561195DBB98AA979F986E2FAB063` |

The machine-bindable adoption receipt is
[`docs/normative-pair.toml`](normative-pair.toml). Its pair key is
`sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`.
Only the two document digests form the normative pair. The receipt, indexes,
registries, issues, tests, audits, and generated projections are evidence or
navigation and cannot become a third normative source.

Architecture prevails over Implementation on semantic conflict. Adoption does
not promote a target mechanism to current implementation support. Product status
remains `NOT_ACCEPTED / UNVERIFIED` until exact Product Proof exists.

## Repository location and branch authority

The canonical files above live on `main`. A copy in another branch, worktree,
package, report, prompt, or agent memory has no current authority. Agents must
resolve current work through `AGENTS.md`, `WORKFLOW.md`, and
`workstreams/ACTIVE.toml` before using documentation.

There are no checked-in dated aliases or predecessor books. The superseded pair
had these digests:

- Architecture: `58E71A2BDB10925C63D85A708ED768AEE8617BED0FB52EB044478EC20AB439D8`;
- Implementation: `C216FB7F6FDBC62D108C748BE6F61CA7EF9E5D24E5BB13AF2677C31A58460C0B`.

Those bytes and their historical audits remain available through Git history
and issue/PR records only. They must not be restored into the active checkout or
combined with current sections as one contract. Any compiler, Rule Catalogue,
conformance map, brief, or runtime handshake still bound to the predecessor is
`STALE` until regenerated and verified against `docs/normative-pair.toml`.

Use [`docs/architecture/README.md`](architecture/README.md) and
[`docs/architecture/INDEX.md`](architecture/INDEX.md) for bounded routing.

## Current-system truth

Current source files, Cargo manifests and lockfile, generated metadata, compiler
diagnostics, tests, installed artifact hashes, store identity, and live runtime
observations are evidence for current support. Prose, reports, graphs, branch
names, successful builds, and test counts cannot by themselves establish
runtime health, D0/D1 acceptance, or `CURRENT_VERIFIED`.

---

## Required item `docs/DEPENDENCY_POLICY.md`

SHA-256: `a69844d656e7cdac0b92fb4d1e6fbcd5d3e923c30ee706ec598acd3c3868933a`; bytes: `5163`.

# Dependency policy

Dependencies implement bounded mechanics behind ELIOT-owned contracts. They do
not own Architecture, task semantics, authority, canonical memory, finish, or
recovery policy.

## Admission

A new or upgraded dependency requires:

- a real current consumer and owner;
- exact version/source identity in `Cargo.lock` or the applicable immutable
  runtime manifest;
- feature, MSRV, license, advisory, Windows-support, and build-cost review;
- a narrow facade/process/protocol boundary with no vendor types in public ELIOT
  contracts;
- failure, removal, migration, and rollback behavior;
- focused proof on the affected package/edge and broader proof only for a
  matching blast radius.

Prefer, in order:

1. use an upstream project unchanged behind a facade;
2. wrap an executable/service through a typed ELIOT protocol;
3. contribute upstream;
4. fork with explicit divergence ownership;
5. implement from scratch only for a genuinely unique ELIOT contract.

## Runtime and authority boundaries

- Optional third-party runtimes are separately obtained/licensed components.
- Credentials are confined to the owning adapter/process boundary.
- Availability or installation never grants semantic authority.
- Provider fallback never expands privacy, effects, or cost silently.
- A framework may implement local mechanics but cannot define ELIOT ownership,
  authority, task lifecycle, or proof semantics.
- Every dependency has an export/removal path appropriate to the state it can
  affect.

## Evidence

README claims, audit prose, donor research, and version names are not admission.
Current authority comes from exact lockfile/manifest identity plus applicable
executed evidence. Advisory and license exceptions are explicit and scoped; a
report is never committed merely to make a gate look complete.

Dependency decisions that change a load-bearing default, hard dependency,
canonical format/protocol, authority boundary, or production contour receive an
ADR. Ordinary implementation and routine patch updates do not.

## Repository hygiene

Downloaded packages, vendor source snapshots, research dossiers, reverse-
engineering output, and generated dependency reports do not live in the active
checkout. Findings belong in the owning issue/PR; generated SBOM/license/
advisory artifacts belong in CI or release artifacts. Git tracks only source,
accepted policy/ADR, and exact manifests/lockfiles required to reproduce the
current product candidate.

## Executable verification profiles

Dependency policy execution operates under two distinct profiles with separate
proof ceilings:

1. **`offline-source`**: A bounded, offline gate for local and PR validation. It
   verifies `deny.toml` policy conformance, scanner pinning, lockfile integrity
   across all ecosystems (`Cargo.lock`, `packages.lock.json`,
   `requirements-verification.txt`), full direct-dependency inventory
   accounting in `config/dependency-policy.toml`, and executes `cargo deny check
   bans licenses sources`. It checks cached offline data and does not claim
   current vulnerability coverage. Proof ceiling: `OFFLINE_SOURCE_EVIDENCE_ONLY`.
2. **`current-advisories`**: A manual source/release workflow profile. In
   addition to offline checks, it validates the current advisory snapshot from
   the authoritative RustSec advisory database, executes `cargo deny check
   advisories bans licenses sources`, binds advisory freshness, and generates a
   content-addressed canonical receipt. Proof ceiling:
   `DEPENDENCY_ADMISSION_AND_ADVISORY_EVIDENCE_CANDIDATE`.

## Multi-ecosystem denominator and inventory

All third-party inputs admitted into ELIOT are accounted for in a single
canonical manifest at `config/dependency-policy.toml`:

- **Rust**: Workspace member and standalone crates, locked via `Cargo.lock`,
  governed by `deny.toml`.
- **NuGet**: Operator desktop dependencies, locked via
  `apps/Eliot.Operator/packages.lock.json` with
  `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>`.
- **Python**: Repository verification dependencies, hash-locked with SHA-256
  digests in `scripts/requirements-verification.txt`.
- **Node / MCPB**: Bridge contracts and manifests under `integrations/`.
- **External executables**: Shipped or runtime services such as SurrealDB,
  inventoried with version, digest, license, trust model, and removal boundary.

Every direct third-party dependency must record a current consumer, capability
owner, justification, enabled features, public-contract exposure boundary, and
removal/rollback plan.

## Pinned scanner identity and canonical receipts

Scanner execution is pinned to an exact toolchain identity (`cargo-deny 0.20.2`
with executable digest). Policy execution produces a canonical receipt
(`.eliot/dependency-policy-receipt.json` or release artifact) that binds:

- Git source commit SHA;
- input manifest and lockfile SHA-256 digests;
- policy digest (`deny.toml` and `config/dependency-policy.toml`);
- scanner executable identity and version;
- advisory database snapshot timestamp and source;
- evaluated targets and feature profiles;
- structured exceptions and verification findings.

---

## Required item `docs/architecture/READING_PROTOCOL.md`

SHA-256: `fc2ac357ecec293f7246a5ebc5c1e46f5407bb3574ffe39b6224e4d5aa6a3e25`; bytes: `2611`.

<!-- generated: eliot-doc-shards-v1 -->
# Mandatory agent documentation protocol

The documentation is a routed contract graph, not a book-shaped prompt.

## Required sequence

1. Resolve current repository authority through `AGENTS.md`, `WORKFLOW.md`, and
   `workstreams/ACTIVE.toml`.
2. Run the verified reader from the repository root:

   ```text
   python scripts/docs_read.py read --path <repository/path> --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
   ```

   Repeat `--path` for every mutable path family, or use `--changed-from
   origin/main` for the complete branch delta, including deletions.
3. Open the verified bundle and read every required file/fragment before
   mutation. A route alone is navigation, not reading evidence.
4. Inspect optional one-hop fragments only when the current decision crosses
   their boundary.
5. Record the route/read receipt IDs, matched routes, required handles, fragment
   paths and SHA-256 values, verified bundle SHA-256, and explicit reading
   attestation in the work unit or pull request.
6. Re-run the reader when the changed path, causal property, authority boundary,
   or evidence scope expands.

Current normative pair: `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`.

## Fail-closed cases

Do not mutate the repository when:

- no non-baseline route matches a material path;
- a required handle cannot be resolved;
- a routed file/fragment hash or byte count differs from the read receipt;
- the verified bundle cannot be materialized;
- the shard manifest cannot reconstruct the adopted source hash;
- an incoming legacy anchor resolves only to a compatibility map and the
  canonical fragment was not opened;
- the task expands beyond the read receipt without a new reader invocation.

## Context discipline

The reader returns decision-sufficient fragments, not every related section.
The compatibility maps, full handle index, Decision Anchor index, and assembled
books are navigation or audit surfaces. They are prohibited as default agent
context.

To inspect all changed paths at once:

```text
python scripts/docs_read.py read --changed-from origin/main --topic "<causal property>" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

The generated bundle and receipts are local evidence and must not be committed.

To verify the documentation graph and reader implementation:

```text
python scripts/docs_shards.py verify --root .
python scripts/docs_router.py check --root .
python scripts/docs_read.py self-test
```

---

## Required item `workstreams/ACTIVE.toml`

SHA-256: `2bf61c09315add08bb0ec8fd2148f2f295b6abbf5e2e1e11b283204cada5b69b`; bytes: `2625`.

````toml
schema = "eliot.active-workstreams.v1"
authority_branch = "main"
updated_at = "2026-09-10"
workflow = "WORKFLOW.md"
agent_rules = "AGENTS.md"

[branch_policy]
new_branch_pattern = "^(work|fix|docs|chore|refactor|test)/[0-9]+-[a-z0-9]+(?:-[a-z0-9]+)*$"
standard_branch_requires_open_issue = true
requires_current_main_ancestor = true
one_issue_one_branch_one_pr = true
nonstandard_branch_requires_explicit_exception = true
merged_or_closed_branch_is_retired = true
unlisted_branch_mutation_allowed = false

[[workstream]]
id = "regression-probes"
status = "active"
branch_strategy = "fresh_per_issue_from_current_main"
issue_refs = [7, 8, 9, 10]
implementation_rule = "Historical observations are regression discriminators only. Each issue first reproduces or refutes the failure on exact current source/runtime/provider/store identities, then changes one causal owner in its own branch and PR."

[[workstream]]
id = "core-daemons"
status = "active"
branch_strategy = "fresh_per_issue_from_current_main"
issue_refs = [13, 14, 15, 18, 19, 20, 21, 22, 24]
completed_baseline_issue_refs = [16, 17, 23]
cross_cutting_follow_up_issue_refs = [100]
integration_issue_refs = [11]
confirmed_open_defect_refs = [63, 64, 65, 66, 67, 74, 77, 78, 79]
merged_source_fix_refs = [59, 61, 68, 70, 72, 73, 75, 76, 120]
forbidden_active_defect_refs = [82, 83, 84]
briefs = ["workstreams/core-daemons/AGENTS.md"]
inventories = ["workstreams/core-daemons/inventory.json"]
excluded_capabilities = ["dreamer"]
implementation_rule = "Open primary issues own current integration. Completed baseline issues remain historical boundary/proof references and are never valid writers. Issue #100 owns the shared native-process convergence follow-up. Confirmed defect issues own one causal contract or local repair. Every active issue uses its own current-main branch/PR; no worker combines the epoch, request-digest, Control-Reserve, process-session and runtime-contour migrations into one patch."

[[workstream]]
id = "cognitive-micromodules"
status = "active"
branch_strategy = "fresh_per_issue_from_current_main"
issue_refs = [38, 39, 40, 41, 43, 44, 45]
briefs = [
  "crates/smart/cognitive-wave-01.toml",
  "crates/smart/cognitive-wave-02.toml"
]
inventories = [
  "crates/smart/cognitive-contract-challenges.toml",
  "crates/smart/cognitive-crate-decisions.toml",
  "crates/smart/cognitive-donor-map.toml",
  "crates/smart/cognitive-edge-map.toml"
]
implementation_rule = "Each cell is implemented in its own issue-numbered branch and PR. Prototype Cargo/module manifests on main create no workspace, runtime, state, authority, or support admission."
````

---

## Required item `docs/architecture/A00-01-purpose-of-the-architecture.md`

SHA-256: `ee540ede56579ec388e26da2b290759e78ad3bb8a70ba57d56364800a1692750`; bytes: `1871`; handles=A0.1.

## A0.1. Purpose of the Architecture

The Architecture is neither an executable code nor a catalog of future structures. It is a **decision compass**. It records:

```text
what problem ELIOT solves;
what outcomes are valuable;
which properties must survive technology changes;
why the core principles were chosen;
how to act under conflict, failure, and incomplete knowledge;
where the Implementation may experiment.
```

The Architecture matters most when the Implementation faces a choice. It must make the following questions answerable:

```text
which option best preserves ELIOT's intent;
which local optimization damages the system;
which rule is obsolete;
where a Hard Boundary is required and where recovery is preferable;
whether a mechanism helps people and agents or merely serves its own ceremony;
whether the system can survive a local failure without losing its goal, evidence, or control;
which defect requires an Architecture change rather than another workaround.
```

Conformance is determined by preserved intent and observable outcomes, not by the number of prescriptions followed.

**ARCH-INTENT-01 — Intent outranks literal compliance.** A rule is useful only while it advances the purpose for which it was introduced. A rule that repeatedly blocks correct work or reproduces the original failure mode must be challenged, narrowed, or changed openly.

**Why:** real agent work always exceeds any rule written in advance; literal discipline without understanding turns safeguards into failure sources.

**Under conflict:** A0.3 Hard Boundaries remain intact. Everything else permits Governed Challenge, reversible deviation, and outcome verification. Citing Intent never authorizes a working agent to bypass controls silently: every deviation must be explicit, scoped, within already granted authority, and assigned an owner, review, and outcome.

---

## Required item `docs/architecture/A00-02-hierarchy-of-architectural-decisions.md`

SHA-256: `342c67f670714c83bb4c68693447fd7597bc4a662b87d4fa6bae09df3cbaf6e5`; bytes: `1867`; handles=A0.2.

## A0.2. Hierarchy of Architectural Decisions

| Class | Meaning |
|---|---|
| **Architectural Intent** | The ultimate goal and rationale; the primary guide under conflict |
| **Theory** | An explanation of cognition, memory, resilience, and learning; it does not impose one mechanism |
| **Invariant** | A property a healthy system preserves or restores over its trajectory |
| **Hard Boundary** | A narrow boundary around authority, secrets, irreversible effects, proof, or canonical integrity; enforced fail-closed |
| **Contract** | An observable capability obligation; degradation under failure must be explicit |
| **Guardrail** | A preferred defense against a known error class; challenge and scoped deviation remain possible |
| **Default** | The currently preferred mechanism; replaceable without changing Intent |
| **Policy** | A governed human decision about privacy, risk, cost, models, or operations |
| **Experiment** | A reversible hypothesis test with an evaluator, stop condition, and rollback |
| **Empirical Profile** | Versioned knowledge about a specific model, harness, toolset, and workload combination |
| **Metric** | A measure of a property that must not become the system's objective |
| **Example** | An illustration with no independent normative force |

`ARCH-*` entries are durable **decision anchors**. They restore meaning and support the conformance map, but must not turn every working boundary into ceremony. Normative force does not follow from words such as "must" alone; it follows from the decision class, rationale, and observable property. A listed mechanism is not permanent unless it is a Hard Boundary.

An Invariant is evaluated over a trajectory. A temporary error is tolerable when it is:

```text
detected;
localized;
not granted hidden authority;
recorded as evidence;
covered by recovery or honest escalation.
```

---

## Required item `docs/architecture/A00-03-hard-boundaries.md`

SHA-256: `695fe5e156e0dde052556e23c34b008009348742d4fc4a1146393b8b13a48bc0`; bytes: `821`; handles=A0.3.

## A0.3. Hard Boundaries

Fail-closed behavior is required only where an error could create irreversible effects or hidden control capture:

```text
hidden creation or expansion of authority;
hidden alteration of the user's ultimate goal;
an untraceable irreversible or external effect;
a false VERIFIED_COMPLETE or other proof claim;
hidden rewriting of provenance or history;
restoration of revoked influence after recovery;
a second ungoverned canonical owner or write path;
secrets or prohibited data crossing a privacy boundary.
```

Other failures default to:

```text
buffering;
isolation;
bounded influence;
branch or snapshot;
retry with new evidence;
alternative route;
repair;
quarantine;
escalation.
```

ELIOT safety depends not only on preventing errors, but also on surviving them without losing control.

---

## Required item `docs/architecture/A00-04-conflict-resolution.md`

SHA-256: `732d3b9a63973398e07e48691ba56f6538d9168f3102e0702a5ca2e08910f556`; bytes: `1318`; handles=A0.4.

## A0.4. Conflict Resolution

First determine whether a Hard Boundary is affected. If so, stop the dependent effect until explicit authority or recovery exists. Otherwise, treat the conflict as information.

| Question | Decisive basis |
|---|---|
| What happened | Observation, artifact, evidence, and an applicable verifier |
| What it means | Competing models, causal analysis, and Concilium |
| What the goal and acceptable risk are | The authorized human, after clarification when needed |
| What is currently permitted | Authority, WorkScope, privacy and cost policy, and actual integration capability |
| How to realize the principle | Intent and Contract, then the simplest reversible mechanism |
| Which model is better | Discriminative evidence and practical outcomes, not vote count |
| What to do when evidence is insufficient | Preserve the unknown; choose a probe, reversible trial, or safe partial progress |

Order of preference among admissible choices:

```text
1. preserve the stated goal and user agency without overriding evidence or Hard Boundaries;
2. improve the correctness and repairability of understanding;
3. prefer an observable, reversible, and recoverable path;
4. preserve provenance, alternatives, and dissent;
5. localize blast radius and cost;
6. choose the simpler mechanism.
```

---

## Required item `docs/architecture/A00-06-changing-the-architecture.md`

SHA-256: `c086ee01cc243b7d7dee465bc0ddfca0c36cc3a344b3b3e803a5eb94ff6f68a8`; bytes: `858`; handles=A0.6.

## A0.6. Changing the Architecture

```text
recurring problem or new fact
→ concise statement of the violated Intent
→ evidence and alternatives
→ Implementation and migration consequences
→ Architecture Owner decision
→ change to the main text.
```

The Implementation may refine concrete contracts and defaults while preserving Intent, Hard Boundaries, and observable behavior.

A **Recoverable Deviation** is permitted: a temporary, scoped departure from a Guardrail or Contract when useful progress requires it and no Hard Boundary is crossed. It has an owner, reason, affected scope, review condition, rollback, and outcome. A successful deviation becomes evidence for correcting the rule; a failed one becomes negative memory.

Append-only addenda with implicit precedence and permanent exceptions without an owner or review are prohibited.

---

## Required item `docs/architecture/A10-04-delegation.md`

SHA-256: `fd9c93b5e66ea93a0a2bb171706449ca8d07d2d48caeb99d1acdc57360014cd9`; bytes: `1980`; handles=A10.4.

## A10.4. Delegation

Every **Agent Work Unit** receives:

```text
one primary causal property and one primary owner;
an exact question and expected artifact or evidence;
a link to the current goal and acceptance criteria;
a frozen contract revision and applicable Architecture and Implementation handles;
minimally sufficient context: one-hop dependencies, known failures, and exact anchors;
read, write, and impact scope, allowed effects, and explicit non-goals;
the old failing behavior, representation gap, or missing capability;
a discriminator or verifier and proof ceiling;
role, authority, State Fence, budget, checkpoint, cancellation, and stop condition;
a structured output and integration owner.
```

"Small work" means causal closure, not a small number of files or lines. If one defect crosses several owners, decompose it into a contract or evidence unit, independent Module units, an edge or integration unit, and a Product Pulse; never give one agent a hidden cross-system mandate.

An agent may return a Contract Challenge when the selected owner is wrong, the discriminator measures a proxy, the contract is contradictory, or the required proof is unattainable within the granted scope. A challenge is not refusal and is routed to the Task Controller or Concilium.

Within one active task, exactly one Task Controller owns the current plan revision for the Authority Epoch. One mutable artifact scope has one writer; read-only research or audit lanes may run in parallel. Workers do not integrate their own results automatically: a separate integration owner revalidates the State Fence, affected edges, and product outcome. No shared mutable plan exists implicitly.

Goals, instructions, and constraints preserve source, authority, scope, and status: active, superseded, expired, or conflicting. A new instruction is not silently layered over an old one; an unresolved conflict limits only dependent actions and creates an interruption or reframing boundary.

---

## Required item `docs/architecture/A14-08-development-doctrine.md`

SHA-256: `c7da919cd6112e97780407b7a7ae9806185994c2de6a275ed2449cb1b9ca78bb`; bytes: `3740`; handles=A14.8.

## A14.8. Development Doctrine

ELIOT is designed with the assumption that fallible agents will implement it and may optimize the nearest test, expression, or status. Task decomposition, testing, and integration must therefore preserve the causal link from user goal and acceptance to observable outcome.

Normal development loop:

```text
1. Build the minimum vertical spine in A0.8 and use it in real work.
2. Select one causal property and its actual production owner and path.
3. Record the old failing behavior or missing capability and its discriminator.
4. Decompose work into Contract or Evidence, Module, and Edge or Integration units.
5. Perform bounded parallel work on independent Modules.
6. Obtain Module Proof, then affected Edge Proof.
7. Run the smallest Product Pulse able to detect architectural drift.
8. Promote, narrow, roll back, or open Mechanism Review.
9. Record the outcome in memory, tests, Skills, and repair or decomposition candidates.
10. Remove ceremony and mechanisms that produce no decision delta.
```

Every supported Module has an independently invocable proof surface. This does not require a fixed size, separate process, or fully independent compilation universe. Independence means a clear contract, bounded fixtures or environment, reproducible entrypoint, exact failure attribution, and known proof ceiling.

Proof levels remain distinct:

```text
Module Proof — capability behind its own contract;
Edge Proof — real provider and consumer interaction or runtime boundary;
Product Proof — end-to-end user or agent outcome;
Release Proof — accepted Product Identity, recovery, and distribution boundary.
```

A local PASS is not promoted automatically. Product Pulse specifically checks whether many local greens have combined into a system-level failure.

Testing and debugging are continuous and proportional to change closure:

```text
the changed Module and its contract;
affected dependency and consumer edges;
selected recovery, security, and concurrency paths;
the full release matrix only for a matching blast radius or release.
```

The first test repair begins with a discriminator that fails on the exact old path. Zero executed expected tests is not PASS. An agent changing implementation does not weaken oracle, fixture truth, tolerance, or verifier semantics in the same work unit without a separate decision and review. Concurrency, retries, cutovers, and recovery use deterministic simulation or fault injection where it distinguishes interleavings; simulation never replaces at least one real-edge or live proof.

Testing during work does not mean rewriting the active generation in place. A candidate Module is tested in an isolated environment, replay, shadow, or canary; background tests cannot displace active work, Control Reserve, or Human attention. A failure creates a Failure Capsule and the next discriminator, not merely another broad suite.

A test is valuable when it:

```text
distinguishes competing implementation hypotheses;
protects already observed value;
checks an effect, integration, recovery, or migration;
prevents recurrence of a real failure;
catches proxy success before it becomes a product regression.
```

Counts of Modules, tests, phases, reports, or certificates are not progress without Product Proof. Topology and test strategy are themselves Improvement Candidates and change according to agent success, context usability, build and test cost, escaped failures, and Product Pulse.

**ARCH-DEV-02 — Depth grows through independently testable layers under stable intent.** ELIOT is not rewritten wholesale for every new model or runtime technique; Modules, proofs, and promotion contours evolve from observed value and failure evidence.

---

## Required item `docs/architecture/I00-03-decision-sources.md`

SHA-256: `c5d7586399d8640484edaa3cb949495bc99a82b50dabddac029b2d08c2d716e8`; bytes: `1265`; handles=I0.3.

## I0.3. Decision sources

Authority and evidence classes are stable; filenames and audit chronology are not part of the normative contract:

1. `ELIOT_ARCHITECTURE.md` — Intent, Theory, Hard Boundaries and decision anchors.
2. This Implementation — current target owners, contracts, defaults, failure behavior and migration paths.
3. Accepted generated contract/registry artifacts — executable projections bound to the exact normative-pair digest; they cannot override either book.
4. Exact code, build, installed-runtime, store and live-operation evidence — support/conformance observations on one Product Identity; they cannot silently rewrite the books.
5. Legacy books, research, donor projects, audits and model reviews — non-normative evidence held in content-addressed external ledgers with scope, provenance, disposition and falsifier. Detailed inactive crate/test/research hypotheses are retained through the current content-addressed cold-backlog evidence receipt and do not enter normal agent context.

A named report, date, vendor document or prior assistant answer never acquires standing by being listed here. The active evidence ledger supplies exact digests and current dispositions; chronological audit prose remains outside this book.

---

## Required item `docs/architecture/I00-04-change-classes.md`

SHA-256: `3c1fc91d692bee9494327b7f5375fbe45cddc00c27d5a0bf0dc3b40300a2ae45`; bytes: `3252`; handles=I0.4.

## I0.4. Change classes

| Class | Example | Decider | Minimum verification |
|---|---|---|---|
| Local | UI text, isolated parser, report format | Module owner | Module checks |
| Compatible Module | new Module generation without state migration | Module owner + supervisor policy | contract + affected integration + canary |
| Cross-module | protocol field, shared contract, dependency edge | integration owner | affected graph + compatibility suite |
| Load-bearing | Kernel, store semantics, authority, ORS, security boundary | System Owner + architecture/conformance review | dedicated fault/migration suite |
| Release | published installation | release owner | full release gate |
| Architecture-impacting | changes Intent or Hard Boundary | Architecture Owner | Architecture revision before code promotion |

### Normative pair and evidence artifact identity

Only `ELIOT_ARCHITECTURE.md` and `ELIOT_IMPLEMENTATION.md` form the normative pair. Audits, research, migrations, benchmarks, and generated projections are evidence artifacts: they may disprove a support claim, open a gap, or propose a change, but gain no normative force from name, date, completeness, or citation count.

```yaml
NormativePairDocumentIdentity:
  document_id:
  role: architecture | implementation
  semantic_version:
  sha256:
  predecessor_sha256:
  paired_document_sha256:
  generated_at:
  status: candidate | accepted | superseded | invalidated

EvidenceArtifactIdentity:
  artifact_id:
  role: audit | research | migration_evidence | benchmark | generated_projection
  sha256:
  source_identity_refs:
  scope_and_validity:
  evidence_class_and_execution_status:
  owner_and_disposition:
  invalidation_and_expiry:
```

Hard rules for an intentionally frozen or published revision:

```text
`ELIOT_IMPLEMENTATION.md` and its published versioned copy are byte-identical;
any byte change after freeze creates a new identity and invalidates only verdicts bound to the prior digest;
an audit or PASS applies only to the exact source identities and scope it names;
Architecture/Implementation projections, Skills and agent packets carry the exact normative-pair identity they were compiled from;
no agent may combine sections from two frozen Implementation digests as one current contract;
an EvidenceArtifactIdentity can narrow or invalidate a support claim, but cannot change Architecture/Implementation without the applicable governed document revision.
```

A working draft may change under version control without minting a content-addressed identity or incrementing the display version after every edit; it acquires an identity only at the freeze/publication boundary of I0.14. The pair identity is emitted externally after both files are frozen. This prose never embeds or hand-maintains its own digest.

Normative identifiers, schemas, wire values, reason codes and generated RuleCatalogue entries use English. Explanatory prose may be Russian or English, but one classified rule block and one generated agent instruction are language-homogeneous. Translation is a projection carrying the exact source rule ID/revision; it is not a second contract. Context measurements use the tokenizer of the actual rendered language rather than assuming STU equivalence.

---

## Required item `docs/architecture/I00-05-conformance-support-and-evidence-status.md`

SHA-256: `bfb599eb462ebfb904ec97ba199a8447371bce91ab73b7bad9e71f150cb837f9`; bytes: `6368`; handles=I0.5.

## I0.5. Conformance, support and evidence status

Conformance is evidence-derived state, not maintained prose. Three orthogonal dimensions are mandatory:

```text
ContractMaturity
  SKELETON | COMPATIBLE | STABLE | REPLACEABLE | RETIRED;

ImplementationSupport
  CURRENT_VERIFIED | CURRENT_UNVERIFIED | PARTIAL | BLOCKED | TARGET |
  EXPERIMENTAL | DEFERRED | DEGRADED | STALE | NOT_APPLICABLE;

EvidenceExecutionStatus
  NOT_EXECUTED | SIMULATED | EXECUTED | UNKNOWN_OUTCOME.
```

A detailed schema, trait, command or state machine in this book is `TARGET` unless exact current source handles and current Product Identity evidence say otherwise. `TARGET` is a design obligation, not evidence that a capability exists. A source implementation can be `CURRENT_UNVERIFIED`; a generated report cannot promote it.

Canonical evidence binds every support claim to an exact Product Identity and invalidation set. `docs/conformance.toml` is the deterministic, read-only **documentation projection** of M1 Architecture IDs and Appendix H. It proves mapping completeness only; it is not runtime/source support evidence and cannot promote any row above `TARGET` / `NOT_EXECUTED` without separate exact evidence. Each row preserves the exact human Appendix-H owner cell as `owner_projection`; that field is unparsed documentation text, not an executable owner registry or authority grant:

```toml
projection_status = "DOCUMENTATION_TARGET"
runtime_evidence_status = "NOT_EVIDENCE"
normative_pair_receipt = "docs/normative-pair.toml"

[[requirement]]
id = "ARCH-MOD-01"
owner_projection = "I1, I2, I14.14–I14.16"
observable_proof_family = "optional module crash while Kernel remains healthy"
contract_maturity = "SKELETON"
implementation_support = "TARGET"
evidence_execution_status = "NOT_EXECUTED"
source_handles = []
evidence_refs = []
notes = "documentation mapping only; exact runtime/source support remains unproven"
```

Rules:

```text
CURRENT_VERIFIED requires executed, current, scoped evidence on the exact identity;
CURRENT_UNVERIFIED means source exists but product behavior is not proven;
TARGET/EXPERIMENTAL/DEFERRED cannot satisfy current product acceptance;
NOT_EXECUTED or SIMULATED evidence cannot satisfy a real-effect verifier;
any invalidated dependency makes support STALE;
report wording, test count, trait presence or manual status edit cannot promote support;
several ARCH anchors may share one end-to-end proof;
no separate test is required merely because an ID exists.
```

### Current-system evidence snapshot

Current implementation support is never inferred from this prose. A generated `CurrentSystemEvidenceSnapshot` binds the exact repository/runtime/data state used by repair, migration, product and deletion decisions:

```yaml
CurrentSystemEvidenceSnapshot:
  snapshot_id_revision_and_digest:
  normative_pair_identity:
  compiler_and_execution_receipt:
  product_identity_and_source_heads:
  installed_artifact_and_generation_hashes:
  active_store_schema_and_data_revision:
  active_integration_skill_hook_and_surface_manifest_digests:
  domain_coverage:
    source: OBSERVED | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    build: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    runtime: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    store: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    integrations: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
  capability_support_rows:
    - contract_ref:
      support_claim_ref:
      support_observation_state: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
      contract_maturity:
      implementation_support:
      evidence_execution_status:
      source_handles:
      evidence_refs:
      blind_or_unobserved_boundaries:
      invalidation_set:
  current_product_blockers_and_unresolved_regressions:
  generated_at_expiry_and_invalidation:
```

Each capability row carries the exact three I0.5 dimensions. `support_observation_state` describes observation availability/state only; it is not an `ImplementationSupport` value. `UNKNOWN`, `UNAVAILABLE`, `NOT_RUNNING` or `CONFLICTED` observation cannot be copied into support, maturity or evidence execution. A bound support claim remains at the strongest state actually justified by exact evidence: absent source evidence stays `TARGET` / `NOT_EXECUTED`; present but behavior-unproven source may be `CURRENT_UNVERIFIED`; incomplete behavior may be `PARTIAL` or `DEGRADED`; invalidated evidence is `STALE`. A report may render these values only from `support_claim_ref`; manual report text cannot promote them.

`CurrentSystemEvidenceCompiler` is a D0 FunctionalCapabilityCell with no canonical mutable state. Its source-maintenance owner is the first-party `eliot-bootstrap` crate; its D0 execution owner is the short-lived `eliot.exe` command `eliot system snapshot`. After InstrumentRunner exists, the same pure compiler core executes as a typed Instrument profile and Governor admits the immutable artifact. The crate also contains the bootstrap-only adapters required to read exact repository/worktree identity, build artifacts, service/process manifests, config/policy, optional runtime/store probes and integration manifests; platform/tool adapters remain behind narrow ports. It never infers a running system from prose or a PID alone, and it does not become a daemon, store or status owner.

The compiler has an independent ModuleTestCapsule covering partial source trees, absent runtime/store, stale manifests, conflicting identities, forged support statuses and interrupted probes. A Human-provided fact is preserved as an attributed observation; it cannot directly set `CURRENT_VERIFIED` or `EXECUTED`. Manual YAML editing is not an admitted producer.

The snapshot is regenerated after any source/runtime/data change and before a repair campaign, repository cutover, old-document deletion or product claim. Missing domains remain explicit as `support_observation_state = NOT_RUNNING | UNKNOWN | UNAVAILABLE | STALE | CONFLICTED`; they never create an `ImplementationSupport` value. An absent runtime is `NOT_RUNNING`, not a global compiler failure. Dependent support remains at the strongest state justified by exact current evidence; absence or staleness never promotes a target contract to current support.

---

## Required item `docs/architecture/I00-13-current-support-conformance-and-product-status.md`

SHA-256: `2d691986e973b4c9191cf5718f32b5035a8470b8355c5d82489df48c18651d2e`; bytes: `996`; handles=I0.13.

## I0.13. Current support, conformance and product status

Architecture defines meaning; Implementation defines the current target contract; exact code, runtime, and data evidence demonstrates support.

Every load-bearing contract has independent `ImplementationSupport`:

```text
CURRENT_VERIFIED;
CURRENT_UNVERIFIED;
PARTIAL;
BLOCKED;
TARGET;
EXPERIMENTAL;
DEFERRED;
DEGRADED;
STALE;
NOT_APPLICABLE.
```

A prose type, CLI example, schema, report, or generated catalogue row is `TARGET` by default unless exact source handles, Product Identity, executed evidence, verifier, and invalidation set exist.

Current product status:

```text
Architecture direction: accepted for continued design;
Implementation document: target contract;
local current source: UNKNOWN until CurrentSystemEvidenceSnapshot;
installed runtime: UNKNOWN;
live store/data revision: UNKNOWN;
product: NOT_ACCEPTED / UNVERIFIED.
```

No audit package, manifest, or test count can elevate this status without Product Proof.

---

## Required item `docs/architecture/I00-14-documentation-and-evidence-build-integrity.md`

SHA-256: `e645a72c291c89a4bc3e2eae99527aa2476dcfab0280e429df80405dbebe3fd9`; bytes: `3413`; handles=I0.14.

## I0.14. Documentation and evidence-build integrity

Documentation integrity is proportional to the decision being made. Routine drafting must not become a release ceremony.

### Working-draft path

Normal iterative edits use:

```text
version control and one visible diff;
Markdown/reference/contract-owner lint;
current section-level review;
no mandatory audit report, ZIP, manifest or archive;
no claim that the draft is accepted or independently verified.
```

A working draft may change repeatedly. Its display version is not a Product Identity and no evidence package is required after every edit.

### Freeze/publication path

Content-addressed packaging is required only when the exact bytes become load-bearing outside the current editing episode, for example:

```text
normative-pair candidate/cutover;
external independent audit;
repository authority migration;
old-document deletion gate;
release or handoff that cites an exact document identity;
forensic/recovery archive.
```

Then the sequence is:

```text
1. Assemble immutable staging inputs.
2. Render documents and required machine ledgers once.
3. Reject unresolved template placeholders, duplicate owners and broken references.
4. Freeze bytes.
5. Compute pair identity and required evidence digests.
6. Build only the package required by the decision.
7. Re-extract that package and verify payload digests/references.
8. Publish atomically.
```

After freezing, any byte change creates a new candidate identity and invalidates only audits/packages that depended on the prior bytes. It does **not** require regenerating unrelated historical packages or a new prose audit merely to continue drafting.

`DocumentationEvidenceCheck` for a frozen decision verifies at least:

```text
current/versioned byte equality when a versioned copy is intentionally published;
manifest/package digest equality for the package actually being used;
no unresolved template sentinel;
referenced local evidence resolves by digest or declared external URI;
generated counts are recomputed from payloads;
no audit claims CURRENT_VERIFIED without executable evidence;
no normative section stores chronological audit history already held by the ledger.
```

A successful documentation check proves artifact integrity and traceability only. It is not Product Proof and cannot certify code/runtime/data conformance.

The normative pair is identified externally after both files are intentionally frozen:

```yaml
NormativePairIdentity:
  pair_key: hash(architecture_sha256, implementation_sha256)
  architecture_revision_and_sha256:
  implementation_revision_and_sha256:
  derived_contract_catalogue_or_generation_refs: # evidence only; not a third normative document
  external_requirement_and_decision_evidence_refs: # evidence only; do not change pair_key
  created_at_and_builder_identity:
  evidence_package_manifest_ref: # optional; required only when the freeze/publication decision uses a package
  supersedes_identity_ref:
```

Only the two document digests form `pair_key`. Requirements ledgers, contract catalogues, audits and packages remain evidence/projections and cannot become a third normative book.

The Implementation never contains its own final digest as authority. Handshakes, cutovers and audits use the external pair receipt. A normal working-draft edit needs no content-addressed package until one of the freeze/publication triggers occurs.

---

## Required item `docs/architecture/I02-17-parallel-agent-development-contract.md`

SHA-256: `6c333908b112859dbffe00c04a9e942b38c5d369a85d89d78788ab576a1d7cb1`; bytes: `1834`; handles=I2.17.

## I2.17. Parallel agent development contract

An agent swarm develops FunctionalCapabilityCells in parallel only after freezing the applicable contract revision; crates are source and build containers.

```text
Contract/Evidence wave
  owner, public API, old failure, discriminator, fixtures;

Module-cell wave
  disjoint FunctionalCapabilityCells are implemented in parallel within bounded source packages;

Edge wave
  independent integrators verify real boundaries;

Product Pulse
  the shortest actual front-door path catches architectural drift.
```

### Assignment rule

One `AgentWorkUnitBrief` contains by default:

```text
one primary FunctionalCapabilityCell;
bounded support closure, justified by one-hop contracts/effects and measured context;
one causal property;
one discriminator;
one contract revision;
one integration owner;
an Agent Workset within I2.16.
```

A cross-crate defect is decomposed into:

```text
contract change unit;
provider/consumer crate units;
edge integration unit;
product pulse.
```

An agent receives neither a giant task such as “fix the entire subsystem” nor a meaningless atomized task such as “change one line” without product context.

### ContractChallenge

An agent must return a challenge instead of proxy optimization when:

```text
the primary owner is wrong;
the discriminator does not fail on the old production path;
the contract is contradictory;
the oracle would need a hidden change;
a decision-sufficient workset fits no applicable qualified Context Envelope;
a local edit would break a product invariant;
several tasks conflict over a public contract or state owner.
```

### Write isolation

Every mutating lane has a worktree, write and path claims, BuildFingerprint, test-resource namespace, and IntegrationCandidate. A worker does not integrate its own result.

---

## Required item `docs/architecture/I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md`

SHA-256: `8a5d8276f2e1357eb58dd06acc7e5ac4017a4515048a5049c84e33849c381ef5`; bytes: `5497`; handles=I2.20.

## I2.20. Module Contract Kit, Crate Context Capsule, and Module Test Capsule

### `FunctionalCapabilityCell`

A functional cell is a causal decomposition unit, not a sentence-length rule and not automatically a Cargo crate:

```yaml
FunctionalCapabilityCell:
  cell_id:
  purpose_and_user_or_system_property:
  causal_responsibilities:
  lifecycle_owner:
  owned_state_or_explicit_statelessness:
  allowed_effect_classes:
  public_contract_refs:
  independent_proof_surface:
  failure_degradation_and_recovery_boundary:
  replacement_and_rollback_boundary:
  providers_consumers_and_product_pulse:
```

One crate may contain several cells when either: (a) they form a stateless cross-owner contracts/primitives island with no mutable state or effects; or (b) they share one lifecycle owner, one coherent contract/dependency island and one package proof boundary. Several unrelated mutable-state owners, unrelated effect classes or independent rollback boundaries inside one crate trigger `MicroModuleTopologyReview`. A single cohesive cell may remain large when its complete Agent Workset is measurable and independently provable. Package membership never transfers lifecycle authority between cells.

### `EffectiveMicroModuleManifest`

The manifest is generated from Cargo, contract catalogue, Build/Test/Verifier graphs and runtime manifests; it is not another manually maintained authority: One manifest represents one FunctionalCapabilityCell; a crate containing several cells has several manifests.

```yaml
EffectiveMicroModuleManifest:
  manifest_id_revision_and_digest:
  functional_cell_ref:
  source_modules_and_crates:
  lifecycle_owner:
  runtime_owner_and_bundle:
  public_contract_digest:
  owned_state_and_effect_classes:
  execution_contour_and_replacement_class:
  iteration_lane_and_proof_latency_profile_ref:
  physical_source_STU:
  loaded_slice_and_agent_workset_profiles:
  dependency_ports_and_one_hop_providers_consumers:
  independent_proof_entrypoint_and_proof_ceiling:
  affected_edge_profiles:
  product_pulse_ref:
  failure_degradation_recovery_and_removal_boundary:
  current_support_freshness_and_invalidation:
  split_merge_extraction_conditions:
```

### `ProofLatencyProfile`

```yaml
ProofLatencyProfile:
  module_cell_and_proof_profile:
  exact_machine_toolchain_cache_and_build_fingerprint:
  sample_count_warmup_and_contention:
  p50_p95_p99_and_max:
  CPU_RSS_IO_and_queue_wait:
  expected_lane: interactive | normal | slow | manual_release
  qualification_status_expiry_and_invalidation:
```

Missing proof-latency evidence disables automatic assignment to the interactive lane; it does not fabricate failure or force a split. The scheduler may still run the proof as a bounded Durable Job.

### `ModuleContractKit`

```yaml
ModuleContractKit:
  contract_revision:
  crate_or_cell_identity:
  purpose_and_invariants:
  public_types_and_schemas:
  owned_state_and_effects:
  dependency_ports:
  compatibility_rules:
  negative_cases:
  known_unknowns:
  oracle_origins:
```

### `CrateContextCapsule`

```yaml
CrateContextCapsule:
  product_objective:
  functional_capability_cell_refs:
  effective_micro_module_manifest_ref:
  primary_source_package:
  source_token_estimate:
  selected_source_and_tests:
  one_hop_providers:
  one_hop_consumers:
  architecture_implementation_refs:
  failure_fingerprints:
  edge_tests:
  product_pulse:
  omitted_material_and_handles:
  effective_context_profile:
```

### `ModuleTestCapsule`

```yaml
ModuleTestCapsule:
  shape_checks:
  unit_property_model_tests:
  parser_or_golden_corpus:
  fake_port_contract_tests:
  real_edge_profiles:
  fault_restart_replay_cases:
  resource_and_serial_groups:
  proof_level_ceiling:
  known_uncovered_behavior:
  expected_nonzero_test_count:
```

Capsules are generated from Cargo, test, and instrument metadata and supplemented only with non-derivable semantic fields. A crate or cell without an executable `ModuleTestCapsule` may be investigated, but is not independently supported.

### Generated local agent surfaces

Each independently planned crate/module exposes two concise **resource projections** generated from the same contract source:

```text
Contract projection
  purpose, owned state/effects, public invariants, dependency ports,
  compatibility, proof ceiling and promotion/replacement boundary;

Agent-working projection
  one-screen instructions: how to check the unit, exact profile commands,
  prohibited shortcuts, relevant handles and escalation route.
```

The normal surface is a resource/handle compiled into the Agent Workset. `CONTRACT.md` and `AGENTS.md` are optional materializations only for host tools that require local files; ELIOT does not create two files per crate by default. Projections are not separate normative sources. They carry the source contract digest and generator version; stale projections are rejected. Handwritten rationale belongs in Architecture/Implementation records, while commands/test inventory are generated from Cargo and Instrument metadata.

The triad `ModuleContractKit` + `CrateContextCapsule` + `ModuleTestCapsule` is mandatory, not advisory. A capability missing any element cannot have `ImplementationSupport` above `CURRENT_UNVERIFIED`, regardless of code quality or test count: without a contract kit the boundary is undefined; without a context capsule the agent lacks a decision-sufficient workset; without a test capsule there is no independently invocable proof. This directly violates `ARCH-MOD-03`.

---

## Required item `docs/architecture/I02-21-crate-and-boundary-validation.md`

SHA-256: `f727b6627cf6151321e0b962c34f636b8b8df923abdf790c7b0cdeb84ef26002`; bytes: `1549`; handles=I2.21.

## I2.21. Crate and boundary validation

`eliot dev crate validate` checks:

```text
layer direction and cycles;
public vendor-type leakage;
missing purpose/owner/test selector;
source and Agent Workset budgets;
public contract digest;
FunctionalCapabilityCell coverage and one lifecycle owner per mutable state;
generated EffectiveMicroModuleManifest freshness and catalogue digest;
replacement class, iteration lane and ProofLatencyProfile for automatic scheduling;
reverse-dependency fan-out;
forbidden dependency islands in hot/core crates;
crate-to-runtime-bundle mapping;
state/effect owner uniqueness;
required edge profiles;
zero-test selection;
forbidden direct process/store calls;
Cargo feature duplication and profile drift.
```

Validation returns evidence and a recommendation. It does not declare the Architecture correct merely because the dependency graph is clean.

### `CrateScaleReview`

Review starts on any of:

```text
physical review/high-review band on the applicable profile;
Agent Workset upper review band or absence of a qualified complete envelope;
high compile critical-path cost;
high reverse-dependency fan-out × change frequency;
two independent fixture or test families;
repeated defect escape across the crate boundary;
systematic co-change with a neighboring crate;
the appearance of a second causal responsibility.
```

Outcome:

```text
keep;
split;
merge;
extract contract;
move heavy dependency to adapter/workspace;
create thin facade;
mark migration legacy with expiry;
run experiment before change.
```

---

## Required item `docs/architecture/I02-22-parallel-build-cache-artifact-and-environment-lanes.md`

SHA-256: `8cc78b566defb73be543c873648e0639694986510b32a25353c6e1cdebe92d4e`; bytes: `2620`; handles=I2.22.

## I2.22. Parallel build, cache, artifact and environment lanes

Each mutating work item receives:

```text
worktree;
BuildFingerprint;
target/build mode;
fixture namespace;
runtime environment lease;
resource claims;
contract revision;
candidate identity.
```

### Target roots

```text
%LOCALAPPDATA%\Eliot\build\<workspace-id>\<worktree-id>\<build-mode>\<fingerprint>
```

Governed instruments do not use the repository `target/` directory by default.

### Cache modes

```text
interactive incremental
  separate worktree target; best repeated feedback within one lane;

shared non-incremental + sccache
  reuse across agents and worktrees under an exact normalized fingerprint;

release
  locked and declared cache; proof depends on source, tool, and run identity,
  not on the fact of a cache hit.
```

Incremental compilation and sccache are not enabled together as a universal magic optimization. Instrument Plane measures hit rate, cold and warm time, cache size, and invalidation.

### Derived-cache trust and reuse

Any reuse of a derived cache or artifact is bound to exact dependency closure:

```text
source and generated-input digests;
toolchain/compiler/parser/runtime versions;
configuration, features and environment fingerprint;
producer identity and generation;
cache root identity, owner/ACL and reparse/symlink disposition;
format/schema revision;
content integrity digest;
```

Rules:

```text
checksum detects corruption but does not authenticate producer or root;
missing, unreadable, untrusted or mismatched cache is a cache miss, not a correctness failure;
no correctness path depends on cache availability;
a result derived from one observed subset cannot overwrite a broader valid cache union
unless the cache contract declares replacement semantics;
partial cache load preserves known-good entries and records rejected/corrupt entries;
restore or copy never upgrades cache authority without requalification;
cache hit carries artifact lineage but never reuses an old test/verifier verdict.
```

The cache layer is rebuildable and may improve performance only after equality checks against the uncached reference path.

### Test concurrency

Test groups declare resource weight and exclusive resources. Nextest partitioning and filtersets distribute independent tests across lanes; stateful ports, services, and database volumes receive separate leases. A worktree does not isolate runtime resources.

Verification has priority over background indexing, coverage, mutation, and Dreamer jobs. A background build cannot displace Kernel, Watchdog, Control Reserve, or interactive product work.

---

## Required item `docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`

SHA-256: `e003d8e17b414ee0715028d7d3997d1b109c18df20ad0294ae2856d3e21e4e49`; bytes: `6889`; handles=I2.23.

## I2.23. Capability-family topology and crate extraction decisions

Implementation fixes responsibility families, not a target count or frozen list of crate names. The current families are:

```text
foundation and public contracts;
Host, Kernel and platform lifecycle;
Governor task, authority and canonical transitions;
store, blob, export, migration and recovery;
Instrument/test execution and evidence normalization;
memory, context, understanding and derived projections;
Watchdog, Doctor, Dreamer and Meta;
agent routes, coordination and bounded swarm;
human/agent surfaces and optional domain/vendor/research contours.
```

Root `default-members` contains only primary binaries, contracts, Kernel/Governor core, primary store path, Instrument Plane baseline, the first agent route and short local proofs. Vendor bridges, coverage/mutation/fuzz, heavy code-index pilots, cloud/AWS, Researcher providers, professional modules, benchmark corpora and experimental actor/WASM/distributed routes remain outside the root default command unless a current work profile needs them.

### Crate admission and merge criteria

A separate crate is preferred only when an executable contract/test/context seam exists and an explicit `CrateExtractionDecision` predicts net benefit. Strong admission grounds are:

```text
independent public or inter-layer contract;
independent unit/property/model-test seam;
separate owner or bounded agent work item;
different dependency, security or license profile;
materially different change cadence;
multiple real consumers;
heavy optional dependency island;
measurable context/rebuild blast-radius reduction;
replaceable implementation boundary;
own pure state machine or causal responsibility.
```

The expected agent seam is concrete: a bounded route can read the capability with its contract/tests, change one causal responsibility, run package-local proof, see one-hop consumers/providers and avoid loading unrelated subsystems.

The following normally remains an ordinary Rust module:

```text
private helper without an independent contract;
small type group used by one parent;
implementation always changed and tested with its owner;
file split only for navigation;
algorithm fragment without an independent reason to change.
```

Crates should merge when most of these conditions hold:

```text
they almost always change in one work unit;
no independent consumer or test selector exists;
one is a pass-through of the other;
manifest/API overhead exceeds context savings;
private mutable state is repeatedly threaded across the boundary;
the split creates cyclic adapter/facade construction;
there is no measured build, fault, dependency or agent blast-radius benefit.
```

Crate-per-file and crate-per-type are prohibited proxy goals. A new package without a real consumer/test seam is rejected unless it is a time-bounded migration facade with an owner, expiry and removal test.

### Canonical extraction decision

```yaml
CrateExtractionDecision:
  affected_functional_cells_and_lifecycle_owners:
  current_source_dependency_and_change_closure:
  proposed_package_boundary:
  public_contract_and_independent_test_entrypoint:
  first_real_consumer_or_time_bounded_migration_facade:
  source_maintenance_owner_and_vendor_type_boundary:
  dependency_security_license_and_build_isolation:
  expected_agent_workset_context_and_reverse_fanout_delta:
  expected_compile_test_integration_and_release_cost_delta:
  migration_reexport_rollback_removal_and_expiry:
  counter_risks_merge_or_rejoin_condition:
  evidence_status_and_review_owner:
  disposition: keep | split | merge | extract_contract | isolate_dependency | experiment
```

A proposed name or presence in a research document is not an implementation task. Historical names and extraction hypotheses live in the external cold backlog until a measured change closure activates them.

### Workspace and fleet evidence

`WorkspaceScaleProfile` is an empirical vector over the actual workspace; it has no universal `small/medium/large` package-count threshold:

```yaml
WorkspaceScaleProfile:
  package_target_feature_and_build_script_counts:
  metadata_and_rust_analyzer_load:
  clean_incremental_and_package_selective_build_distributions:
  reverse_fanout_and_typical_change_closure:
  test_inventory_and_sharding_cost:
  shared_target_cache_and_io_contention:
  parallel_agent_throughput_and_merge_cost:
  manifest_contract_and_orientation_burden:
  validity_scope_expiry_and_countermetrics:
```

Generated `CrateFleetReport` adds source/context footprint, public API surface, change/co-change frequency, reverse fan-out, cold/warm compile and critical-path time, test discovery/execution cost, dependency/feature weight, defect attribution, agent success/repair escapes and runtime-bundle mapping. Its `ContractSurfaceProfile` records applicable contracts/owners, agent-visible contract tokens, one-hop edges, generated/manual duplication, proof latency, Product Pulse dependency and wrong-owner incidents.

`WorkspaceScaleReview` opens when package-selective work repeatedly reaches a wide closure, metadata/rust-analyzer latency blocks interactive work, target/cache contention appears, feature unification causes incompatible rebuilds, typical changes cross many owners, or added parallel lanes no longer improve throughput.

A scalar may sort candidates but cannot authorize split or merge. A split is rejected when it reduces source size while increasing contract surface, ceremony or wrong-owner rate. A merge is rejected when it removes independent proof or replacement. Topology changes are admitted only when context/build/test/ownership outcomes improve without material regression in Product Pulse, dependency clarity, recovery or agent correctness.

### Capability cell registry

`FunctionalCapabilityCell` is enumerable, not only referenced. A generated `CapabilityCellRegistry` is compiled from `[package.metadata.eliot].functional_cell_refs`, Module/service manifests and the contract catalogue:

```text
cell id and revision;
one-line causal responsibility;
owns: contract surface, mutable state or explicit statelessness, effects;
must not own: explicit non-responsibilities;
runtime layer and execution contour;
replacement class and iteration lane;
independently invokable proof entrypoint;
one-hop providers and consumers;
current support and invalidation set.
```

The registry is the answer to “how many cells exist and who owns what” without reading this chapter. It is generated: prose never maintains a parallel list. A cell without a proof entrypoint, with an undeclared state owner or with a second owner for the same mutable state is a registry defect, not an acceptable variant.

A crate may host several cells and one cohesive cell may span several crates; the registry keeps both mappings explicit so source packaging and causal ownership never silently merge.

---

## Required item `docs/architecture/I17-development-sequence.md`

SHA-256: `bce8bda02a5f57e7f1b11f4a037cc5481d6bc2615d1521e072f632f5b4c67b63`; bytes: `29`; handles=I17.

# I17. Development sequence

---

## Required item `docs/architecture/I18-testing-and-instrumental-grounding-strategy.md`

SHA-256: `facd29dfe4a6fdb98a70f5a5decb7d960f8ca95419924828a44596c57940fb10`; bytes: `52`; handles=I18.

# I18. Testing and Instrumental Grounding strategy
