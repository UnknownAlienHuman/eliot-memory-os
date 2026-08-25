# ELIOT Memory OS project map

Status of this map: 2026-08-24, audited product-source baseline
`f63675ba0539aca21e813fe9ba2c0076e1badb1f`. Subsequent graph/docs-only
commits do not change the product bytes described here.

This is a routing map, not an acceptance record. Current source, `Cargo.toml`,
`Cargo.lock`, Cargo diagnostics, and live machine readback outrank this file.
The normative architecture sources are the external pair routed by
[`docs/ARCHITECTURE_CONTRACT.md`](ARCHITECTURE_CONTRACT.md) and the Runtime Live
V3 task document. The persistent CodeCortex snapshot currently reports 54,134
nodes and 268,208 edges; it is useful for navigation only and may lag source.

## Workspace shape

`cargo metadata --no-deps --format-version 1` at this revision reports 125
workspace members, all version `0.1.0`, with the default runtime members
`eliot`, `eliot-host`, `eliot-kernel`, `eliot-store-surreal`, `eliot-watchdog`,
and `eliotd`. The workspace is Rust 2024 and MSVC; the workspace manifest
declares `rust-version = "1.94"`, while the checked-in `rust-toolchain.toml`
selects channel `1.97.1`. Cargo output is redirected by the developer
configuration to the ELIOT build root, not a repository `target/`.

The source is organised into these planes:

| Plane | Source groups | Responsibility |
|---|---|---|
| Foundation | `crates/foundation/*` | contracts, protocols, evidence, receipts, rules, runtime and security types |
| Governor | `crates/governor/*`, `crates/eliot-app`, `crates/eliot-engine` | authority, task/session/workscope, coordination, canonical governor and application behavior |
| Kernel | `crates/kernel/*` | Host state, IPC, Kernel lifecycle, installation, Windows effects, process and runtime boundaries |
| Storage | `crates/storage/*`, `crates/eliot-store` | store API, memory store, Surreal adapter, blobs, backup and ECXF |
| Agent fabric | `crates/agent/*` | agent APIs, ACP/Codex/OpenCode adapters, coordination and swarm contracts |
| Smart/research/security | `crates/smart/*`, `crates/research/*`, `crates/security/*` | understanding, memory/curation, dreamer, research exchange and source/erasure/influence controls |
| Instrument/meta | `crates/instrument/*`, `crates/meta/*` | code graph, diagnostics, process execution, reports, verification, test selection and runtime-status projection |
| Surfaces/modules | `crates/surfaces/*`, `crates/modules/*` | CLI/MCP/skills/user broker, native worker and WASM boundaries |
| Composition roots | `bins/*`, `workspace/tools/*` | operator/runtime executables and bounded tools |

## Runtime composition roots

| Executable | Source | Role |
|---|---|---|
| `eliot.exe` | `bins/eliot/src/main.rs` plus `source_bundle_materializer.rs` | canonical operator CLI; installation plan/apply/status and manifest-bound runtime canary entrypoints |
| `eliot-host.exe` | `bins/eliot-host/src/main.rs` | Host lifecycle, durable activation and operational-state composition |
| `eliot-kernel.exe` | `bins/eliot-kernel/src/main.rs` | Kernel composition root and lifecycle/IPC entrypoint |
| `eliot-store-surreal.exe` | `bins/eliot-store-surreal/src/main.rs` | canonical SurrealDB store process and provider boundary |
| `eliot-watchdog.exe` | `bins/eliot-watchdog/src/main.rs` | sibling SCM watchdog and bounded Host/Kernel/Store observation |
| `eliotd.exe` | `bins/eliotd/src/main.rs` | production daemon composition root and governed work submission |
| `eliot-live-canary.exe` | `workspace/tools/eliot-live-canary/src/{main.rs,lib.rs}` | bounded Pulses 1–5 verifier; production invocation is through `eliot runtime canary` |
| `eliot-runtime-status` | `crates/meta/eliot-runtime-status/src/lib.rs` | read-only fail-closed projection of registry, journal, ORS, publication and process/service evidence |

Other workspace roots include `eliot-doctor`, `eliot-dreamer`,
`eliot-native-worker`, `eliot-notify`, `eliot-testd`, `eliot-user-broker`,
`eliot-wasm-host`, `eliot-mod-research`, `eliot-agent-bridge`, and the
runtime/compiler/campaign tools. Their presence in metadata is not evidence
that they are installed or live in the current machine.

## Runtime control and data flow

```text
canonical docs/task
        |
        v
release builder -> signed bundle + manifests + hashes + public VerifyBundle
        |
        v
eliot source-bundle materializer (exact nine Phase-A roles)
        |
        v
eliot-installation planner -> immutable plan + Redb transaction/evidence
        |
        v
elevated Apply -> protected roots/ACLs -> ApprovedGenerationRegistry
        |                                      |
        |                                      +-> EliotHost SCM service
        |                                      +-> EliotWatchdog SCM service
        v
HostStateJournal -> Kernel activation/ProbeReady -> eliotd submission
                                      |
                                      +-> Store launch -> surreal.exe loopback endpoint
                                      +-> Host/Kernel/Store process and Job observations
        |
        v
runtime-status (read-only) -> `eliot runtime status --json`
        |
        v
`eliot runtime canary` -> Pulses 1..5 -> protected marker-last evidence
```

The intended SystemService roots are immutable packages under
`%ProgramData%\Eliot\packages\<generation>` and a durable installation root
under `%ProgramData%\Eliot\installations\<installation-key>`. Host, Kernel,
Store and Watchdog state roots are distinct and are digest-bound by the launch
descriptor. Store working, data and temporary roots must remain distinct from
Kernel roots; the Store receives an explicit working directory and database
path rather than current-directory or environment fallback.

## Runtime ownership map

| Contract | Canonical implementation |
|---|---|
| Installation transaction, profiles, plan/apply/recover, registry | `crates/kernel/eliot-installation` |
| Windows protected paths, ACLs, SCM and process/Job observations | `crates/kernel/eliot-platform-windows` and `crates/eliot-windows-ipc` |
| Host journal and epoch/nonce state machine | `crates/kernel/eliot-host-state` |
| Host service/control boundary | `crates/kernel/eliot-host-service`, `bins/eliot-host` |
| Kernel activation, readiness and supervision | `crates/kernel/eliot-kernel-service`, `crates/kernel/eliot-kernel-core`, `bins/eliot-kernel` |
| Store-neutral API and Surreal provider | `crates/storage/eliot-store-api`, `crates/storage/eliot-store-surreal-adapter`, `bins/eliot-store-surreal` |
| Daemon semantic submission | `bins/eliotd`, `crates/governor/eliot-governor`, `crates/governor/eliot-maintenance` |
| Watchdog admission and bounded observation | `crates/supervision/eliot-watchdog-core`, `bins/eliot-watchdog` |
| Runtime status | `crates/meta/eliot-runtime-status` and the `eliot` CLI |
| Canary | `workspace/tools/eliot-live-canary`, routed by `bins/eliot` |

## Release and installation boundaries

The supported release scripts are `scripts/build-eliot-windows-x64-release.ps1`,
`scripts/finalize-eliot-windows-x64-release.ps1`, and
`scripts/invoke-eliot-windows-x64-production.ps1`. The builder stages an
unsigned bundle. The finalizer signs and independently verifies seven PE
roles: six runtime materializer roles plus the install-authoritative CLI. The
Rust materializer then owns the exact nine-role Phase-A handoff and does not
turn a static release readback into installation authority by itself.

`eliot-installation` is the authority for profile validation, immutable plan,
transaction persistence, root/ACL effects, package staging, approved-generation
registry and SCM approval. Host startup may inspect an installed sibling
service; it is not the installer and must not register itself on every start.

## Current verified boundary at f636

Verified source/build facts are recorded in
[`reports/audit/RUNTIME_LIVE_V3_STATUS_2026-08-24.md`](../reports/audit/RUNTIME_LIVE_V3_STATUS_2026-08-24.md).
That report is deliberately explicit about the boundary: source and signed
artifact proof exist, but there is no claim that the Windows installation or
runtime is live.
