# ELIOT Memory OS project map

Status of this routing map: 2026-08-28.

Repository head used for the current inventory:
`7d7f03259cc3d3d90b2fe1af7a6175b13808ece2`.

The last audited product-source baseline remains
`f63675ba0539aca21e813fe9ba2c0076e1badb1f`; later graph/documentation commits
do not by themselves change the product bytes or prove a live installation.

This is a routing map, not an acceptance record. Current source, `Cargo.toml`,
`Cargo.lock`, Cargo diagnostics, installed artifact identities, and live machine
readback outrank this file. Product status remains `NOT_ACCEPTED / UNVERIFIED`.

The accepted architecture authority is defined by
[`docs/ARCHITECTURE_CONTRACT.md`](ARCHITECTURE_CONTRACT.md) and the
machine-bindable [`docs/normative-pair.toml`](normative-pair.toml):

- [ELIOT Architecture](architecture/ELIOT_ARCHITECTURE.md), revision
  `4.5-draft`, English edition `2026-08-28`, SHA-256
  `C6932EAF26935E752EEFB4DE591AFC91EA1A7180BE5A8FF0005554B8029BAC1A`;
- [ELIOT Implementation](architecture/ELIOT_IMPLEMENTATION.md), revision
  `0.29-draft`, English edition `2026-08-28`, SHA-256
  `7805BF238FE91819ABA50D7E13AA86A8B977561195DBB98AA979F986E2FAB063`.

The dated English-final filenames in `docs/architecture/` are byte-identical
publication aliases. The predecessor pair and `docs/normative/` projection
remain historical evidence; predecessor-bound generated artefacts are `STALE`
for current authority until regenerated against the accepted pair.

## Workspace shape

`cargo metadata --no-deps --format-version 1` reports 126 workspace members,
with default runtime members `eliot`, `eliot-host`, `eliot-kernel`,
`eliot-store-surreal`, `eliot-watchdog`, and `eliotd`. The workspace is Rust
2024/MSVC. The workspace manifest declares `rust-version = "1.94"` while
`rust-toolchain.toml` selects `1.97.1`.

| Plane | Source groups | Responsibility |
|---|---|---|
| Foundation | `crates/foundation/*` | contracts, protocols, evidence, receipts, rules, runtime and security types |
| Governor | `crates/governor/*`, `crates/eliot-app`, `crates/eliot-engine` | authority, task/session/WorkScope, coordination, canonical Governor behavior |
| Kernel | `crates/kernel/*` | Host state, IPC, Kernel lifecycle, ORS, installation, Windows/process boundaries |
| Storage | `crates/storage/*`, `crates/eliot-store` | store API, Surreal adapter, blobs, backup and ECXF |
| Agent fabric | `crates/agent/*` | agent APIs, route adapters, coordination and swarm contracts |
| Smart/research/security | `crates/smart/*`, `crates/research/*`, `crates/security/*` | understanding, memory/curation, research exchange and influence/privacy controls |
| Instrument/meta/supervision | `crates/instrument/*`, `crates/meta/*`, `crates/supervision/*` | instruments, diagnostics, verification, runtime status, Watchdog and repair cores |
| Surfaces/modules | `crates/surfaces/*`, `crates/modules/*` | CLI/MCP/skills, User Broker, native worker and WASM boundaries |
| Composition roots | `bins/*`, `workspace/tools/*` | operator/runtime executables and bounded proof tools |

A crate is a source/build boundary, not a runtime or authority owner.

## Core and daemon conformance inventory

Machine-readable inventory:
[`swarm/inventory/core-daemons.json`](../swarm/inventory/core-daemons.json).

Agent work-unit rules:
[`swarm/briefs/core-daemons/AGENTS.md`](../swarm/briefs/core-daemons/AGENTS.md).

This inventory is `SOURCE_INVENTORY_ONLY`; every runtime row is
`NOT_EXECUTED` until exact installed/runtime evidence exists. Dreamer is excluded
because it is owned by a separate workstream. The inventory's original
document-authority finding records the pre-adoption state; current authority is
the receipt above.

| Process/capability | Source disposition | Primary work item |
|---|---|---|
| Host | `PARTIAL`; required crates exist, but composition/lifecycle/state/test boundaries need a thin-Host proof | [#14](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/14) |
| Kernel | `PARTIAL`; Recovery View, Control Reserve and Generation Registry concepts exist, but the small-Kernel/fencing/recovery boundary is unproven | [#15](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/15) |
| `eliotd` | `CURRENT_UNVERIFIED`; comparatively thin, but semantic admission/PreparedTransition/strict finish ownership needs proof | [#18](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/18) |
| Watchdog | `PARTIAL`; deterministic core exists, spool/SCM/containment/reconciliation cells need closure | [#16](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/16) |
| Doctor | `CURRENT_UNVERIFIED`; thin process/core exist, bounded recipe identities, verifier and no-direct-write proof remain | [#17](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/17) |
| Store bridge | `PARTIAL`; substantial source/tests exist, named-operation/effect-ceiling/crash/idempotency/generation proof remains | [#19](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/19), [#7–#9](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/7) |
| BlobStore | `CURRENT_UNVERIFIED`; API/core exist, single active root owner, GC, residency, key and cutover proof remain | [#19](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/19) |
| `surreal.exe` dependency | `TARGET`; installation identity, exclusive data-root ownership and live readiness are not observed | [#19](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/19), [#11](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/11) |
| testd | `PARTIAL`; substantial implementation exists, but it must remain only the isolated typed Instrument execution plane | [#20](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/20) |
| WASM host | `PARTIAL`; host exists, capability introductions, ambient-access denial and immutable shadow/canary generations need closure | [#21](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/21) |
| native worker | `CURRENT_UNVERIFIED`; relatively bounded source, exact artifact/facet/epoch/resource/process proof remains | [#22](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/22) |
| User Broker | `CURRENT_UNVERIFIED`; SID/session/broker epoch, credentials/resources, logoff and no-generic-shell proof remain | [#23](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/23) |
| Researcher process module | `PARTIAL`; candidate-only shape is correct, but ambient env-selected direct process launch bypasses the governed process contour | [#24](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/24) |
| notify | `CURRENT_UNVERIFIED`, keep and bind; thin notification-only source, no separate rewrite justified | [#13](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/13) |
| agent bridge | `CURRENT_UNVERIFIED`, keep and bind; thin near-stateless source, no separate rewrite justified | [#13](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/13) |

Cross-cutting owner/proof metadata is tracked by
[#13](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/13). The live
D0/D1 Windows operational spine and Product Pulse remain owned by
[#11](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/11).

No empty crates were created by this inventory. Every audited capability already
has a source owner. A new crate is admissible only after a real
`CrateExtractionDecision` proves an independent consumer, contract/test/context
seam, migration/removal path, and expected net benefit. Concept-named scaffolds
would currently risk a second owner and violate the one-owner rule.

## Runtime composition roots

| Executable | Source | Intended role |
|---|---|---|
| `eliot.exe` | `bins/eliot` | canonical one-shot operator CLI and runtime-status/canary front door |
| `eliot-host.exe` | `bins/eliot-host` | external Host lifecycle/recovery boundary |
| `eliot-kernel.exe` | `bins/eliot-kernel` | failure-surviving Governor boundary: identity, fencing, ORS, reserve and generation routing |
| `eliot-store-surreal.exe` | `bins/eliot-store-surreal` | closed store bridge and sole Surreal SDK/credential boundary |
| `eliot-watchdog.exe` | `bins/eliot-watchdog` | independent SCM supervision service |
| `eliotd.exe` | `bins/eliotd` | Governor semantic application daemon |
| `eliot-doctor.exe` | `bins/eliot-doctor` | one-shot bounded repair executor |
| `eliot-testd.exe` | `bins/eliot-testd` | isolated typed Instrument execution plane |
| `eliot-wasm-host.exe` | `bins/eliot-wasm-host` | capability-limited component generation host |
| `eliot-native-worker.exe` | `bins/eliot-native-worker` | isolated OS-heavy native generation |
| `eliot-user-broker.exe` | `bins/eliot-user-broker` | authenticated interactive-user launch/resource boundary |
| `eliot-notify.exe` | `bins/eliot-notify` | one-shot notification adapter only |
| `eliot-agent-bridge.exe` | `bins/eliot-agent-bridge` | near-stateless agent/stdio protocol shim |
| `eliot-mod-research` | `bins/eliot-mod-research` | Researcher acquisition/provider exchange process |
| `eliot-live-canary.exe` | `workspace/tools/eliot-live-canary` | bounded Product Pulse; invoked through `eliot runtime canary` |
| `eliot-runtime-status` | `crates/meta/eliot-runtime-status` | read-only fail-closed runtime evidence projection |

Presence in Cargo metadata is not evidence that an executable is installed,
admitted, running, healthy, or current.

## Runtime control and data flow

```text
canonical pair / task / policy
        |
        v
release builder -> signed immutable bundle + manifests + hashes
        |
        v
installation transaction -> protected roots/ACLs -> approved generations
        |
        +------------------------------+
        |                              |
        v                              v
Host SCM service                 Watchdog SCM service
        |
        +-> Kernel lineage -> store bridge -> Host-managed surreal.exe
        |        |
        |        +-> eliotd and replaceable/on-demand generations
        |
        +-> HostStateJournal / managed dependency lineage

Kernel front door + ORS/fencing
        |
        v
eliotd semantic admission -> PreparedTransition
        |
        v
Kernel mechanical validation/order/stage
        |
        v
closed named store transaction -> receipt/outbox -> reconciliation

runtime-status -> `eliot runtime status --json`
eliot-live-canary -> bounded D0/D1 Product Pulse
```

Host, Kernel, canonical-store, Watchdog, User Broker, BlobStore, and Module
mutable-state roots must remain distinct and have exactly one writer. Runtime
control arrows do not transfer semantic/source ownership.

## Runtime ownership map

| State/capability | Intended owner |
|---|---|
| Installation transaction and Host artifact approval | installer/Host through `eliot-installation` and `HostStateJournal` |
| Host activation and managed dependency process lineage | Host only |
| Authority Epochs, ORS, Generation Registry, active Session/User Broker bindings | Kernel only |
| WorkScopes, tasks, plans, semantic admission, Module Catalog, finish | logical Governor / `eliotd` + canonical store |
| Canonical DB files and transaction execution | Host-managed `surreal.exe` through the closed store bridge |
| Blob bytes/reachability/GC | one active BlobStore owner |
| Watchdog signals/spool/anchors | Watchdog only; non-semantic and reconciled through Governor |
| User-session process tree and launch epoch | User Broker; ORS holds the active registration |
| Derived graphs/indexes/caches | owning replaceable Module generation |
| UI-local transient state | Human surface only; never task truth |

The generated `CapabilityCellRegistry` and `EffectiveMicroModuleManifest` must
become the executable projection of these boundaries under #13. This table is
routing evidence only.

## Release and installation boundaries

The supported release scripts are
`scripts/build-eliot-windows-x64-release.ps1`,
`scripts/finalize-eliot-windows-x64-release.ps1`, and
`scripts/invoke-eliot-windows-x64-production.ps1`.

The builder stages an unsigned bundle. The finalizer signs and independently
verifies the declared PE roles. The Rust materializer owns the exact Phase-A
handoff and does not turn static release readback into installation authority.

`eliot-installation` is the authority for profile validation, immutable plan,
transaction persistence, root/ACL effects, package staging,
approved-generation registry and SCM approval. Host startup may inspect an
installed sibling service; it is not the installer and must not register itself
on every start.

## Current proof boundary

Source and signed-artifact evidence are recorded in
[`reports/audit/RUNTIME_LIVE_V3_STATUS_2026-08-24.md`](../reports/audit/RUNTIME_LIVE_V3_STATUS_2026-08-24.md).
That evidence does not establish that the Windows installation, canonical store,
service tree, fencing, restart, supervision, or D0/D1 Product Pulse is live.

The exact live-runtime owner remains
[#11](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/11). Until it
produces current executed evidence, all core/daemon support in this map remains
`TARGET`, `PARTIAL`, or `CURRENT_UNVERIFIED`; none is `CURRENT_VERIFIED`.
