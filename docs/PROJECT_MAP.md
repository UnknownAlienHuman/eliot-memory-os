# ELIOT Memory OS project map

Status: current routing map for `main`, 2026-08-28. This file is navigation,
not acceptance evidence. Product status remains `NOT_ACCEPTED / UNVERIFIED`.

## Authority and work routing

| Question | Source |
|---|---|
| Current code and documentation | `main` |
| Repository work rules | `AGENTS.md`, `WORKFLOW.md` |
| Active workstreams/exceptional branches | `workstreams/ACTIVE.toml` |
| Architecture authority | `docs/ARCHITECTURE_CONTRACT.md` |
| Exact normative identity | `docs/normative-pair.toml` |
| Current implementation work | owning GitHub issue and PR |
| Live Windows operational-spine proof | issue #11 |

A branch is not a documentation edition or a durable project state. New work
starts from current `main` in a fresh issue-numbered branch. Historical reports,
donor research, recovery programmes, and generated/local state are not present
in the active checkout.

## Repository shape

| Area | Paths | Responsibility |
|---|---|---|
| Foundation | `crates/foundation/*` | contracts, protocol, evidence, receipts, security/runtime types |
| Governor | `crates/governor/*`, `crates/eliot-app`, `crates/eliot-engine` | semantic admission, tasks, WorkScopes, plans, coordination, finish |
| Kernel/Host | `crates/kernel/*` | installation, Host journal, IPC, ORS, authority/fencing, process lifecycle |
| Storage | `crates/storage/*`, `crates/eliot-store` | store-neutral API, Surreal bridge, BlobStore, export/backup |
| Agent fabric | `crates/agent/*` | agent route and coordination contracts/adapters |
| Smart/research/security | `crates/smart/*`, `crates/research/*`, `crates/security/*` | understanding, context, memory, Dreamer/Researcher candidates, influence/privacy |
| Instrument/meta/supervision | `crates/instrument/*`, `crates/meta/*`, `crates/supervision/*` | process/test instruments, verification, runtime status, Watchdog/Doctor cores |
| Surfaces/modules | `crates/surfaces/*`, `crates/modules/*` | CLI/MCP/skills, User Broker, native/WASM boundaries |
| Composition roots | `bins/*`, `workspace/tools/*` | runtime executables and bounded tools |
| Canonical docs | `docs/architecture/*`, `docs/ARCHITECTURE_CONTRACT.md` | accepted pair and navigation |
| Active work routing | `workstreams/*` | bounded briefs and machine-readable active status |

A crate is a source/build boundary, not a lifecycle or authority owner.

## Runtime composition roots

| Executable/capability | Intended role | Primary work item |
|---|---|---|
| `eliot.exe` | one-shot operator/agent CLI | issue #11 / applicable surface issue |
| `eliot-host.exe` | external lifecycle and recovery boundary | #14 |
| `eliot-kernel.exe` | identity, fencing, ORS, Control Reserve, generation routing | #15 |
| `eliotd.exe` | Governor semantic application daemon | #18 |
| `eliot-watchdog.exe` | independent SCM supervision | #16 |
| `eliot-doctor.exe` | bounded one-shot repair executor | #17 |
| `eliot-store-surreal.exe` | closed store bridge and Surreal credential boundary | #19, #7–#9 |
| Host-managed `surreal.exe` | sole canonical DB-file process owner | #19 |
| BlobStore | single active blob-root owner | #19 |
| `eliot-testd.exe` | isolated typed Instrument execution plane | #20 |
| `eliot-wasm-host.exe` | capability-limited component host | #21 |
| `eliot-native-worker-*` | isolated OS-heavy native generation | #22 |
| `eliot-user-broker.exe` | interactive-user launch/resource boundary | #23 |
| `eliot-notify.exe` | stateless notification adapter | #13 |
| `eliot-agent-bridge.exe` | near-stateless agent protocol shim | #13 |
| `eliot-mod-research` | Researcher provider execution boundary | #24 |

Dreamer work is deliberately excluded from the core/daemon workstream and is
owned separately.

## Canonical transition path

```text
proposal/observation
→ eliotd semantic admission and immutable PreparedTransition
→ Kernel identity/authority/fence/order/generation validation
→ closed named store transaction
→ immutable receipt/outbox
→ reconciliation and affected projection publication
```

No report, branch, Module, Doctor, Watchdog, Dreamer, provider, or recovery
spool creates a second semantic write path.

## Mutable-state owners

| State | Intended owner |
|---|---|
| installation approval, Host activation, managed dependency lineage | Host / `HostStateJournal` |
| Authority Epochs, ORS, Generation Registry, active session/broker bindings | Kernel |
| tasks, plans, semantic admission, Module Catalog, finish | logical Governor / canonical store |
| canonical DB files and transaction execution | Host-managed Surreal generation through store bridge |
| blob bytes/reachability/GC | one active BlobStore owner |
| Watchdog signal spool/anchors | Watchdog, non-semantic |
| user-session process tree and broker epoch | User Broker; active registration in ORS |
| derived indexes/caches | owning replaceable Module generation |
| UI-local transient state | Human surface only |

The executable projection of this table is tracked by #13. This prose cannot
create authority by itself.

## Active implementation programmes

- Core/daemon issues #13–#24:
  `workstreams/core-daemons/AGENTS.md`.
- Existing cognitive candidate PR #26:
  retained on `cognitive-micromodules-wave-01`, but marked non-mutable until it
  is refreshed from current `main`.

There is no shared long-lived core/daemon branch. Each issue starts a fresh
branch when an agent is assigned.

## Evidence boundary

Source shape and compilation are not live runtime proof. Current support is
established only by exact source/build/runtime/store evidence and the applicable
Product Pulse. Issue #11 remains the integration owner for the live Windows
service tree, canonical store, restart/fencing/supervision, and D0/D1 operational
spine. No committed dated audit substitutes for that issue and its executed
evidence.
