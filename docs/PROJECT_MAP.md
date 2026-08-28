# ELIOT Memory OS project map

Status: current routing map for `main`, 2026-08-28. Navigation only; product
status remains `NOT_ACCEPTED / UNVERIFIED`.

## Authority and work

| Question | Source |
|---|---|
| Current code and documentation | `main` |
| Repository workflow | `AGENTS.md`, `WORKFLOW.md` |
| Active programmes and branch exceptions | `workstreams/ACTIVE.toml` |
| Architecture authority and pair identity | `docs/ARCHITECTURE_CONTRACT.md`, `docs/normative-pair.toml` |
| Current implementation change | owning open issue and PR |
| Live Windows operational-spine proof | issue #11 |

Branches are disposable execution state, not documentation editions. Ordinary
work starts from current `main` in a fresh issue-numbered branch. Historical
reports, donor research, recovery programmes, and local/generated state are not
present in the active checkout.

## Repository planes

| Plane | Paths | Responsibility |
|---|---|---|
| Foundation | `crates/foundation/*` | contracts, protocols, evidence, receipts, security/runtime types |
| Governor | `crates/governor/*`, `crates/eliot-app`, `crates/eliot-engine` | semantic admission, tasks, WorkScopes, coordination, finish |
| Kernel/Host | `crates/kernel/*` | installation, Host journal, IPC, ORS, authority/fencing, process lifecycle |
| Storage | `crates/storage/*`, `crates/eliot-store` | store API, Surreal bridge, BlobStore, export/backup |
| Agent fabric | `crates/agent/*` | agent routes and coordination contracts/adapters |
| Smart/research/security | `crates/smart/*`, `crates/research/*`, `crates/security/*` | context, memory, understanding, Dreamer/Researcher candidates, privacy/influence |
| Instrument/meta/supervision | `crates/instrument/*`, `crates/meta/*`, `crates/supervision/*` | instruments, verification, runtime status, Watchdog/Doctor cores |
| Surfaces/modules | `crates/surfaces/*`, `crates/modules/*` | CLI/MCP/skills, User Broker, native/WASM boundaries |
| Composition roots | `bins/*`, `workspace/tools/*` | runtime executables and bounded tools |

A crate is a source/build boundary, not a lifecycle or authority owner.

## Runtime owners and work items

| Capability | Intended role | Work item |
|---|---|---|
| `eliot-host.exe` | external lifecycle/recovery boundary | #14 |
| `eliot-kernel.exe` | identity, fencing, ORS, reserve, generation routing | #15 |
| `eliotd.exe` | Governor semantic daemon | #18 |
| `eliot-watchdog.exe` | independent supervision | #16 |
| `eliot-doctor.exe` | bounded one-shot repair | #17 |
| store bridge / Surreal generation / BlobStore | closed storage path and single owners | #19, #7–#9 |
| `eliot-testd.exe` | isolated Instrument execution | #20 |
| `eliot-wasm-host.exe` | capability-limited component host | #21 |
| native worker | isolated OS-heavy generation | #22 |
| User Broker | interactive-user launch/resource boundary | #23 |
| notify / agent bridge | stateless or near-stateless surfaces | #13 |
| Researcher provider process | governed acquisition execution | #24 |

Dreamer is excluded from the core/daemon workstream and owned separately.

## Canonical transition path

```text
proposal or observation
→ eliotd semantic admission and PreparedTransition
→ Kernel identity/authority/fence/order/generation validation
→ closed named store transaction
→ receipt/outbox
→ reconciliation and projection publication
```

No report, branch, Module, Doctor, Watchdog, Dreamer, provider, or recovery
spool creates another semantic write path.

## Mutable-state ownership

| State | Owner |
|---|---|
| installation approval, Host activation, managed dependency lineage | Host / `HostStateJournal` |
| Authority Epochs, ORS, Generation Registry, active session/broker bindings | Kernel |
| tasks, plans, semantic admission, Module Catalog, finish | logical Governor / canonical store |
| canonical DB files and transaction execution | Host-managed Surreal generation through store bridge |
| blob bytes/reachability/GC | one active BlobStore owner |
| Watchdog signals/spool/anchors | Watchdog; non-semantic |
| user-session process tree and broker epoch | User Broker; registration in ORS |
| derived indexes/caches | owning replaceable Module generation |
| UI-local transient state | Human surface only |

The executable projection of these boundaries is tracked by #13; this table
cannot grant authority by itself.

## Active programmes

- Core/daemon issues #13–#24 use fresh issue-numbered branches and
  `workstreams/core-daemons/AGENTS.md`.
- Draft cognitive prototype PR #26 is the sole active nonstandard branch. Its
  branch must contain current `main` as an ancestor before mutation or merge,
  and mutation is restricted to the paths declared in `workstreams/ACTIVE.toml`.
  It is not a general repair branch.

Every other nonstandard branch is retired/read-only archaeology. Current
support still requires exact source/build/runtime/store evidence and the
applicable Product Pulse; committed prose does not substitute for that proof.
