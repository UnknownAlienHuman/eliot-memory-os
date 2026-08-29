# ELIOT Memory OS project map

Status: current routing map for `main`, 2026-08-29. Navigation only; product
status remains `NOT_ACCEPTED / UNVERIFIED`.

## Authority and work

| Question | Source |
|---|---|
| Current code and documentation | `main` |
| Repository workflow | `AGENTS.md`, `WORKFLOW.md` |
| Active programmes | `workstreams/ACTIVE.toml` |
| Documentation routing | `docs/README.md` |
| Architecture authority and pair identity | `docs/ARCHITECTURE_CONTRACT.md`, `docs/normative-pair.toml` |
| Current implementation change | owning open issue and PR |
| Live Windows operational-spine proof | issue #11 |

Branches are disposable execution state, not documentation editions. Ordinary
work starts from current `main` in a fresh issue-numbered branch. Historical
reports, donor research, recovery programmes, and local/generated state are not
present in the active checkout.

## Repository planes

| Plane | Current source paths | Responsibility |
|---|---|---|
| Foundation | `crates/foundation/*` | contracts, protocols, evidence, receipts, security/runtime types |
| Governor | `crates/governor/*`, `bins/eliotd` | semantic admission, tasks, WorkScopes, coordination, finish |
| Kernel/Host | `crates/kernel/*`, `bins/eliot-host`, `bins/eliot-kernel` | installation, Host journal, IPC, ORS, authority/fencing, process lifecycle |
| Storage | `crates/storage/*`, `bins/eliot-store-surreal` | store API, Surreal bridge, BlobStore, export/backup |
| Agent fabric | `crates/agent/*` | agent routes and coordination contracts/adapters |
| Smart/research/security | `crates/smart/*`, `crates/research/*`, `crates/security/*` | context, memory, understanding, Dreamer/Researcher candidates, privacy/influence |
| Instrument/meta/supervision | `crates/instrument/*`, `crates/meta/*`, `crates/supervision/*` | instruments, verification, runtime status, Watchdog/Doctor cores |
| Surfaces/modules | `crates/surfaces/*`, `crates/modules/*`, applicable `bins/*` | CLI/MCP/skills, User Broker, native/WASM boundaries |
| Composition roots | `bins/*`, `workspace/tools/*` | runtime executables and bounded tools |

A crate is a source/build boundary, not a lifecycle or authority owner.

## Legacy migration facades

The earlier broad source owners remain in the workspace for compatibility,
regression reproduction, extraction, and deletion. Their names and code volume
do not make them current runtime or semantic owners.

| Facade | Current disposition |
|---|---|
| `crates/eliot-app` / `eliot-governor` | Legacy migration/regression facade. Not a production composition root or root default member. Read its local `AGENTS.md`; no new feature or state/effect owner is allowed. Extraction/disposition is owned by #18 and registry binding by #13. |
| `crates/eliot-engine` | Migration facade for historical application/domain logic. New capabilities belong in the declared current owner; edits require a proven current consumer or extraction path. |
| `crates/eliot-store` | Migration facade around historical store-facing behavior. It cannot bypass the current store API/bridge or become a second storage owner. |
| `crates/eliot-types` | Migration contract/type facade. It must not become an unbounded common-type owner; stable current contracts live in the declared foundation/domain contract crates. |
| `crates/eliot-windows-ipc` | Compatibility facade for historical Windows IPC behavior; current process/IPC ownership remains in the declared Kernel/platform/surface contracts. |

A regression may still terminate in a facade. That permits a scoped repair or
migration under the owning issue, not general development there.

## Runtime owners and work items

| Capability | Intended role | Work item |
|---|---|---|
| `eliot.exe` | canonical one-shot operator/agent CLI | current surface/installation issue |
| `eliot-host.exe` | external lifecycle/recovery boundary | #14 |
| `eliot-kernel.exe` | identity, fencing, ORS, reserve, generation routing | #15 |
| `eliotd.exe` | Governor semantic daemon | #18 |
| `eliot-watchdog.exe` | independent supervision | #16 |
| `eliot-doctor.exe` | bounded one-shot repair | #17 |
| store bridge / Surreal generation / BlobStore | closed storage path and single owners | #19; payload regression #10 |
| `eliot-testd.exe` | isolated Instrument execution | #20 |
| `eliot-wasm-host.exe` | capability-limited component host | #21 |
| native worker | isolated OS-heavy generation | #22 |
| User Broker | interactive-user launch/resource boundary | #23 |
| notify / agent bridge | stateless or near-stateless surfaces | #13 |
| Researcher provider process | governed acquisition execution | #24 |

Dreamer is excluded from the core/daemon workstream. Its candidate-only
cognitive capability-cell scaffold is on `main`; issues #38–#45 own the current
contract, donor-migration, integration, and self-learning gaps.

## Canonical transition path

```text
proposal or observation
→ eliotd semantic admission and PreparedTransition
→ Kernel identity/authority/fence/order/generation validation
→ closed named store transaction
→ receipt/outbox
→ reconciliation and projection publication
```

No report, branch, facade, Module, Doctor, Watchdog, Dreamer, provider, or
recovery spool creates another semantic write path.

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

- Regression issues #7–#10 first reproduce or refute their historical failure
  class on exact current identities; implementation then changes only the proven
  current owner/path.
- Core/daemon issues #13–#24 use fresh issue-numbered branches and
  `workstreams/core-daemons/AGENTS.md`.
- Cognitive issues #38–#45 use the wave/edge/donor/decision manifests already
  on `main`; every implementation cell receives a fresh issue-numbered branch.
- Issue #11 owns current live Windows installation and Product-Pulse evidence.

There is no shared long-lived implementation branch. Visible legacy refs are
non-mutable aliases of `main` until they can be physically deleted. Current
support still requires exact source/build/runtime/store evidence and the
applicable Product Pulse; committed prose does not substitute for that proof.
