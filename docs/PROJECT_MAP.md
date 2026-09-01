# ELIOT Memory OS project map

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact repository paths and causal property being changed. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. The stable `ELIOT_*` files are compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->


Status: current routing map for `main`, audited against
`0c041d6ab9c33ed21fbd950cf9eb1d94254d39f7` on 2026-08-31. Navigation only;
product status remains `NOT_ACCEPTED / UNVERIFIED`.

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

Issue status in the maps below is explicit:

- **open** — current bounded work item;
- **completed baseline** — the issue is closed and remains only a historical
  boundary/proof reference, not a current writer;
- **follow-up** — a separate open cross-cutting issue owns remaining shared work.

A completed baseline does not prove current installation, runtime health,
Product acceptance, release support, or completion of a named follow-up.

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

## Exact Cargo composition roots

This table is an inventory of root-workspace `bins/*` packages. Presence in the
workspace proves source/build admission only; it does not prove installation,
runtime health, authority correctness, Product acceptance, or release support.

| Cargo member | Executable | Intended boundary | Work item |
|---|---|---|---|
| `bins/eliot` | `eliot.exe` | canonical one-shot operator/agent CLI and installation/runtime-status front door | current surface/installation issue; live proof #11 |
| `bins/eliot-agent-bridge` | `eliot-agent-bridge.exe` | thin public agent bridge ingress surface | open #13; full bridge integration #77 |
| `bins/eliot-doctor` | `eliot-doctor.exe` | bounded one-shot repair composition root | completed baseline #17; open process follow-up #100 |
| `bins/eliot-dreamer` | `eliot-dreamer.exe` | candidate-only Dreamer execution surface | open cognitive issues #38–#45 |
| `bins/eliot-host` | `eliot-host.exe` | external lifecycle, journal, launch, and recovery boundary | open #14 |
| `bins/eliot-kernel` | `eliot-kernel.exe` | identity, fencing, ORS, reserve, and generation routing | open #15 |
| `bins/eliot-mod-research` | `eliot-mod-research.exe` | governed external-corpus acquisition provider process | open #24 |
| `bins/eliot-native-worker` | `eliot-native-worker.exe` | isolated OS-heavy native generation | open #22 |
| `bins/eliot-notify` | `eliot-notify.exe` | thin stateless/near-stateless notification surface | open #13 |
| `bins/eliot-store-surreal` | `eliot-store-surreal.exe` | closed Surreal store bridge composition root | open #19; payload regression #10 |
| `bins/eliot-testd` | `eliot-testd.exe` | isolated typed Instrument execution | open #20 |
| `bins/eliot-user-broker` | `eliot-user-broker.exe` | SID/session-bound interactive-user launch and resources | completed baseline #23; open process follow-up #100 |
| `bins/eliot-wasm-host` | `eliot-wasm-host.exe` | capability-limited WASM/component mechanics | open #21 |
| `bins/eliot-watchdog` | `eliot-watchdog.exe` | independent supervision process | completed baseline #16; open process follow-up #100 |
| `bins/eliotd` | `eliotd.exe` | Governor semantic daemon/application owner | open #18 |

The executable inventory is checked against the root `Cargo.toml`; a new or
removed `bins/*` workspace member must update this table in the same bounded
change. Issue-state qualifiers are audited separately against GitHub and must be
updated when a referenced issue opens, closes, is superseded, or changes owner.

## Legacy migration facades

The earlier broad source owners remain in the workspace for compatibility,
regression reproduction, extraction, and deletion. Their names and code volume
do not make them current runtime or semantic owners.

| Facade | Current disposition |
|---|---|
| `crates/eliot-app` / `eliot-governor` | Legacy migration/regression facade. Not a production composition root or root default member. Read its local `AGENTS.md`; no new feature or state/effect owner is allowed. Extraction/disposition is owned by open #18 and registry binding by open #13. |
| `crates/eliot-engine` | Migration facade for historical application/domain logic. New capabilities belong in the declared current owner; edits require a proven current consumer or extraction path. |
| `crates/eliot-store` | Migration facade around historical store-facing behavior. It cannot bypass the current store API/bridge or become a second storage owner. |
| `crates/eliot-types` | Migration contract/type facade. It must not become an unbounded common-type owner; stable current contracts live in the declared foundation/domain contract crates. |
| `crates/eliot-windows-ipc` | Compatibility facade for historical Windows IPC behavior; current process/IPC ownership remains in the declared Kernel/platform/surface contracts. |

A regression may still terminate in a facade. That permits a scoped repair or
migration under the owning issue, not general development there.

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

The executable projection of these boundaries is tracked by open #13; this
table cannot grant authority by itself.

## Active programmes

- Regression issues #7–#10 first reproduce or refute their historical failure
  class on exact current identities; implementation then changes only the proven
  current owner/path.
- Open core/daemon issues #13–#15, #18–#22, and #24 use fresh issue-numbered
  branches and `workstreams/core-daemons/AGENTS.md`.
- Completed boundary baselines #16, #17, and #23 remain historical references;
  open #100 owns the shared native-process contract/convergence follow-up across
  those and other process clients.
- Open cognitive issues #38–#45 use the wave/edge/donor/decision manifests
  already on `main`; every implementation cell receives a fresh issue-numbered
  branch.
- Issue #11 owns current live Windows installation and Product-Pulse evidence.

Dreamer remains outside the core/daemon workstream. Its source/build presence is
not runtime or Product support.

There is no shared long-lived implementation branch. Visible legacy refs are
non-mutable aliases of `main` until they can be physically deleted. Current
support still requires exact source/build/runtime/store evidence and the
applicable Product Pulse; committed prose does not substitute for that proof.
