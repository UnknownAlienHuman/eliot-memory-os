## I1.9. Three registries, three owners

“Module Registry” is not a single mutable object. The implementation uses three distinct owners:

| Registry | Owner | State class | Contains | Must not contain |
|---|---|---|---|---|
| **Module Catalog** | Governor / `eliotd` | canonical configuration/intent | desired module manifests, semantically admitted/allowed versions, dependencies, capability intent, policy and removal boundary | PIDs, pipes, Job Objects, Host-level artifact approval or uncommitted health |
| **Generation Registry** | Kernel / ORS | operational recovery state | installed/running/candidate generations, process handles, Authority Epoch, route switch, drain/checkpoint/restart state | project claims, task meaning, semantic policy decisions |
| **Capability Registry** | Governor composite projection | canonical manifests/evidence + Kernel generation/health + policy/supervision inputs | current usable installations/routes, evidence, limitations and admission status | lifecycle ownership, process truth or authority inferred from mere availability |

Hot replacement reconciles them:

```text
Module Catalog requests desired generation
→ Kernel stages/starts/observes candidate in Generation Registry
→ probes/production produce capability evidence
→ Governor updates Capability Registry and decides admission
→ Kernel performs fenced route switch
→ receipts/outbox reconcile the three views.
```

One table, actor or file may not own all three lifecycles. Code, protocol and documentation use these names exactly.

A Governor-admitted generation produces an immutable `KernelExecutionManifest` copied into the Generation Registry:

```text
artifact/config/protocol hashes;
start command and dependency order;
Job Object/resource limits;
health/readiness contract;
restart budget and quarantine rule;
restart_authorization_class: read_rebuild | effect_exact_lease | current_catalog_required;
authority/effect ceiling and allowed scopes;
checkpoint/state-class behavior;
accepted Module Catalog revision and receipt.
```

This is a technical execution projection, not desired-state policy. It lets Kernel restart the exact previously admitted daemon/module while `eliotd` is unavailable only within the recorded restart class.

```text
read-only/rebuildable generation
  → may restart from the exact manifest under bounded restart budget;

effect-capable generation
  → may resume only exact already-authorized operations covered by an unexpired operation lease;
  → new effect admission requires a current Module Catalog/Policy view;

Catalog/Policy unavailable, stale, revocation event unacknowledged or delivery gap open
  → candidate may start in shadow/no-effect diagnostic mode only.
```

Kernel cannot create, widen or update the manifest without a governed Catalog/lifecycle receipt. Missing, stale or incompatible manifest means visible degradation and escalation, not an improvised restart. A process restart never converts stale desired state into current authority.

Host-managed dependencies use a fourth, strictly operational record:

```text
ManagedDependencyRecord
  owner: Host;
  contains: immutable process manifest, artifact/config hash, Job Object/PID lineage,
            start/stop/restart budget, observed exit/readiness and requester identity;
  must not contain: DB claims, task state, schema meaning or canonical authority.
```

For the canonical store, process liveness comes from this record and Host/Watchdog observations; semantic readiness comes from store-bridge version/schema/transaction probes. Neither observation can substitute for the other.

Host persists these records in a separate minimal `HostStateJournal` outside Kernel ORS and Canonical Memory:

```text
installation/Host epoch and clean-shutdown marker;
active/candidate Kernel activation identity and one-time nonce state;
managed-dependency process generation, PID/Job lineage and restart budget;
approved artifact/config hashes and last observed process disposition.
```

The journal has exactly one writer — Host — and is opened through `eliot-platform::HostStateStore`. The Windows DEFAULT is a dedicated redb file under `%ProgramData%\Eliot\host`, with checksummed records and transaction durability; another platform may replace the backend without changing the contract. It stores no project semantics, task state, policy interpretation, credentials or canonical authority. Corruption closes automatic activation/restart, preserves evidence and enters manual recovery; Host never reconstructs missing state from PIDs or directory contents alone.

### Mutable-state ownership matrix

Every mutable state class has one authoritative owner. Mirrors, caches and projections may be rebuilt, but cannot mutate independently or survive owner invalidation as authority.

| State class | Authoritative owner | Durable location | Rebuildable mirrors / consumers | Forbidden ambiguity |
|---|---|---|---|---|
| Host/Kernel and Host-managed dependency artifact approval, Host activation and managed dependency process lineage | Host | HostStateJournal | Watchdog observations, ControlBoard | Kernel/daemon cannot infer Host-level approval from files or PIDs; module semantic admission remains in Module Catalog |
| cognitive inheritance, tasks, policy/config, Module Catalog and semantic receipts | logical Governor | Canonical Store | daemon caches, packets, reports | ORS, modules and vendor runtimes cannot become semantic owners |
| canonical DB files and transaction execution | SurrealDB process through store bridge | canonical DB storage | logical export, read projections | Host process liveness is not semantic readiness |
| pending operations, Authority Epochs, Generation Registry, delivery cursors, active Session/User Broker bindings and recovery intents | Kernel | ORS | Recovery View, canonical reconciliation receipts | restore never revives active operational authority |
| immutable large payload bytes, reachability and GC state | Blob Store | Blob root/CAS metadata | canonical BlobRef, read caches | DB bridge cannot write blob files; a blob receipt is not a semantic receipt |
| provisional security/liveness signals and independent integrity anchors | Watchdog | Watchdog spool | Governor Problem/Incident reconciliation | Watchdog spool is not project memory |
| user-session process tree and launch epoch | User Broker in the authenticated user session | broker runtime + ORS registration | Host/Watchdog process observations | canonical consent does not prove a live broker |
| native provider/runtime continuation state | exact external runtime/adapter generation | runtime-native state plus ELIOT locator/checkpoint | public rehydration packet | native state is not task identity or canonical truth |
| derived indexes, graphs and caches | owning Module generation | rebuildable module state | Governor read views | derived state cannot outlive invalidated source dependencies as current evidence |
| UI-local transient state | Human surface | process-local | canonical ControlBoardView | UI state cannot mutate task truth directly |

A proposed implementation that introduces a second writer for any row above is rejected even if it calls the duplicate state a cache, registry, journal or recovery store.

