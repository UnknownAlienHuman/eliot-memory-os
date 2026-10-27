# Architecture authority and version boundary

## Current owner decision

On 2026-10-18 the owner directed that V2 join V1 as an archived Memory donor and that V3 be designed from scratch before implementation. This supersedes old Memory documents as authority for the next implementation. It does not claim V3 code exists.

Current synchronized V3 set:

| Surface | Role |
|---|---|
| [Architecture draft.19](v3/ARCHITECTURE.md) | Purpose, authority, Base and invariants |
| [Implementation draft.40](v3/IMPLEMENTATION.md) | Runtime, Store/schema/query, maintenance and order |
| [Cognition draft.23](v3/COGNITION.md) | Reconstruction, retrieval, learning and failure algorithms |
| [Inference Contract 0.18](v3/INFERENCE-CONTRACT.md) | Sole Memory↔controller boundary |
| [Active registry](v3/ANALYSIS-REGISTRY.md) | Sole current decisions/gaps/source/queue ledger |
| [V3 audit and source map](v3/AUDIT.md), [AUDIT-MAP](v3/AUDIT-MAP.md) | Evidence, criticism and donor dispositions |

Architecture intent prevails over conflicting lower-level mechanism. Resolve a changed load-bearing mechanism in every affected owner document; do not add an errata layer or second contract.

A mechanism, threshold, process, database or credential path is accepted only with a real caller, owner, durable result/unknown and consumer plus appropriate evidence. Synchronized prose establishes an implementation target, not working behavior.

## Current controller, Store and backup boundary

Controller authority:

```text
eliot-swarm-controller@613ea6b5ff6389c7629a988e271477ee45c9d2c1
```

It selects fresh V2 JSON-RPC + SQLite WAL and treats the old runtime as legacy.

Therefore:

- issue #200 must separate monotonic binding allocation, selected current pointer and effect publication;
- candidate admission never moves pointer; launch/resume publish target pointer with dispatch, while attach/detach move it only after exact effect;
- controller V2 L0/L1 must exist before issue #199 implements Contract 0.18;
- daemon owns controller-mutation and backup-set owners;
- supervisor owns candidate process/root and final cutover;
- final backup directory first appears through atomic directory rename with exact fence already inside;
- self-contained abort/retire tombstones remain terminal after cleanup;
- restore admits finite part limits, retains directory/fence/manifest with read sharing only and streams one verified part at a time;
- daemon/channel loss forces candidate discard before restart/cutover;
- Store maintenance rows are mirrors only;
- missing controller capability is a dependency, not permission to revive V1.

Initial Store target is SurrealDB 3.3.4/RocksDB `sync=every`, one query-only authenticated client, a `STRICT` database and six Base `SCHEMAFULL` tables.

Application IDs crossing JSON are canonical strings; Surreal record IDs remain internal. Queries are fixed and explicitly projected. Schema bundle identity includes runner protocol, wrapper template, ordered DDL and expected catalog. Schema admission uses plain `INFO FOR DB/TABLE` maps and forbids unstable `STRUCTURE`. Scored FTS uses numbered match references and one bounded top-K snapshot per call.

## Donor identity

V2 baseline: `5aac094834fb5635921b550c821cb933a1196105`. V1 donor: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. The V2 normative pair and routing tools remain donor evidence only.

While issue #5324 and PR #5325 remain open, their branch `docs/v3/` files are current working authority. Follow [AGENTS](../AGENTS.md) and [WORKFLOW](../WORKFLOW.md). Independent review and required CI remain applicable.