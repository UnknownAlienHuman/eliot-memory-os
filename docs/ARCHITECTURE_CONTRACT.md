# Architecture authority and version boundary

## Current owner decision: coherent V3 design before runtime rewrite

On 2026-10-18 the owner directed that V2 join V1 as an archived donor and that V3 be designed from scratch before implementation. This direction supersedes old Memory documents as authority for the next implementation. It does not claim that V3 code exists or that design text proves runtime behavior.

The current synchronized V3 set is:

| Surface | Current role |
|---|---|
| [Architecture draft.10](v3/ARCHITECTURE.md) | Product purpose, authority owners, Base, extensions and invariants |
| [Implementation draft.31](v3/IMPLEMENTATION.md) | Runtime, Store, Windows/process, durability, backup/restore and implementation order |
| [Cognition draft.14](v3/COGNITION.md) | Current-work reconstruction, retrieval, learning and revision algorithms |
| [Inference Contract 0.9](v3/INFERENCE-CONTRACT.md) | Sole normative Memory↔controller V2 boundary |
| [Active analysis registry](v3/ANALYSIS-REGISTRY.md) | Sole active decisions/gaps/source-coverage/work queue |
| [V3 navigation](v3/README.md) | Reading order, current baseline and proof ceiling |
| [V3 audit](v3/AUDIT.md), [source map](v3/AUDIT-MAP.md) | Evidence, criticism, donor analysis and stable source dispositions; not an independent subsystem authority |
| `docs/architecture/`, `docs/normative-pair.toml`, existing source/scripts/workstreams | Retained V2 donor surfaces; old status terms are historical |

Architecture intent prevails over a conflicting lower-level mechanism. Implementation and Cognition must agree with Architecture and the cross-repository Inference Contract. Resolve a changed load-bearing mechanism in all affected owner documents in the same change; do not add an errata layer or second active contract.

A new mechanism, budget, process count, database choice, credential path or evaluation threshold is not accepted merely because an agent wrote it. It must have a concrete caller, owner, durable result/unknown and consumer, plus source/design evidence appropriate to the decision.

There is no V3 adoption digest or product acceptance receipt in this revision. Do not generate one by relabelling the V2 pair. The synchronized V3 documents establish the implementation target; they do not establish completed code, model integration, learning, backup, recovery or runtime qualification.

## Controller version boundary

The current inspected controller authority is:

```text
UnknownAlienHuman/eliot-swarm-controller
main = c8c0ee122c98a01be86bc5296a22a389662a1c89
merged PR #197
```

That V2 specification selects a fresh local JSON-RPC + SQLite WAL implementation with canonical external ULID `WriteId` receipts. It explicitly treats the existing Rust/`swarm-client`/generic Operation runtime as V1 legacy pending deletion.

Therefore:

- controller revision `e42c464d` and its roles, hello, Operation/artifact and generic registration code are donor evidence only;
- no Memory implementation may add one-shot inference to that retired stack;
- the active boundary is Contract 0.9: dedicated `memory_inference` principal, stable client ID, monotonic token version, authenticated `client.identity`, pre-send `WriteId`, minimal `inference_calls` state, private call-owned input/result copies and admission-sequence restore inventory;
- controller V2 L0/L1 must exist before the Memory inference extension;
- a missing V2 capability is a real dependency, not permission to revive V1.

## V2 archival identity

The retained V2 baseline is [commit 5aac094834fb5635921b550c821cb933a1196105](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105). Its incomplete audit materials are preserved by [release audit-2026-10-16-incomplete](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete). V1 remains a separate [donor snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7).

The V2 sharded pair and machine receipt remain byte-identifiable evidence:

| V2 document | Manifest and index | Historical revision/edition | Reconstructed SHA-256 |
|---|---|---|---|
| Architecture | [docs/architecture/architecture/manifest.json](architecture/architecture/manifest.json), [index](architecture/architecture/README.md) | `4.5-draft`, `2026-08-28` | `A3C5B2028D9DF89A53CD565F8FF493484BE74078E4EFD7B534C0F1C3169577C7` |
| Implementation | [docs/architecture/implementation/manifest.json](architecture/implementation/manifest.json), [index](architecture/implementation/README.md) | `0.29-draft`, `2026-08-28` | `EAD4CEFF2DB254E4202C8FA7AE167225A6F65B720C222075ADA61FC45FC407A4` |

[normative-pair.toml](normative-pair.toml) records the V2 pair key `sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1`. Earlier monolith digests and adoption history remain in the [baseline V2 authority contract](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/ARCHITECTURE_CONTRACT.md); they are not merged into V3 authority.

[ELIOT_ARCHITECTURE.md](architecture/ELIOT_ARCHITECTURE.md) and [ELIOT_IMPLEMENTATION.md](architecture/ELIOT_IMPLEMENTATION.md) are V2 compatibility maps. Use the [reading protocol](architecture/READING_PROTOCOL.md), [routes](architecture/ROUTES.md) and [handle index](architecture/HANDLE_INDEX.md) when investigating their exact fragments. A route is navigation, not comprehension or current runtime proof.

## Working and evidence rules

`main` is repository integration authority. While issue #5324 and PR #5325 remain open, their `docs/v3/` branch files are the current V3 working authority. Follow [AGENTS](../AGENTS.md), [START](../START.md) and [WORKFLOW](../WORKFLOW.md); independent review and required CI remain applicable.

Source/workstream statuses inside the donor tree do not authorize V2 continuation. Do not resume the October audit factory or assign every unresolved V2 row as a V3 implementation task.

The freeze preserves source and history without copying the project into a second directory, closing every old issue, deleting user data or migrating a running installation. Those actions are outside this documentation change.

The V2 ACTIVE registry and validators remain unchanged, including historical active values. This is a human-directed version boundary, not a machine-registry transition; retaining donor bytes does not override the owner’s current task scope.

Current source, dependencies, build diagnostics, actual runtime observations and evaluated outcomes establish only the properties they demonstrate. Drafts, reports, compilation, line counts, tests or CI status do not establish a working cognitive loop or accepted product.
