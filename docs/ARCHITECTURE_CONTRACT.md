# Architecture authority and version boundary

## Current owner decision: design V3 before implementation

On 2026-10-18 the owner directed that V2 join V1 as an archived donor and that V3 be written from scratch after its documentation is refined. This direction supersedes the old documents' claim to govern the next implementation. It does not claim that every V3 proposal has already been accepted.

| Surface | Current role |
|---|---|
| [V3 Architecture](v3/ARCHITECTURE.md) | Draft intent, preserved requirements, and proposed product boundary |
| [V3 Implementation](v3/IMPLEMENTATION.md) | Draft mechanisms, normal/failure paths, and open decisions |
| [V3 audit](v3/AUDIT.md) | Requested evidence, criticism, donor analysis, and rationale; no independent authority to create mandatory subsystems |
| [V3 navigation](v3/README.md) | Stage, reading order, source pins, and next documentation work |
| `docs/architecture/`, `docs/normative-pair.toml`, existing source/scripts/workstreams | Retained V2 donor surfaces; old status terms are historical |

Architecture intent prevails over a conflicting proposed mechanism. Resolve contradictions explicitly in both documents, using the owner's instructions and source evidence. A new mechanism, numeric budget, process count, database choice, or evaluation threshold is not owner-approved merely because an agent wrote it in a draft.

There is no V3 adoption digest or product acceptance receipt in this revision. Do not generate one by relabeling the V2 pair. A later agreed documentation revision can establish the implementation boundary without pretending that code, model integration, learning, or recovery already works.

## V2 archival identity

The retained V2 baseline is [commit 5aac094834fb5635921b550c821cb933a1196105](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105). Its incomplete audit materials are preserved by [release audit-2026-10-16-incomplete](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete). V1 remains a separate [donor snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7).

The V2 sharded pair and machine receipt remain byte-identifiable evidence:

| V2 document | Manifest and index | Historical revision/edition | Reconstructed SHA-256 |
|---|---|---|---|
| Architecture | [docs/architecture/architecture/manifest.json](architecture/architecture/manifest.json), [index](architecture/architecture/README.md) | `4.5-draft`, `2026-08-28` | `A3C5B2028D9DF89A53CD565F8FF493484BE74078E4EFD7B534C0F1C3169577C7` |
| Implementation | [docs/architecture/implementation/manifest.json](architecture/implementation/manifest.json), [index](architecture/implementation/README.md) | `0.29-draft`, `2026-08-28` | `EAD4CEFF2DB254E4202C8FA7AE167225A6F65B720C222075ADA61FC45FC407A4` |

[normative-pair.toml](normative-pair.toml) records the V2 pair key `sha256:ab2011bd67557d89b2f094061d350a297389f7f57d0478be5e1ff8d2da8ed1c1`. Earlier monolith digests and adoption history are preserved in the [baseline authority contract](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/5aac094834fb5635921b550c821cb933a1196105/docs/ARCHITECTURE_CONTRACT.md), not merged into a new V3 authority.

[ELIOT_ARCHITECTURE.md](architecture/ELIOT_ARCHITECTURE.md) and [ELIOT_IMPLEMENTATION.md](architecture/ELIOT_IMPLEMENTATION.md) are V2 compatibility maps. Use the [reading protocol](architecture/READING_PROTOCOL.md), [routes](architecture/ROUTES.md), and [handle index](architecture/HANDLE_INDEX.md) when investigating their source fragments. A route is navigation, not comprehension or current runtime proof.

## Working and evidence rules

`main` is the repository integration authority. Follow [AGENTS](../AGENTS.md), [START](../START.md), and [WORKFLOW](../WORKFLOW.md); independent review and required CI remain applicable. Source/workstream statuses inside the donor tree do not authorize V2 continuation. Do not resume the October audit factory or assign all its unresolved rows as V3 implementation tasks.

The freeze preserves source and history without copying the whole project into a second directory, closing every old issue, deleting user data, or migrating a running installation. Those actions are outside this documentation change.

The V2 ACTIVE registry and its validators remain unchanged, including their active values. This is a human-directed documentation freeze, not a machine-registry transition; preserving those donor bytes does not override the owner's current task scope.

Current source, dependencies, build diagnostics, actual runtime observations, and evaluated outcomes establish only the properties they demonstrate. Drafts, reports, compile success, line counts, and test totals do not establish a working cognitive loop or accepted product.
