# Eliot Memory OS

> **V3 is the current design authority.** V1 and V2 Memory implementations are archived donors. The documentation does not claim a V3 runtime exists.

Eliot preserves exact experience, reconstructs current work, supplies applicable context before the next decision, learns bounded procedures from observed outcomes and revises mistaken memory without losing source history.

## Start with V3

| Read | Purpose |
|---|---|
| [V3 navigation](docs/v3/README.md) | Current versions, construction and proof ceiling |
| [Architecture draft.19](docs/v3/ARCHITECTURE.md) | Purpose, ownership, Base, schema/backup invariants |
| [Implementation draft.41](docs/v3/IMPLEMENTATION.md) | Runtime, exact Store/schema/query contract, Windows/process, backup/rollback and sequence |
| [Cognition draft.23](docs/v3/COGNITION.md) | Reconstruction, retrieval, learning and failure diagnosis |
| [Inference Contract 0.18](docs/v3/INFERENCE-CONTRACT.md) | Sole Memory↔controller V2 boundary |
| [Active analysis registry](docs/v3/ANALYSIS-REGISTRY.md) | Current decisions, gaps, evidence and queue |
| [Consolidated audit](docs/v3/AUDIT.md) | Donor evidence, criticism and rationale |

Architecture 19, Implementation 41, Cognition 23 and Contract 0.18 describe one synchronized implementation target. Specification text, source presence, green build or receipt does not establish working behavior.

Current work: [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324), [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325).

## Product boundary

Memory owns observations, revisions, context, provenance, finite learning jobs and outcome-linked methods. Hosts/controllers own goals, actions, Agent/task execution and user acceptance.

Useful Base:

```text
real host event
→ Store ownership or durable spool
→ replay and restart
→ current-work reconstruction
→ actual context emission or explicit retrieval
→ exact source open
```

First learning:

```text
retained episode
→ exact recipe
→ one controller call with precommitted global WriteId
→ typed result or unknown
→ ordinary Memory revision
→ changed later context
→ rollback-safe dependency-aware cleanup
```

## Current physical decisions

- one Rust codebase with supervisor, daemon and transient relay modes;
- SurrealDB 3.3.4/RocksDB `sync=every` qualification target;
- six Base `SCHEMAFULL` tables plus immutable blobs;
- canonical OS-random application IDs, domain-separated derived keys and fixed query DTOs;
- explicit indexed workspace/task/actor/session projection for direct continuation;
- read-only identity/creation fields plus body/validity/claim/request/slot assertions;
- schema-bundle identity covers runner protocol, wrapper template, ordered DDL and expected catalog;
- plain `INFO FOR DB/TABLE` catalog readback; unstable `STRUCTURE` is forbidden;
- scored FTS uses numbered match references and one bounded top-K snapshot, not a cross-call cursor;
- daemon-owned controller-mutation and backup-set owners;
- atomic backup-directory first visibility with fence already present;
- self-contained abort/retire tombstones;
- bounded streaming restore lease with one verified part at a time;
- supervisor candidate process/root and final cutover; candidate discard on daemon/channel loss;
- exact rollback rather than invented merge.

## Controller boundary

Current controller authority is `eliot-swarm-controller@613ea6b5ff6389c7629a988e271477ee45c9d2c1`; V2 remains specification-only.

Issue #200 separates binding allocation, selected pointer and effect state. PR #201 fixes validator fixtures only. V2 L0/L1 and #200 must exist before issue #199 implements Contract 0.18. Never extend controller V1 for Memory inference.

## Version boundary

Existing Rust workspace, old architecture shards, scripts and workstream records describe V2 Memory. They remain selective donors, not authorization to continue V2 topology.

- [V2 source snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105)
- [V2 unfinished audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete)
- [V1 donor snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7)

Follow [AGENTS.md](AGENTS.md), [WORKFLOW.md](WORKFLOW.md) and [Architecture authority](docs/ARCHITECTURE_CONTRACT.md). Production code first; after coherent increments run formatting and minimum changed-package Clippy. Broad suites follow connected product.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](docs/architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for exact paths and causal property. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. Stable `ELIOT_*` files are V2 compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->

## License

MIT License. Third-party code and runtimes retain their own licenses; verify exact revisions before reuse.