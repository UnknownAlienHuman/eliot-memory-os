# Eliot Memory OS

> **V3 is the current design authority.** V1 and V2 Memory implementations are archived donors. No V3 runtime is implemented by this documentation revision.

Eliot is a memory, understanding and learning system for people and AI agents. It preserves exact experience, reconstructs current work, supplies useful context before the next decision, learns bounded procedures from observed outcomes and revises mistaken memory without losing source history.

## Start with V3

| Read | Purpose |
|---|---|
| [V3 navigation](docs/v3/README.md) | Current versions, reading order, selected construction and proof ceiling |
| [Architecture draft.10](docs/v3/ARCHITECTURE.md) | Product purpose, ownership, Base, extensions and invariants |
| [Implementation draft.31](docs/v3/IMPLEMENTATION.md) | Runtime, Store, Windows/process, durability, backup/restore and implementation sequence |
| [Cognition draft.14](docs/v3/COGNITION.md) | Current-work reconstruction, retrieval, learning and revision algorithms |
| [Inference Contract 0.9](docs/v3/INFERENCE-CONTRACT.md) | Sole normative Memory↔controller V2 boundary |
| [Active analysis registry](docs/v3/ANALYSIS-REGISTRY.md) | Current decisions, gaps, source coverage and queue |
| [Consolidated audit](docs/v3/AUDIT.md) | Evidence, criticism, donor analysis and rationale |

Architecture 10, Implementation 31, Cognition 14 and Contract 0.9 describe one design at increasing depth. Source presence, specification text, a green build or a receipt does not establish a working capability.

The current documentation task is [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325).

## Version boundary

The existing Rust workspace, old architecture shards, scripts and workstream records describe **V2**. They remain available for selective investigation and reuse; their checklists do not authorize continuing V2 implementation or importing its physical architecture into V3.

- [V2 source snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105)
- [V2 unfinished audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete)
- [V1 donor snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7)

This is a documentation-stage donor freeze. Old source bytes and issues remain available; data import, runtime replacement and code removal are later separately scoped work. The V2 `ACTIVE.toml` registry still contains its historical active values and is not a V3 authority.

[Architecture authority](docs/ARCHITECTURE_CONTRACT.md) records the precedence. The active V3 owner documents define the design; the Russian audit explains evidence and alternatives without turning every idea into a required subsystem.

## Selected product boundary

Memory owns durable observations, revisions, context, provenance, finite learning jobs and outcome-linked methods. External hosts/controllers own goals, actions, agent/task execution and user acceptance.

Useful Base comes first:

```text
real host event
→ exact source ownership in Store or durable spool
→ replay and restart
→ current-work reconstruction
→ actual context emission or explicit retrieval
→ exact source open
```

The first learning extension is:

```text
retained episode
→ exact processing recipe
→ one controller V2 call with a precommitted WriteId
→ typed result or unknown
→ ordinary Memory revision
→ changed later context
→ exact cleanup state
```

A provider result does not grant Memory authority or demonstrate external task completion.

## Controller boundary

The current inspected controller authority is `UnknownAlienHuman/eliot-swarm-controller@c8c0ee122c98a01be86bc5296a22a389662a1c89` from merged PR #197. It selects a fresh local JSON-RPC + SQLite WAL V2 with canonical external ULID `WriteId` receipts and treats the old Rust/`swarm-client`/Operation runtime as legacy pending deletion.

Memory therefore targets:

```text
principal = memory_inference
client_id = memory:<stable-installation-id>
token_version = current credential generation
call identity = client_id + WriteId + method + semantic payload
```

Memory commits `WriteId` before first send. Lost reply, restart or restore reuses the same ID and exact bytes. There is no separately discovered Operation ID, V1 protocol-v2 hello or Memory submission ledger. Exact details live only in [Contract 0.9](docs/v3/INFERENCE-CONTRACT.md).

Controller V2 must implement its own L0/L1 foundation before the inference extension. Do not patch its legacy runtime to make Memory appear connected.

## Repository work

Follow [AGENTS.md](AGENTS.md), [START.md](START.md) and [WORKFLOW.md](WORKFLOW.md). Work from current `main`, preserve unrelated changes, use one writer per mutable scope and obtain independent review before integration.

For implementation, follow the owner’s sequence:

```text
write connected production code
→ cargo fmt --check
→ minimum relevant package build/Clippy
→ continue vertical path
→ broad tests after the connected product exists
```

A documentation edit calls for documentation consistency checks. Runtime proof must match actual runtime behavior.

The [documentation map](docs/README.md) separates current V3 authority from V2 donor references. [PROJECT_MAP](docs/PROJECT_MAP.md), [scripts](scripts/README.md), [workstream records](workstreams/ACTIVE.toml) and the pinned Rust toolchain describe the retained V2 tree, not V3 deployment requirements.

## Related repositories

| Repository | V3 relationship |
|---|---|
| [eliot-swarm-controller](https://github.com/UnknownAlienHuman/eliot-swarm-controller) | External agent/task execution and the Contract 0.9 one-shot inference boundary after controller V2 L0/L1 exists |
| [eliot-search](https://github.com/UnknownAlienHuman/eliot-search) | Optional source preparation/retrieval adapter for a concrete selected path |
| [eliot-research](https://github.com/UnknownAlienHuman/eliot-research) | Optional external research/acquisition owner for a concrete remaining gap |

## V2 donor reading tools

The generated block below routes retained V2 documentation. It does not certify V3 or replace the current owner documents.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](docs/architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact repository paths and causal property being changed. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. The stable `ELIOT_*` files are compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->

## License

Eliot is licensed under the MIT License — see [LICENSE](LICENSE). Third-party code and runtimes retain their own licenses; verify the exact revision before reuse. The existing [dependency policy](docs/DEPENDENCY_POLICY.md) remains a V2 reference until a V3 dependency decision explicitly adopts or revises it.
