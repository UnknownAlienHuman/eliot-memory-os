# Eliot Memory OS

> **V3 is the current design authority.** V1 and V2 Memory implementations are archived donors. This documentation does not claim a V3 runtime exists.

Eliot preserves exact experience, reconstructs current work, supplies applicable context before the next decision, learns bounded procedures from observed outcomes and revises mistaken memory without losing source history.

## Start with V3

| Read | Purpose |
|---|---|
| [V3 navigation](docs/v3/README.md) | Current versions, reading order, selected construction and proof ceiling |
| [Architecture draft.14](docs/v3/ARCHITECTURE.md) | Product purpose, ownership, Base, extensions and invariants |
| [Implementation draft.35](docs/v3/IMPLEMENTATION.md) | Runtime, Store, Windows/process, durability, backup/rollback and implementation sequence |
| [Cognition draft.18](docs/v3/COGNITION.md) | Reconstruction, retrieval, learning, backup publication/dependencies and revision algorithms |
| [Inference Contract 0.13](docs/v3/INFERENCE-CONTRACT.md) | Sole normative Memory↔controller V2 boundary |
| [Active analysis registry](docs/v3/ANALYSIS-REGISTRY.md) | Current decisions, gaps, source coverage and queue |
| [Consolidated audit](docs/v3/AUDIT.md) | Evidence, criticism, donor analysis and rationale |

Architecture 14, Implementation 35, Cognition 18 and Contract 0.13 describe one synchronized design. Source presence, specification text, green build or receipt does not establish working behavior.

Current work: [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324), [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325).

## Version boundary

Existing Rust workspace, old architecture shards, scripts and workstream records describe **V2 Memory**. They remain selective donors; their checklists do not authorize continuing V2 implementation or importing its physical architecture into V3.

- [V2 source snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105)
- [V2 unfinished audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete)
- [V1 donor snapshot](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7)

[Architecture authority](docs/ARCHITECTURE_CONTRACT.md) records precedence. Active V3 owner documents define implementation target; audit explains evidence/alternatives without turning every idea into required subsystem.

## Selected product boundary

Memory owns durable observations, revisions, context, provenance, finite learning jobs and outcome-linked methods. Hosts/controllers own goals, actions, Agent/task execution and user acceptance.

Useful Base comes first:

```text
real host event
→ exact source ownership in Store or durable spool
→ replay and restart
→ current-work reconstruction
→ actual context emission or explicit retrieval
→ exact source open
```

First learning extension:

```text
retained episode
→ exact processing recipe
→ one controller V2 call with precommitted global WriteId
→ typed result or unknown
→ ordinary Memory revision
→ changed later context
→ crash-safe dependency fence and cleanup
```

Provider result does not grant Memory authority or prove external task completion.

## Controller boundary

Current inspected controller authority:

```text
UnknownAlienHuman/eliot-swarm-controller
main = 613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

It selects fresh local JSON-RPC + SQLite WAL V2 with global external ULID `WriteId` receipts and treats old Rust/`swarm-client`/generic Operation runtime as V1 legacy pending deletion.

Memory targets:

```text
principal_kind = memory_inference
client_id      = memory:<random-stable-installation-id>
token_version  = current credential version
live call ID   = global WriteId + client_id + method + semantic payload
```

Memory persists every caller mutation WriteId before send. One monotonic generator state lives outside rollback Store roots. Cancel, release and retention advance receive their own IDs.

Before controlled backup records high-water, Memory pauses/drains one controller-dispatch owner and classifies every created call ID:

```text
admitted                exact call and admission_seq exist
retired_not_admitted    exact healthy absence; old ID can never be sent
admission_unknown       controller continuity incomplete
```

Every admitted in-cut call is then:

```text
controller_closed       backup is self-contained
controller_dependent    backup still needs controller state/result/copy/readback
```

Before backup files are published, Memory durably records a provisional dependency fence naming expected manifest identity/digest and every dependent call. `preparing` and `publication_unknown` block release exactly like a retained backup. A rename that may have succeeded but lacks directory-sync/readback cannot clear the fence.

Old backup never first-admits absent call ID. While any retained or provisional backup marks a call dependent, Memory blocks release that would remove required controller state/copies. `retain_after_seq` remains a monotonic post-cut denominator and is not lowered for these dependencies.

Controller registration owns `last_admission_seq` and guaranteed `retain_after_seq`. Fixed-window inventory below cut returns `history_gap`. Erased content above cut leaves bounded text-free membership tombstone until every backup pinning interval is retired and cut advances.

With valid caller, cleanup uses optional `inference.cancel` and `inference.release(...)`. Controller-owner `inference.erase` is local break-glass. Memory never receives owner authority and records owner-action-required debt until non-content owner readback.

Exact details live only in [Contract 0.13](docs/v3/INFERENCE-CONTRACT.md).

Controller issue #200 must repair binding-revision allocator/schema authority. V2 L0/L1 must then exist before issue #199 implements Memory inference. Do not patch legacy controller runtime.

## Repository work

Follow [AGENTS.md](AGENTS.md), [START.md](START.md) and [WORKFLOW.md](WORKFLOW.md). Work from current `main`, preserve unrelated changes, use one writer per mutable scope and obtain independent review before integration.

Implementation sequence:

```text
write connected production code
→ cargo fmt --check
→ minimum relevant changed-package Clippy
→ continue vertical path
→ broad tests after connected product exists
```

A documentation edit calls for documentation consistency checks. Runtime proof must match actual runtime behavior.

The [documentation map](docs/README.md) separates V3 authority from V2 donor references. [PROJECT_MAP](docs/PROJECT_MAP.md), [scripts](scripts/README.md), [workstream records](workstreams/ACTIVE.toml) and pinned Rust toolchain describe retained V2 tree, not V3 deployment requirements.

## Related repositories

| Repository | V3 relationship |
|---|---|
| [eliot-swarm-controller](https://github.com/UnknownAlienHuman/eliot-swarm-controller) | External Agent/task owner and Contract 0.13 one-shot inference boundary after controller #200 + V2 L0/L1 |
| [eliot-search](https://github.com/UnknownAlienHuman/eliot-search) | Optional source preparation/retrieval adapter for concrete selected path |
| [eliot-research](https://github.com/UnknownAlienHuman/eliot-research) | Optional external research/acquisition owner for concrete remaining gap |

## V2 donor reading tools

The generated block below routes retained V2 documentation. It does not certify V3 or replace current owner documents.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](docs/architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact repository paths and causal property being changed. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. The stable `ELIOT_*` files are compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->

## License

Eliot is licensed under the MIT License — see [LICENSE](LICENSE). Third-party code and runtimes retain their own licenses; verify exact revision before reuse. Existing [dependency policy](docs/DEPENDENCY_POLICY.md) remains V2 reference until V3 decision explicitly adopts/revises it.