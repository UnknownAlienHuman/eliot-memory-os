# Eliot Memory OS

> **V3 is the current design authority.** V1 and V2 Memory implementations are archived donors. This documentation does not claim a V3 runtime exists.

Eliot preserves exact experience, reconstructs current work, supplies applicable context before the next decision, learns bounded procedures from observed outcomes and revises mistaken memory without losing source history.

## Start with V3

| Read | Purpose |
|---|---|
| [V3 navigation](docs/v3/README.md) | Current versions, reading order, selected construction and proof ceiling |
| [Architecture draft.16](docs/v3/ARCHITECTURE.md) | Product purpose, ownership, Base, extensions and invariants |
| [Implementation draft.37](docs/v3/IMPLEMENTATION.md) | Runtime, Store, Windows/process, durability, backup/rollback and implementation sequence |
| [Cognition draft.20](docs/v3/COGNITION.md) | Reconstruction, retrieval, learning, rollback-safe backup dependencies/retirement and revision algorithms |
| [Inference Contract 0.15](docs/v3/INFERENCE-CONTRACT.md) | Sole normative Memory↔controller V2 boundary |
| [Active analysis registry](docs/v3/ANALYSIS-REGISTRY.md) | Current decisions, gaps, source coverage and queue |
| [Consolidated audit](docs/v3/AUDIT.md) | Evidence, criticism, donor analysis and rationale |

Architecture 16, Implementation 37, Cognition 20 and Contract 0.15 describe one synchronized design. Source presence, specification text, green build or receipt does not establish working behavior.

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
→ rollback-safe backup publication/retirement authority
→ dependency-aware cleanup
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

Memory persists every caller mutation WriteId before send. One monotonic generator state lives outside rollback Store roots. Call admission, cancel, release and retention advance are serialized through one controller-mutation owner.

Before controlled backup records high-water, Memory closes/drains that owner and classifies every created call ID:

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

Old backup never first-admits absent call ID. While any retained or provisional backup marks a call dependent, Memory blocks release that would remove required controller state/copies. `retain_after_seq` remains monotonic and is not lowered for these in-cut dependencies.

### Rollback-safe backup publication

Before writing backup parts, Memory captures the exact spool/controller cut, constructs a canonical immutable plan and computes `backup_plan_digest` over a field set that excludes the digest itself, publication state and later part/manifest digests.

It durably publishes:

```text
backups/<backup-id>/fence.json
```

outside rollback Store roots. Final `manifest.json` repeats the plan digest plus actual inventories. There is no precommitted final-manifest digest inside Store data being backed up.

### Monotonic backup retirement

Controlled records:

```text
fence.json
parts/...
manifest.json
abort.json?     # candidate never became published
retire.json?    # valid published backup made non-restorable
```

A published backup is retired only by create-new durable `retire.json` binding backup ID, plan digest, observed manifest digest and local retirement operation. Deleting manifest/fence/parts is not retirement. `abort.json` and `retire.json` are mutually exclusive.

Until retirement-marker readback succeeds, backup remains restorable and pins release/retention. After success, restore refuses it and pins may be recomputed. Physical content cleanup is later; retirement tombstone remains. Retirement is not physical erasure.

`preparing` and `publication_unknown` provisional fences pin both dependent-call release and post-cut retention at their high-water. Exact Memory rollback cannot erase this authority.

Controller registration owns `last_admission_seq` and guaranteed `retain_after_seq`. Fixed-window inventory below cut returns `history_gap`. Erased content above cut leaves bounded text-free membership tombstone until every backup pinning interval is retired and cut advances.

With valid caller, cleanup uses optional `inference.cancel` and `inference.release(...)`. Controller-owner `inference.erase` is local break-glass. Memory never receives owner authority and records owner-action-required debt until non-content owner readback.

Exact details live only in [Contract 0.15](docs/v3/INFERENCE-CONTRACT.md).

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
| [eliot-swarm-controller](https://github.com/UnknownAlienHuman/eliot-swarm-controller) | External Agent/task owner and Contract 0.15 one-shot inference boundary after controller #200 + V2 L0/L1 |
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