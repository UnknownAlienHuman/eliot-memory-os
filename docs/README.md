# Documentation map

## Current work: V3 design

The owner retired V1/V2 Memory implementations as active product designs and selected a fresh V3 implementation. These files are design authority, not evidence of implemented runtime support.

| Need | Current V3 source |
|---|---|
| Stage, versions, reading order and proof ceiling | [v3/README.md](v3/README.md) |
| Product purpose, ownership and invariants | [v3/ARCHITECTURE.md](v3/ARCHITECTURE.md) — draft.16 |
| Runtime, Store, maintenance and implementation order | [v3/IMPLEMENTATION.md](v3/IMPLEMENTATION.md) — draft.37 |
| Reconstruction, retrieval, learning, rollback-safe backup dependencies/retirement and revision algorithms | [v3/COGNITION.md](v3/COGNITION.md) — draft.20 |
| Memory↔controller V2 boundary | [v3/INFERENCE-CONTRACT.md](v3/INFERENCE-CONTRACT.md) — Contract 0.15 |
| Active decisions, gaps, source coverage and queue | [v3/ANALYSIS-REGISTRY.md](v3/ANALYSIS-REGISTRY.md) |
| Consolidated evidence, criticism and donor rationale | [v3/AUDIT.md](v3/AUDIT.md) |
| Requirement/source dispositions | [v3/AUDIT-MAP.md](v3/AUDIT-MAP.md) |
| Version precedence | [ARCHITECTURE_CONTRACT.md](ARCHITECTURE_CONTRACT.md) |
| Repository workflow | [../AGENTS.md](../AGENTS.md), [../START.md](../START.md), [../WORKFLOW.md](../WORKFLOW.md) |

Read Architecture, Implementation, Cognition and Inference Contract together when changing a load-bearing V3 boundary. `ANALYSIS-REGISTRY.md` is the only active audit/work ledger. Consolidated audit is evidence/rationale, not another normative book or task generator.

### Current controller boundary

Inspected authority:

```text
eliot-swarm-controller@613ea6b5ff6389c7629a988e271477ee45c9d2c1
merged PR #198
```

It selects fresh local JSON-RPC + SQLite WAL V2 with global external ULID `WriteId` receipts and declares old Rust/`swarm-client`/generic Operation runtime legacy.

Memory uses dedicated `memory_inference` principal, stable random installation client ID, monotonic token version, rollback-safe installation WriteId state, private call-owned input/result copies and admission-sequence restore inventory.

Controlled backup closes one controller-mutation owner before high-water: every created call ID is admitted, permanently retired as proven absent, or explicitly unknown. Every admitted in-cut call is `controller_closed` or `controller_dependent`.

Before any backup part, Memory computes a canonical non-self-referential `backup_plan_digest` and durably publishes installation-scoped `backups/<id>/fence.json` outside rollback Store roots. Final manifest repeats plan digest and actual inventories. Store job mirrors status but is not authority.

A published backup leaves the restorable set only after a create-new durable `retire.json` binds backup ID, plan digest and observed manifest digest. Deleting fence/manifest/parts is not retirement. `abort.json` applies only before publication; abort and retire are mutually exclusive.

Until retirement-marker readback succeeds, backup remains restorable and pins release/retention. After success, restore refuses it and pins may be recomputed. Content cleanup is later and retirement tombstone remains; retirement is not physical erasure.

`preparing` and `publication_unknown` provisional fences block release and pin post-cut retention. A dependent call cannot be released while any published non-retired or unresolved provisional backup needs controller state/result/copy. `retain_after_seq` remains monotonic and is not lowered for in-cut dependencies. Calls erased above cut retain bounded text-free membership tombstones until cut advances.

Caller cleanup uses cancel/release. Controller-owner erase is external break-glass; Memory cannot submit it and retains owner-action-required debt until observed readback.

Old V1 hello, generic Operation/artifact ownership and submission-state paths are donor history. Controller issue #200 plus V2 L0/L1 are prerequisites for issue #199 and Contract 0.15 runtime implementation.

## Retained V2 donor documentation

These files describe old Memory tree. Their historical use of “current,” “active” or “accepted” refers to V2 unless a current V3 owner document explicitly adopts bounded property. They do not grant authority to resume old programmes.

V2 ACTIVE registry and validators retain historical values. This branch establishes human-directed version boundary; it does not migrate that machine registry or claim machine-enforced freeze.

| Need | V2 donor reference |
|---|---|
| Accepted V2 pair identity and fragments | [normative-pair.toml](normative-pair.toml), [architecture/](architecture/) |
| Verified source reading and routing | [architecture/READING_PROTOCOL.md](architecture/READING_PROTOCOL.md) |
| Workspace/prototype navigation | [code-navigation/PACKAGE_DOCS_INDEX.md](code-navigation/PACKAGE_DOCS_INDEX.md), [code-navigation/PROTOTYPE_DOCS_INDEX.md](code-navigation/PROTOTYPE_DOCS_INDEX.md) |
| Cargo composition and code navigation | [PROJECT_MAP.md](PROJECT_MAP.md), [CODE_NAVIGATION.md](CODE_NAVIGATION.md) |
| Existing script contracts | [../scripts/README.md](../scripts/README.md) |
| Historical programme records | [../workstreams/ACTIVE.toml](../workstreams/ACTIVE.toml) |
| Dependency, operations, releases, integrations, ADRs | [DEPENDENCY_POLICY.md](DEPENDENCY_POLICY.md), [operations/](operations/), [release/](release/), [integrations/](integrations/), [ADR/](ADR/) |

Generated routing block below applies only to donor surfaces. Its receipts attest to exact bytes read; they do not make V3 mechanism implemented or inherit V2 topology.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact repository paths and causal property being changed. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. The stable `ELIOT_*` files are compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->

## Documentation checks and evidence

For V3 documentation, verify current version/status consistency, links, ownership, normal/failure paths, source attribution and `git diff --check`. A donor verifier applies only when its governed donor surface changed; never regenerate V2 normative pair as fictitious V3 adoption evidence.

Keep requested consolidated audit and stable design rationale in Git. Raw research downloads, generated bundles/receipts, local databases, agent transcripts and temporary review notes remain outside source tree. Record executed checks, limits and uncertainty in issue/PR. Repository CI/integration ownership remain governed by WORKFLOW.