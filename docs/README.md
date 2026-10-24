# Documentation map

## Current work: V3 design

The owner has retired V1/V2 as active product designs and selected a fresh V3 implementation **after documentation**. The files below are the current design discussion. They are drafts, not evidence of implemented or accepted runtime support.

| Need | Source |
|---|---|
| Stage, reading order, donor pins, open decisions | [v3/README.md](v3/README.md) |
| Purpose and preserved properties | [v3/ARCHITECTURE.md](v3/ARCHITECTURE.md) |
| Proposed mechanisms and future behavioral scenarios | [v3/IMPLEMENTATION.md](v3/IMPLEMENTATION.md) |
| Consolidated Russian audit, 34 requirements, 29 original scenarios, donor map | [v3/AUDIT.md](v3/AUDIT.md) |
| Version precedence | [ARCHITECTURE_CONTRACT.md](ARCHITECTURE_CONTRACT.md) |
| Current repository workflow | [../AGENTS.md](../AGENTS.md), [../START.md](../START.md), [../WORKFLOW.md](../WORKFLOW.md) |

Read Architecture and Implementation together when changing a V3 contract. Follow the relevant audit evidence back to its source. The audit is a requested consolidated deliverable; it is not an extra normative book or a task generator.

## Retained V2 donor documentation

These files describe the old tree. Their historical use of “current,” “active,” or “accepted” refers to V2 unless a V3 decision explicitly adopts a bounded part. They do not grant authority to resume the old programmes.

The V2 ACTIVE registry and its validators still retain their original active values. This documentation change establishes the human-directed version/scope boundary; it does not migrate that machine registry or claim a machine-enforced freeze.

| Need | V2 donor reference |
|---|---|
| Accepted V2 pair identity and fragments | [normative-pair.toml](normative-pair.toml), [architecture/](architecture/) |
| Verified source reading and routing | [architecture/READING_PROTOCOL.md](architecture/READING_PROTOCOL.md) |
| Workspace/prototype package navigation | [code-navigation/PACKAGE_DOCS_INDEX.md](code-navigation/PACKAGE_DOCS_INDEX.md), [code-navigation/PROTOTYPE_DOCS_INDEX.md](code-navigation/PROTOTYPE_DOCS_INDEX.md) |
| Cargo composition and code navigation | [PROJECT_MAP.md](PROJECT_MAP.md), [CODE_NAVIGATION.md](CODE_NAVIGATION.md) |
| Existing script contracts | [../scripts/README.md](../scripts/README.md) |
| Historical programme records | [../workstreams/ACTIVE.toml](../workstreams/ACTIVE.toml) |
| Dependency, operations, releases, integrations, ADRs | [DEPENDENCY_POLICY.md](DEPENDENCY_POLICY.md), [operations/](operations/), [release/](release/), [integrations/](integrations/), [ADR/](ADR/) |

The generated routing block below applies to these donor surfaces. Its receipts attest to exact bytes read; they do not make a proposed V3 mechanism implemented or inherit V2's physical topology.

<!-- eliot-doc-routing:start -->
## Documentation entry point

Start with the [mandatory verified-reading protocol](architecture/READING_PROTOCOL.md), then run `python scripts/docs_read.py read ...` for the exact repository paths and causal property being changed. Open the verified bundle and record its read receipt before mutation. A route alone is navigation, not reading evidence. The stable `ELIOT_*` files are compatibility maps, not task prompts.
<!-- eliot-doc-routing:end -->

## Documentation checks and evidence

For V3 documentation, verify changed Markdown links, version/status consistency, preservation of the required behavior, and `git diff --check`. Use a relevant donor verifier when changing a donor projection or index; do not regenerate the V2 normative pair as a fictitious V3 adoption receipt.

Keep the requested consolidated audit and stable design rationale in Git. Raw downloaded research, generated bundles/receipts, local databases, agent transcripts, and temporary review notes remain outside the source tree. Record executed checks, their limits, and remaining questions in the issue/PR. Repository CI requirements and integration ownership remain governed by WORKFLOW.
