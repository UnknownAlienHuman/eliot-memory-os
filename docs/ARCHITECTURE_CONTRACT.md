# Architecture authority and version boundary

This page identifies owners and precedence. It is not another product specification.

## V3 working authority

The owner selected a fresh V3 design and retained V1/V2 Memory as donors.
PR #5325 is merged: `docs/v3/` on current `main` is the documentation baseline.
The exception for `docs/5324-v3-documentation-audit` has ended; do not revive it.
Merged design is not implemented behavior, independent review or runtime support.
The existing registry keeps unresolved decisions and verification work visible.

| Owner document | Decision owned |
|---|---|
| [Architecture](v3/ARCHITECTURE.md) | Product purpose, responsibility and invariants |
| [Implementation](v3/IMPLEMENTATION.md) | Runtime, Store, operations, maintenance and build order |
| [Cognition](v3/COGNITION.md) | Reconstruction, retrieval, learning and revision algorithms |
| [Inference contract](v3/INFERENCE-CONTRACT.md) | Proposed Memory/controller interface, not proof of provider support |

Architecture intent prevails over a conflicting mechanism. Correct the owning
mechanism and its consumers together before implementing the disputed behavior.
Do not resolve conflicts by inventing an exception in a README, issue, registry or
a new contract. An external repository owns its own accepted API; a Memory draft
cannot declare that API implemented or impose a superseded controller design.

The [registry](v3/ANALYSIS-REGISTRY.md#documentation-stages) tracks unresolved
consistency work, including controller compatibility. No blanket assertion that
all drafts are synchronized is made. Base work is not blocked by missing inference.

## Navigation and evidence

[Task routes](v3/README.md#task-routes) are navigation only. The
[registry](v3/ANALYSIS-REGISTRY.md) is the sole work ledger, not another normative
source. The [audit](v3/AUDIT.md) and [source map](v3/AUDIT-MAP.md) retain rationale
and bounded donor findings. Source review, selected design, compilation, observed
runtime behavior and product qualification are distinct; record the actual scope.

Do not copy external roadmap status or revision lists into entry pages. Keep a
dated, pinned observation in the existing registry and refresh it for an affected
integration decision. Read only the owning sections required by the task.

## Donors

V2 source baseline: `5aac094834fb5635921b550c821cb933a1196105`.
V1 donor: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`.
The V2 pair, router, workstream records and validators remain retained evidence;
they do not prescribe V3 topology or certify its design. Their machine migration
is a separate explicit change, not a consequence of this prose update.

Follow [AGENTS](../AGENTS.md) and [WORKFLOW](../WORKFLOW.md). Required checks and
independent integration remain applicable.
