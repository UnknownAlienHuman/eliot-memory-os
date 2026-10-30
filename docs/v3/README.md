# Eliot Memory OS V3

**Working design in PR #5325; not a qualified runtime.**

Memory preserves observations, revises knowledge and supplies useful context.
Hosts/controllers execute tasks and own permissions/acceptance. Base capture,
replay, exact/lexical retrieval and context must work without inference. Learning
later uses the same records and produces a revision consumed by a real caller.

Choose one route below. For file locations, a bounded assignment, exact check commands
and companion updates, use the [development guide](DEVELOPMENT.md). It is a task
reference, not another required book. Documentation work uses the
[existing stages](ANALYSIS-REGISTRY.md#documentation-stages); implementation order belongs
to [Implementation §11](IMPLEMENTATION.md#11-implementation-sequence). The
[version boundary](../ARCHITECTURE_CONTRACT.md) identifies document precedence.

## Task routes

| Change | Required starting sections | Expand only when |
|---|---|---|
| Entry pages, navigation or work registry | [AGENTS](../../AGENTS.md), [authority](../ARCHITECTURE_CONTRACT.md), affected index/registry row | A link or summary changes a product rule: read that owner section. |
| Product boundary or new mechanism | [Architecture §1–3](ARCHITECTURE.md#1-purpose-and-completion) | Follow the mechanism into Implementation; do not create an owner per noun. |
| Startup, processes, Windows IPC | [Implementation §1–3](IMPLEMENTATION.md#1-runtime-and-installation), [Architecture §2](ARCHITECTURE.md#2-ownership) | Identity, credentials, shutdown or restore custody changes. |
| Store schema, IDs, query or transaction | [Implementation §4–6](IMPLEMENTATION.md#4-migration-0001-and-schema-authority), [Store source ownership](store/README.md) | Follow the changed field/query to its writer and reader; inspect exact pinned upstream semantics when relied on. |
| Capture, spool, replay or host emission | [Implementation §7](IMPLEMENTATION.md#7-core-operations-and-host), [Cognition §1–2](COGNITION.md#1-observations-claims-and-revisions) | Context construction: read Cognition §6; maintenance crossing: read Implementation §8. |
| Retrieval, context, correction or learning | [Cognition §2–6](COGNITION.md#2-current-work-reconstruction), then the affected algorithm | Persistence: Implementation §4–7; external model call: Inference contract. |
| Backup, restore, erasure or rotation | [Implementation §8–10](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle), [Architecture §7–8](ARCHITECTURE.md#7-backup-authority) | Controller copies, release or retention are involved: read the matching Inference clauses. |
| Controller inference | [Inference contract](INFERENCE-CONTRACT.md), [current dependency finding](ANALYSIS-REGISTRY.md#controller-dependency) | Verify the live controller API/source before changing its adapter; current compatibility is unresolved. |
| Requirements, donor reuse or rejected design | Relevant item in [AUDIT-MAP](AUDIT-MAP.md), then its pinned source | Open [AUDIT](AUDIT.md) only for the disputed rationale, not as a default prompt. |

Section links are starting points, not permission to omit a boundary the change
actually crosses. Record the sections inspected in the PR; a navigation result
is not evidence that the text was understood.

## Small implementation rule

A change must connect a real caller → owning operation → durable result or typed
unknown → actual consumer/readback, including restart where persistence matters.
A standalone type, schema, port, receipt or passing compile is an intermediate
artifact, not completed product behavior.

Prefer an ordinary function/module and existing storage owner. A new process,
crate, table, protocol or dependency needs a concrete caller and a reason the
existing owner cannot serve it. Do not add parallel task/proof/report machinery.

The owner selects runtime work separately from this documentation task. For that
work, write production code first and run formatting/minimum changed-package
Clippy. Broad campaigns follow the assembled product; claims must still match
actual checks. The [registry stages](ANALYSIS-REGISTRY.md#documentation-stages)
are documentation work, not an alternative runtime scheduler.

## Design assets and dependencies

[Store source ownership](store/README.md) identifies one executable asset owner.
Its separate unmerged PR is not present in this documentation branch and is not
an admitted Store. The former docs SQL copies are retired; their exact historical
links and unresolved differences remain available. Do not dynamically load docs
or import a stale pack instead of fixing the owning source.

Controller foundation and Memory inference are different capabilities. Do not
copy a historical controller SHA or unchecked-roadmap claim into a current task.
Use the [pinned observation](ANALYSIS-REGISTRY.md#controller-dependency); missing
inference does not justify an Agent/Goal/owner-token fallback or block Base.

## Maintaining these documents

Correct the owner rule, update its direct consumers, then update the existing
registry row with remaining work and evidence. Indexes contain links and purpose,
not duplicated schema, backup algorithms, revision lists or CI status. Keep
chronology in Git and issue/PR discussion. No second ledger or errata document.

Use the [change-propagation map](DEVELOPMENT.md#change-propagation) to update only affected
owners, source projections and references. [Checks](DEVELOPMENT.md#checks) give exact
commands, their limits and failure actions. [Documentation integration](DEVELOPMENT.md#documentation-integration)
separates merge evidence from unfinished product work; existing CI and independent
review still apply under [WORKFLOW](../../WORKFLOW.md).
