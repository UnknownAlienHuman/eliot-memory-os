# Eliot Memory OS V3

**Documentation baseline on `main`; PR #5325 is merged. Not a qualified runtime.**

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

Start implementation with [the connected sequence](IMPLEMENTATION.md#11-implementation-sequence):
repair the existing Store asset owner, then inline capture → commit/replay identity →
exact open. [Source placement](IMPLEMENTATION.md#111-source-placement-and-handoff)
distinguishes the existing proposal from the not-yet-created runtime. V2 validator and
archive migration are not prerequisites for that path.

## Task routes

Root and applicable inherited instructions apply once under
[AGENTS](../../AGENTS.md#select-the-version-and-task). Select the row for the actual
change, not every row mentioning the same subsystem. Read the linked section and the
definitions it uses; expand along changed data/effects, not every outgoing link.

| Change | Start here | Expand for this dependency |
|---|---|---|
| Entry pages, navigation or registry | [Authority](../ARCHITECTURE_CONTRACT.md), affected instruction/index/registry row | Follow the route to its named owner/source/check; read product rules only when their meaning changes. |
| Local source repair with unchanged behavior, such as a missing import | Applicable source instructions, failing symbol and its definition/caller; [package checks](DEVELOPMENT.md#rust-source) | Any changed field, query, public behavior or dependency selects its operation row below. A compile repair alone needs no whole Store book. |
| Product boundary or new mechanism | [Architecture §1–3](ARCHITECTURE.md#1-purpose-and-completion) | Follow the mechanism into its owning operation; do not create an owner per noun. |
| Startup, processes or Windows IPC | Relevant subsection of [Implementation §1–3](IMPLEMENTATION.md#1-runtime-and-installation) | [Architecture ownership](ARCHITECTURE.md#2-ownership) for moved responsibility; credentials, shutdown or restore only when crossed. |
| Store schema, IDs or projections | Changed clause of [Implementation §4](IMPLEMENTATION.md#4-migration-0001-and-schema-authority), [Store source map](store/README.md) | Follow that field through its writer/decoder/history; query shape uses §5, atomicity §6, exact pinned upstream semantics when relied on. |
| Store query or transaction | [Fixed operations](IMPLEMENTATION.md#5-fixed-query-corpus), [transactions](IMPLEMENTATION.md#6-transactions-and-durable-files), affected operation in §7 | Read that operation's fields/limits in §4 and actual writer/reader, not unrelated backup or inference contracts. |
| Capture identity or replay result | [Capture command](IMPLEMENTATION.md#72-capture-command-commit-and-replay), [observations/binding](COGNITION.md#1-observations-claims-and-revisions) | Capture policy §7.1, ID/field definitions §4, transaction §6; durable host ingress adds §7.5. |
| Spool custody or restart | [Durable ingress](IMPLEMENTATION.md#75-durable-ingress-and-replay), [durable files](IMPLEMENTATION.md#6-transactions-and-durable-files) | Its owning command/result (§7.2 or §7.4); restore rules only for rollback/cutover. |
| Direct memory creation or correction | [Revision command/publication](IMPLEMENTATION.md#74-direct-revision-and-lost-replies), [direct updates](COGNITION.md#5-direct-updates) | Changed fields/limits §4; grounds Cognition §3; exact read §7.3; notice/context rules only for affected publication or delivery. |
| Current-work binding, grounds or retrieval | Changed subsection of [Cognition §2–3](COGNITION.md#2-current-work-reconstruction) or [§6.1–6.4](COGNITION.md#61-decision-frame) | Scoped Store queries/projections and exact open; packet or emission only if their output changes. |
| Exact source/history open | [Implementation §7.3](IMPLEMENTATION.md#73-exact-open-and-byte-ranges), actual projection/decoder | Relevant field/hash/history definitions and current authorization; not search or inference. |
| Context packet or host emission | [Packet](COGNITION.md#641-base-packet-encoding) for encoding; [handoff](COGNITION.md#65-handoff) for emission | Packing/qualifiers and source open; custody, notices or cutover only where crossed. Verify the installed host boundary before enabling it. |
| Episode coverage, jobs or learning | [Coverage](COGNITION.md#4-episode-membership-and-coverage), [job lifecycle](COGNITION.md#8-processing-methods-and-jobs) or [attribution](COGNITION.md#12-consolidation-disagreement-and-improvement), whichever changes | Scheduler/claim uses Implementation §4.7.3; publishing uses §7.4; an external call uses the matching Inference clause. |
| Backup, restore, erasure or rotation | Affected subsection of [Implementation §8–10](IMPLEMENTATION.md#8-backup-set-owner-and-lifecycle) | [Architecture §7–8](ARCHITECTURE.md#7-backup-authority) for authority changes; Inference only for external copies, release or retention. |
| Controller inference | [Prerequisites](INFERENCE-CONTRACT.md#0-authority-and-prerequisites), affected interface clause and [dependency finding](ANALYSIS-REGISTRY.md#controller-dependency) | Verify the live controller API/source before changing its adapter; do not substitute a historical claim. |
| Requirements or donor reuse | Relevant [AUDIT-MAP](AUDIT-MAP.md) item, then its pinned source | Open [AUDIT](AUDIT.md) only for disputed rationale, not as a default prompt. |

Use [one applicable check](DEVELOPMENT.md#checks) and the directly affected
[companion updates](DEVELOPMENT.md#change-propagation). Record inspected sections and
actual results in the existing PR. These human task routes do not change the machine
reader's required set or waive [integration evidence](DEVELOPMENT.md#documentation-integration).

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
Verify its separate source PR and current code; merging documentation does not
admit that Store implementation. The former docs SQL copies are retired; their exact historical
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
Use the [retirement recipe](DEVELOPMENT.md#retiring-documentation) before removing legacy material;
file count is not a reason to delete a real input or retain an orphan projection.

Use the [change-propagation map](DEVELOPMENT.md#change-propagation) to update only affected
owners, source projections and references. [Checks](DEVELOPMENT.md#checks) give exact
commands, their limits and failure actions. [Documentation integration](DEVELOPMENT.md#documentation-integration)
separates merge evidence from unfinished product work; existing CI and independent
review still apply under [WORKFLOW](../../WORKFLOW.md).
