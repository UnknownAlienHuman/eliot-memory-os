# Eliot Memory OS V3

**V3 design baseline; not a qualified runtime.**

Eliot retains evidence and reconstructs a compact
[working model](ARCHITECTURE.md#1-purpose-and-completion): goal/criterion, mechanism, state,
attempts/results, uncertainty and next step. Base captures and assembles context without
inference; Dreamer prepares reusable knowledge and answers explicit Research questions.
Hosts/controllers execute tasks and own permissions/acceptance.

Choose one task route below. The [development guide](DEVELOPMENT.md) gives file scope,
checks and companion updates; the [registry](ANALYSIS-REGISTRY.md#documentation-stages)
tracks work; the [version boundary](../ARCHITECTURE_CONTRACT.md) defines precedence.

For the first runtime increment, follow [Implementation §11](IMPLEMENTATION.md#11-implementation-sequence):
repair the Store asset owner, then inline capture → commit/replay identity → exact open.
[Source placement](IMPLEMENTATION.md#111-source-placement-and-handoff) separates the
existing proposal from the planned runtime. V2 validator/archive migration is not a prerequisite.

## Task routes

Apply [AGENTS](../../AGENTS.md#select-the-version-and-task) and inherited instructions.
Select the actual change; read its owner and required definitions. Expand only along
affected data/effects; unrelated links do not add reading requirements.

| Change | Start here | Expand for this dependency |
|---|---|---|
| Entry pages, navigation or registry | [Authority](../ARCHITECTURE_CONTRACT.md), affected entry | Check that entry's owner/source/check route; expand into product rules only when their meaning changes. |
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

Use the [applicable check](DEVELOPMENT.md#checks) and
[companion updates](DEVELOPMENT.md#change-propagation); record inspected sections and
actual results in the existing PR. Human routes do not waive the machine reader or
[integration evidence](DEVELOPMENT.md#documentation-integration).

## Small implementation rule

Connect caller → owning operation → durable result/typed unknown → consumer/readback,
including restart for persistent effects. Scaffolding or compilation alone is incomplete.
Prefer existing functions/modules and storage owners; a new process/crate/table/protocol/
dependency needs a caller the existing owner cannot serve. No parallel task/proof/report machinery.

Runtime work is separately assigned. Write production code first, then formatting/minimum
changed-package Clippy; broad campaigns follow the assembled product. Follow the
[source checks](DEVELOPMENT.md#rust-source) for that increment, not documentation stages.

## Design assets and dependencies

[Store source ownership](store/README.md) identifies the executable asset owner and
retired SQL copies. Check its retained candidate and [assignment disposition](ANALYSIS-REGISTRY.md#implementation-handoff); docs approval is not implementation
acceptance. Fix owning source rather than loading docs or importing a stale pack.

The [controller observation](ANALYSIS-REGISTRY.md#controller-dependency) is pinned, not
current capability proof. Foundation and Memory inference differ; missing inference
does not justify Agent/Goal/owner-token fallback or block Base.

## Maintaining these documents

Correct the owner and direct consumers; update the existing registry row with remaining
work and evidence. Indexes link to contracts; chronology stays in Git/PR discussion.
No second ledger. Follow the [retirement recipe](DEVELOPMENT.md#retiring-documentation)
before deleting legacy material: check real consumers, not file counts.
Existing CI and independent review still apply under [WORKFLOW](../../WORKFLOW.md).
