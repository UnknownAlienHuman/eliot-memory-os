# Eliot Memory OS V3 — documentation

**Revision 0.13 · 2026-10-20.** Documentation before the greenfield rewrite. V1/V2 remain donors; these documents do not implement the product.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose, cognition, automatic learning and boundaries; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths and connected product work; remains 0.11 |
| [Cognition](COGNITION.md) | Algorithms inside those modules; 0.13 refines episode intake and incremental learning |
| [Consolidated audit](AUDIT.md) | Source findings, 34 requirements, 29 A15 cases and D01–D44 |
| [Audit map](AUDIT-MAP.md) | Actual source coverage, limits and next connected reading |

## Current donor result

[Audit §27](AUDIT.md#27-episodes-incremental-learning-and-memory-feedback-013) continues MemMachine and Hindsight beyond their architectural descriptions. It follows actual segment/derive code, semantic-ingestion callers and storage, and Hindsight's retention hooks and selected retain orchestration.

The resulting Eliot choices are small: ordinary text splitting prepares search inputs but does not define a working episode; related host events form useful interpretation input; only new material and relevant prior context need processing. The adapter excludes its own injected memory from fresh learning input instead of generating successive copies of the same advice. Actual tool outcomes remain separate from a chat report.

A successful no-change is not a missing parsed result or an oversized failed request. Progress belongs to the work actually completed, without blocking access to preserved data. Existing facts are selected for relevance to an update, not always from the oldest fixed-size page. A short follow-up uses the active goal/resources and nearby original turns, without a mandatory model-mediated query rewrite.

These changes belong to Cognition §§1,5.2,6.3,6.6,6.8. No new service, store, approval stage, parser framework or checklist family is added. Hindsight's delta behavior is conditional on its retain path/backend; MemMachine findings concern the inspected ingestion and PostgreSQL storage, not every deployment.

## Earlier mechanisms retained

[Audit §26](AUDIT.md#26-donor-mechanisms-for-useful-memory-012) records Hindsight's same-aspect updates and saved questions, MemMachine's source-episode expansion, and Graphiti's temporal resolution. [§25](AUDIT.md#25-real-experience-input-and-normal-context-010) distinguishes genuine Eliot inputs/consumers from generated skill cards and success-shaped proof records.

Architecture and Implementation are unchanged. All existing requirement/scenario/donor families and thirty-six cognitive walkthroughs remain. They are design expectations, not executed product tests. Historical full documentation is available in [Git history](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/6f4ea70830d5964dc58be549657b0770d828d468/docs/v3).

## Remaining reading and publication

The [map](AUDIT-MAP.md) retains the unresolved Eliot tool-outcome-to-interpretation edge, Graphiti temporal caller, Hindsight top-level queued/inline retain boundary, Harness2 reset/executor and ORS ownership. Unavailable large-file content is not evidence that its implementation is absent; navigation searches are not complete reads.

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Report actual commit/ref/diff/CI there. This pass is source reading and design review, not a donor/model/database run or independent subagent review. Runtime, schema, dependencies, CI, old ACTIVE registry and user data are unchanged. Product implementation follows the documentation stage and the owner's product-code/minimum-Clippy/tests-later order.
