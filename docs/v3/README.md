# Eliot Memory OS V3 — documentation

**Revision 0.12 · 2026-10-20.** Documentation before the greenfield rewrite. V1/V2 remain donors; the product has not been implemented by these documents.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose, cognition, automatic learning and module boundaries; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Direct native Store/host/controller paths, background work and practical recovery; remains 0.11 |
| [Cognition](COGNITION.md) | Algorithms inside the same modules; 0.12 adds selected donor mechanisms |
| [Consolidated audit](AUDIT.md) | Source findings, 34 original requirements, 29 A15 cases and donors D01–D44 |
| [Audit map](AUDIT-MAP.md) | Exact fresh/prior reading, limits and the next useful source paths |

## Current donor work

[Audit §26](AUDIT.md#26-donor-mechanisms-for-useful-memory-012) studies D09 Hindsight, D01 MemMachine and D08 Graphiti at named source revisions. It distinguishes their actual code/documentation from the proposed Eliot implementation:

- Hindsight: update a particular aspect using existing related records, batch compatible interpretation/embedding work, and save an answer to a recurring question instead of regenerating an entire project report.
- MemMachine: a short search hit can lead to its original episode and relevant neighboring events, including a later repair and result. The inspected declarative backend is not all MemMachine behavior.
- Graphiti: separate when a fact applied from when it was learned; search for changed facts more broadly than exact duplicate endpoints. Preserve historical occurrences without a whole-graph rebuild.

These refine ordinary `memory`, `context` and `jobs`, not three new runtime dependencies. The donor's terminology and limits are recorded: Hindsight observations are synthesized knowledge; its documented staleness check does not see deletions. MemMachine's selected low-level writer is not a raw-first guarantee. Graphiti's temporal helper concern is a conditional source finding, not a reproduced deployment failure.

Cognition §3 clarifies temporal occurrences; §§4.1–4.2 make useful question-shaped views concrete; [§5.3](COGNITION.md#53-recover-the-episode-not-just-the-matching-fragment) describes source-episode expansion; §6.8 specifies incremental same-aspect updates and compatible batching. There is no new promotion gate, separate episodic database, ontology service or compulsory extra interpretation pass. Existing useful primary reads remain available.

## Earlier work retained

[Audit §25](AUDIT.md#25-real-experience-input-and-normal-context-010) distinguishes a real experience consumer from its map/maturity dependencies, generated skill cards from stored methods, and fabricated execution proof from host observations. [Cognition §6.8](COGNITION.md#68-one-episode-to-a-useful-next-attempt) connects a captured episode or explicit correction to useful advice in a subsequent context.

The 0.11 Implementation specifies native host events, actual stored records, native database operations and connected product work rather than success-shaped scaffolding. Ordinary advice does not wait for global graph readiness, optional diagnostics or a universal effectiveness certificate.

The existing requirement/scenario/donor identities and thirty-six cognitive walkthroughs remain. They are design expectations, not executed product tests. No new checklist family is added.

## Continuing work and publication

The [map](AUDIT-MAP.md) now prioritizes MemMachine event/semantic segmentation, Hindsight retain/retrieval callers and Graphiti temporal search filters. The actual Eliot episode-scheduling edge, remaining Harness2 executor/reset work and ORS ownership are still explicit open reads. A donor name in the registry does not mean its whole code or experiments were reviewed.

V2 source: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Earlier documentation is retained in [Git history](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5c5e23dfe8470c26e036d2f5ec6b90c671c0dc43/docs/v3); archived research remains in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Record actual publication/diff/CI there. This pass is source reading, not a live donor/model/database experiment or independent subagent review. Runtime, schemas, dependencies, CI, the old ACTIVE registry and user data are unchanged. Product implementation follows the documentation stage and the owner's product-code/minimum-Clippy/tests-later order.
