# Eliot Memory OS V3 — documentation

**Revision 0.14 · 2026-10-20.** Documentation before the greenfield rewrite. V1/V2 remain donors; these documents do not implement the product.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose, cognition, automatic learning and ownership; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths, work and recovery; remains 0.11 |
| [Cognition](COGNITION.md) | Algorithms inside those modules; 0.14 adds useful associations, recall entrances and exposure control |
| [Consolidated audit](AUDIT.md) | Source findings, 34 original requirements, 29 A15 cases and donors D01–D44 |
| [Audit map](AUDIT-MAP.md) | Actual fresh/prior reading and the next source paths |

## Current result: different donors, concrete consumers

[Audit §28](AUDIT.md#28-associations-and-useful-forgetting-014) studies **D43 A-MEM, D19 Nocturne Memory and D03 Subcog**. It separates the research idea, published library code and Eliot's proposed use rather than treating a benchmark or completed specification as proof of a working integration.

A-MEM motivates updating an older lesson's useful search description and meaningful relations when new experience changes its interpretation. The inspected library also shows why the actual path matters: result positions are used as storage positions, added neighbors can fall beyond the final cutoff, and metadata evolution does not automatically change the text being searched.

Nocturne supplies stable content identity with multiple entrances and a real renderer that presents selected content plus short clues for related detail. Eliot uses ordinary cues/links and `open`; it does not inherit a mandatory boot ritual, a prescribed agent personality, a materialized URI hierarchy or the idea that all contradictions must disappear.

Subcog supplies independent text/vector retrieval and ordinary rank fusion. Its per-result maximum normalization is relative ranking, not certainty. A separate lifecycle helper's constant importance prevents its own Archive threshold from being reached; that limited source finding is not a claim that all Subcog consolidation is broken. Eliot reduces unnecessary proactive detail without confusing access frequency, truth and erasure.

Cognition updates §2, §5.2, [§5.4](COGNITION.md#54-recall-clues-without-a-mandatory-navigation-ritual), §6.8 and §7. One lesson has several ways to be found; real indexed representations change when appropriate; useful neighbors are considered before final packing; permitted history remains accessible when no longer shown by default. No new service, store, approval protocol or test matrix is introduced.

## Continuing work

Previous work remains: [§27](AUDIT.md#27-episodes-incremental-learning-and-memory-feedback-013) separates episodes from search chunks and excludes known injected context from fresh interpretation; [§26](AUDIT.md#26-donor-mechanisms-for-useful-memory-012) covers scoped updates, saved questions and source-episode expansion; [§25](AUDIT.md#25-real-experience-input-and-normal-context-010) distinguishes real experience input/consumers from fabricated skill surfaces.

The [map](AUDIT-MAP.md) next selects MAGMA and Letta for concrete adaptive-retrieval/context mechanisms, while keeping the actual Eliot capture-to-job edge, Graphiti temporal caller, Hindsight full retain boundary and ORS/process gaps visible. The donor registry is not a list of mandatory dependencies.

V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Earlier detail remains in [Git history](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/f82b7ff884c57412becb747e4fb673495c2df271/docs/v3); archived research is in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Report actual commit/ref/diff/CI there. This pass is source reading and design review, not a donor/model/database run or independent subagent review. Existing requirement/scenario identities remain; runtime, schema, dependencies, CI, old ACTIVE registry and user data are unchanged. Product implementation follows the documentation stage and the owner's product-code/minimum-Clippy/tests-later order.
