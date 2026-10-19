# Eliot Memory OS V3 — documentation

**Revision 0.4 · 2026-10-19 · documentation stage.** V1/V2 are donors. V3 will be written from scratch after documentation is agreed. No product runtime, database migration or model integration is implemented by this revision.

## Reading order

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Stable product manifesto: purpose, preserved cognition/learning, ownership and boundaries |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Runtime, storage, host, controller, jobs, learning and recovery contracts |
| [COGNITION.md](COGNITION.md) | Implementation chapter: current-value resolution, project views, applicability and criterion-specific learning inside the existing modules |
| [AUDIT.md](AUDIT.md) | One Russian consolidated audit; prior findings, 34 requirements, all 29 original scenarios, 43 donor entries and current-pass findings in §17 |

Read Architecture and the relevant Implementation chapters together for a contract change. Cognition expands the existing module responsibilities; it is not another architecture, service or audit. Use the consolidated audit for exact sources, rejected mechanisms and evidence limits. New research does not automatically authorize a new subsystem.

## What revision 0.4 adds

[Cognition](COGNITION.md) now specifies atomic replacement publication, explicit scoped retirement without implicit resurrection, multi-predecessor history traversal, independent lexical candidates and target-check coverage for learning. A new session summary does not supersede every claim from the preceding session. Failed or skipped verification does not become a positive outcome merely because one diagnostic was absent.

[Audit §17](AUDIT.md#17-memory-transition-audit-04) records the pinned Hy coding reconciliation/store paths and two isolated SQL reproductions: retire-before-insert failure and an omitted history branch. It distinguishes those probes from a deployed Hy test. Current SurrealDB filtering documentation informs the query choice without qualifying an installed server. These changes refine existing operations; no new service, queue or semantic store is introduced.

Architecture remains at 0.2 and the runtime/integration overview at 0.3; Cognition 0.4 is their implementation chapter, not a competing specification. Earlier audit sections and the 34/29/43 requirements/scenario/donor matrices are retained.

## What revision 0.3 added

The cognitive path is made concrete rather than left behind reliability machinery. Current values are resolved by subject/aspect, perspective, time and scope; relevance ranking cannot silently settle a contradiction. Intended behavior and observed code remain different views. Unknown procedure applicability stays unknown, and an unrelated task failure does not automatically discredit every delivered lesson.

Project views track not just cited files but the source selection that found their members. A new consumer can invalidate a map without changing its old citations. Finite target-keyed jobs coalesce repeated changes, while exact capture and rare failure warnings never wait for a semantic cluster. Repeated summaries do not create independent support.

New primary-source work covers V1 current-value resolution and the Understanding Layer mission, DCPM's cognitive architecture, selected Hy-Memory System 2 helpers, and the distinction between reward annotation and a production writer. An isolated source-helper probe is recorded separately from any full donor/runtime experiment. Architecture is unchanged because these mechanisms implement its existing requirements.

Revision 0.2 remains the basis for historical evidence versus live applicability, actual host timing, external execution identity, embedding profiles, unique outcome contributions, conservative backup and demand-start independent supervision. The [previous complete audit](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/da441352d98e9ea9307fa186345162bff109d605/docs/v3/AUDIT.md) remains immutable; its old review/check statements do not certify new bytes.

## Remaining decisions

[Implementation §13](IMPLEMENTATION.md#13-open-decisions-for-the-next-documentation-stage) separates concrete proposals from exact interface/version choices and future runtime qualification. O5 now has a proposed first API-compatibility criterion and three-valued applicability contract; the actual evaluator/profile and empirical promotion threshold remain unqualified. Controller-to-memory context and memory-to-controller inference are distinct directions.

The full product retains vectors, automatic local learning, project/concept understanding, negative memory, independent observation, privacy/restore and operator control. Exact/lexical operation during model outages is a degraded profile, not the whole product. A search-only host does not demonstrate the complete cognitive loop.

## Source pins and donor freeze

| Source | Pin |
|---|---|
| V2 | [5aac094834fb5635921b550c821cb933a1196105](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105) |
| V1 | [b5c84d4e53292dbc8996917c63448d5ee96c4bc7](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7) |
| Incomplete audit | [audit-2026-10-16-incomplete](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete) |
| Hy-Memory | [7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a](https://github.com/Tencent-Hunyuan/Hy-Memory/tree/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a), [writer paper v1](https://arxiv.org/html/2610.22196v1) |
| DCPM cognitive architecture | [2606.09483v1](https://arxiv.org/html/2606.09483v1), distinct from writer-weight training |
| Controller source boundary inherited from 0.2 | [96a0d5a6632cfbd541e804d7969d3e76e716bf6a](https://github.com/UnknownAlienHuman/eliot-swarm-controller/tree/96a0d5a6632cfbd541e804d7969d3e76e716bf6a) |
| Selected MemOS mechanism inherited from 0.2 | [a7367d07e55db61099f7b4e2c1108bc5831a24f3](https://github.com/MemTensor/MemOS/tree/a7367d07e55db61099f7b4e2c1108bc5831a24f3) |

Old source/shards stay recoverable as donors. Do not duplicate them in an archive tree or resume their old implementation programmes. `workstreams/ACTIVE.toml`, its validators, CI and user data are unchanged; their old active values are not a machine-enforced V3 freeze. See [architecture authority](../ARCHITECTURE_CONTRACT.md).

## Publication and verification

This work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Record actual changed-document checks and remote readback there. Current-pass authorship is solo; do not reuse old independent-review attestations as review of this candidate. Required CI and independent integration are not bypassed, and publication to the branch is not a merge to main.

Product development starts after the documentation stage, with the owner's sequence: product code, minimum relevant checks/Clippy, tests after the product is built. The future behavioral scenarios are not claimed to have run in this pass.
