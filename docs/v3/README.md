# Eliot Memory OS V3 — documentation

**Revision 0.23 · 2026-10-21.** Documentation before the greenfield rewrite. V1/V2 remain donors. This revision prepares and applies source-grounded Architecture/Implementation changes for disagreement, external research and self-correction; it is not implemented V3.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose and boundaries; 0.23 preserves Concilium, autonomous research and targeted self-improvement without new owners |
| [Implementation](IMPLEMENTATION.md) | Concrete operations, interfaces and work sequence; 0.23 adds §§7.5,8.6–8.7 |
| [Cognition](COGNITION.md) | Cognitive algorithms within those modules; remains 0.16 |
| [Consolidated audit](AUDIT.md) | Sources, findings and rejected alternatives; new §36 |
| [Audit map](AUDIT-MAP.md) | Actual coverage, unreviewed sources and the next implementation choices |

## Current material for the rewrite

[Audit §36](AUDIT.md#36-disagreement-research-and-self-revision-023) compares original Concilium/research/self-quality requirements with selected V2 functions and the current separate Research plan. The original Concilium already rejects voting and permits one agent; the new design keeps that purpose rather than inventing a mandatory council.

[Implementation §7.5](IMPLEMENTATION.md#75-diagnose-the-failing-step-and-revise-the-useful-method) distinguishes missing input, failed retrieval, failed delivery, non-use and a genuinely harmful method. Correct the affected step through ordinary observations, jobs and revisions. A previous failed repair does not prohibit all further diagnosis under the same configuration. Incomplete general monitoring does not conceal a known local problem.

[§8.6](IMPLEMENTATION.md#86-resolve-the-question-not-a-compulsory-panel) resolves a useful question using actual grounds, contrary evidence and a discriminating observation. Additional agents are optional through the host/controller. Qualified alternatives and dissent remain readable; unrelated work does not wait for universal agreement.

[§8.7](IMPLEMENTATION.md#87-acquire-the-missing-evidence-through-an-actual-research-route) starts with available local memory and sources, then uses configured external acquisition for a remaining useful gap. The separate Research project owns its corpus and execution; Eliot stores the useful compact evidence and lessons. Its exact request/result integration is still unverified, not replaced with a fabricated RPC or the old federation framework.

Architecture states why these functions matter. Implementation assigns concrete inputs, work, outputs and consumers to the existing modules. No self-quality database, ConflictRegistry, compulsory panel, research engine inside memory or new promotion gate is added.

## Earlier decisions retained

The first structural source is configured codebase-memory-mcp, not an embedded parser/graph clone. Project views come from real source/documents and are refreshed by relevant changes. Primary Store reads do not await mirrored search publication. Controller input admission is not model completion; the dedicated vector operation remains explicit implementation work. Capture preserves real observations before optional interpretation; useful provisional lessons reach ordinary context.

The 34 requirement groups, 29 original A15 cases, D01–D47, Implementation S1–S32 and 36 cognitive walkthroughs remain. They are not executed product tests. Sixteen numbered donors have concrete source-excerpt findings, three docs/paper treatment and twenty-eight remain unreconciled; none of those counts means whole-product qualification. Full archive and original-requirement reconciliation are still open.

## Continuing work and publication

The [map](AUDIT-MAP.md) next prioritizes first-use configuration/process ownership and actual remaining routes, followed by unfinished original/audit reconciliation. There is no need for a new installation or permission platform merely to connect one useful path.

V2 source: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Prior documentation remains in [Git history](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/d7a9de88b87020585a02194c4b51189063f97d96/docs/v3); research material remains in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Actual changed-file/readback and workflow status are recorded there. No independent subagent review, model/DB/runtime execution, synthetic test, benchmark or Clippy run occurred. Runtime, schema, dependencies, permissions, CI, validators, ACTIVE registry, main and user data are unchanged. Product implementation follows documentation and the owner's code/minimum-Clippy/tests-later sequence.
