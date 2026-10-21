# Eliot Memory OS V3 — documentation

**Revision 0.21 · 2026-10-21.** Documentation before the greenfield rewrite. V1/V2 remain donors. This revision selects the initial native Store layout and capture-to-lesson operations; it does not apply a schema or claim implemented V3.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose and ownership; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths; 0.21 adds physical records and operations in §§2.6–2.9 |
| [Cognition](COGNITION.md) | Cognitive mechanisms in the same owners; remains 0.16 |
| [Consolidated audit](AUDIT.md) | Findings, 34 requirements, 29 original A15 cases and D01–D46; adds §34 |
| [Audit map](AUDIT-MAP.md) | Actual coverage, remaining product decisions and exact source-reading limits |

## Current result

[Audit §34](AUDIT.md#34-native-store-operations-without-mirrored-state-021) compares the selected V2 SQL readers with native SurrealDB operations. The old search query gates even an exact handle on a project-wide published projection. The semantic loader reads the oldest512 physical records. Neither mechanism is needed for direct primary reads or properly paged history.

[Implementation §§2.6–2.9](IMPLEMENTATION.md#26-initial-physical-layout) specifies the initial `stream`, `observation`, `memory`, `memory_history`, `link` and `job` tables. They are data inside one Store, not six services or a fixed budget for the whole product. A working item has one current editorial revision; previous revisions are archived on amendment. Competing claims and actual validity still use Cognition's resolver, not latest-edit-wins.

Capture saves the original and necessary pending work together. A running job has a finite input; new events extend a pending successor instead of changing that input or restarting inference. Amendment publishes the addressed content, history, links and job result in one explicit transaction. SDK transport success, zero changed rows and a successful semantic no-change remain different outcomes.

Direct IDs, lexical candidates and selected source ranges read primary data. Native indexes replace the mirrored search publisher; no global readiness row decides whether a stored source exists. New text is usable while its vector is pending. Late vectors must match the content/profile they were computed for and do not create new lessons or reflection work.

The API reference profile is SurrealDB server/SDK 3.3.4, checked 2026-10-21. The query shapes are documented design, not executed DDL or a measured plan. No new kernel, task-graph engine, query language, proof service or memory database is introduced.

## Controller and earlier work

[Audit §33](AUDIT.md#33-controller-execution-and-embedding-boundary-020) and [Implementation §6](IMPLEMENTATION.md#6-dreamer-through-controller) retain the real controller text mapping and the missing dedicated embedding operation. Input admission is not a generated response; the selected Claude send/result pair has concrete limits. These source findings are not a claim of an installed connection and were not re-audited in this Store pass.

Earlier donor findings remain in [§32](AUDIT.md#32-host-capture-and-non-destructive-continuation-019), [§31](AUDIT.md#31-real-interpretation-not-validation-shaped-learning-017) and preceding sections. The 34 requirements, 29 A15 cases, Implementation S1–S32 and 36 cognitive walkthroughs remain design expectations, not executed tests.

## Coverage is still partial

D01–D46 still comprise fifteen entries with identifiable function-level findings, three with documentation/paper treatment and twenty-eight unreconciled for comparable source review. SurrealDB documentation does not change that application-donor census. Hy-Memory, V1/V2 and other named material remain outside its denominator. The full archive and all earlier audits have not been checked.

[Map §5](AUDIT-MAP.md#5-what-remains-for-an-implementable-v3-model) now records the selected Store layout/operation sequence and its remaining implementation. The next design priority is original Understanding Layer autonomy and a concrete structural-source→affected-view→next-agent path. Actual host/controller wiring, the encoder, lifecycle details and the remaining source/audit reconciliation are still open.

V2 source is `5aac094834fb5635921b550c821cb933a1196105`; V1 is `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. The [incomplete release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete) remains research input, not a mandatory implementation programme.

## Publication

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Actual diff/ref/readback and workflow status are reported there. No independent subagent review, model/DB runtime, synthetic test, benchmark or Clippy run occurred. Runtime, deployed schema, dependency files, CI, validators, permissions, ACTIVE registry, main and user data are unchanged. Product implementation follows documentation and the owner's product-code/minimum-Clippy/tests-later order.
