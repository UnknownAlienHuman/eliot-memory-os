# Eliot Memory OS V3 — documentation

**Revision 0.20 · 2026-10-21.** Documentation before the greenfield rewrite. V1/V2 remain donors. This revision makes the initial controller text path concrete and identifies the separate vector operation still needed; it does not claim implemented V3.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose and ownership; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths; 0.20 expands §6 and the O2 integration choice |
| [Cognition](COGNITION.md) | Cognitive mechanisms in the same owners; remains 0.16 |
| [Consolidated audit](AUDIT.md) | Findings, 34 requirements, 29 original A15 cases and D01–D46; adds §33 |
| [Audit map](AUDIT-MAP.md) | Actual coverage, remaining product decisions and exact source-reading limits |

## Current result

[Audit §33](AUDIT.md#33-controller-execution-and-embedding-boundary-020) follows controller `912df90f86320ff556c1dba23badc2c69e518e34`: public method registry, Task admission, actual dispatch, Claude SDK execution and response pages. The existing Memory OS integration document describes controller-to-memory context, not a completed reverse inference API.

[Implementation §6](IMPLEMENTATION.md#6-dreamer-through-controller) maps a finite interpretation job to existing controller operations. A genuine synthesis Task can omit an acceptance policy; it does not need fabricated code checks or a Git change. Preparing an executor and admitting input do not mean a response has been generated. Read the actual completed output through its result/artifact path, rather than ask the agent to repeat it in a new paid turn.

The inspected Claude bridge accepts later `agent.send`, but its examined result reader addresses a `task.dispatch` origin. That input/result pairing and its body/page/retention limits must be reflected by the small memory adapter, not hidden behind a generic promise. Other routes may differ; the current Codex README is not a complete audit of its executor.

No dedicated vector-embedding method was found in the inspected positive public registry. [§6.5](IMPLEMENTATION.md#65-embeddings-are-a-separate-batch-operation) specifies the required batch input/output at the existing controller provider boundary. It is a missing implementation, not an invented existing RPC. Do not wrap each vector in a coding Task, ask a model to print numerical embeddings or build another provider runtime inside memory. Text and vector routes are independent; useful primary/lexical reads continue meanwhile.

The two directions of integration must not wait for each other's unfinished output. A job already holding its saved source slice can start; optional retrieval reads available memory instead of demanding completion of that same interpretation. This is call ordering within the existing modules, not a new readiness service.

## Coverage is still partial

D01–D46 still comprise fifteen entries with identifiable function-level findings, three with documentation/paper treatment and twenty-eight unreconciled for comparable source review. No new donor number is added. These are not forty-six complete audits or a completeness percentage. Hy-Memory, V1/V2 and other named material remain outside that denominator. The full archive and all earlier audits have not been checked.

[Map §5](AUDIT-MAP.md#5-what-remains-for-an-implementable-v3-model) retains original-purpose reconciliation, actual host/controller wiring, minimal Store operations, autonomous work selection, grounded project views and practical lifecycle consistency. This pass settles a more concrete text mapping and vector requirement, not a working connection or the physical schema. The next design work is primary records and native capture/retrieve/revise/open queries, alongside remaining original-purpose and structural-source decisions.

Earlier findings remain in [§32](AUDIT.md#32-host-capture-and-non-destructive-continuation-019), [§31](AUDIT.md#31-real-interpretation-not-validation-shaped-learning-017) and preceding sections. The 34 requirements, 29 A15 cases, Implementation S1–S32 and 36 cognitive walkthroughs are design expectations, not executed tests. V2 source is `5aac094834fb5635921b550c821cb933a1196105`; V1 is `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. The [incomplete release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete) remains research input, not a mandatory implementation programme.

## Publication

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Actual diff/ref/readback and workflow status are reported there. No independent subagent review, model/DB runtime, synthetic test, benchmark or Clippy run occurred. No new runtime, schema, dependency, CI, validator, permission or ACTIVE-registry change was made in either repository. Main and user data are untouched. Product implementation follows the documentation stage and the owner's product-code/minimum-Clippy/tests-later order.
