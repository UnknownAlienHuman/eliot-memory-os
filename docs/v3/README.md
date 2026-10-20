# Eliot Memory OS V3 — documentation

**Revision 0.19 · 2026-10-20.** Documentation before the greenfield rewrite. V1/V2 remain donors. The requested subagents were not launched because no usable invocation was available in this session; this is a solo source review, not independent multi-agent validation.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose and ownership; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths; remains 0.11 |
| [Cognition](COGNITION.md) | Cognitive mechanisms in the same owners; remains 0.16 |
| [Consolidated audit](AUDIT.md) | Findings, 34 requirements, 29 original A15 cases; adds §32 and donors D45–D46 |
| [Audit map](AUDIT-MAP.md) | Actual coverage, unfinished audit/design work and next concrete reads |

## Current result

[Audit §32](AUDIT.md#32-host-capture-and-non-destructive-continuation-019) examines the previously omitted claude-mem and OpenHands Software Agent SDK at named source revisions.

claude-mem's local observation handler saves through its spool before a best-effort worker wake; provider processing is separate. Its current context registration preserves an unchanged conversation prefix, while optional child-agent filters expose the distinction between capture policy and inference cost. Eliot retains useful real events and coalesces processing, rather than making every tool result wait for a model or suppressing all new corrections for the sake of caching.

OpenHands chooses condensation boundaries using actual call/result relationships and keeps the source event log separate from the model's View. Its selected summarizer/apply path can accept an absent textual summary while removing events from that View; this is a source-level conditional finding, not reproduced source-data loss. Eliot keeps its captured originals and distinguishes a usable continuation from failed or empty synthesis, without becoming another owner of the host's context window.

The findings apply existing capture/jobs/context and continuation contracts. No new scheduler, proof service, memory database, compulsory reflection, tests or runtime dependency is added. Architecture, Implementation and Cognition are not rewritten merely to repeat their existing ownership.

## Coverage is still partial

The table now has D01–D46: fifteen entries with identifiable function-level findings, three with documentation/paper treatment and twenty-eight unreconciled for comparable current source review. These are not forty-six complete audits or a completeness percentage. Hy-Memory, V1/V2 and other named material remain outside that denominator. The full archive and all older audits have not been checked.

[Map §5](AUDIT-MAP.md#5-what-remains-for-an-implementable-v3-model) preserves the six real design questions: original-purpose reconciliation, actual host/controller routes, minimal Store operations, autonomous work selection, grounded project views and practical lifecycle consistency. This pass informs the input/continuation parts; it does not establish Eliot's external inference/embedding API or close the other questions.

Earlier substantive findings remain in [Audit §31](AUDIT.md#31-real-interpretation-not-validation-shaped-learning-017) and preceding sections. The 34 requirements, 29 A15 cases and 36 cognitive walkthroughs remain design expectations, not executed tests. V2 source is `5aac094834fb5635921b550c821cb933a1196105`; V1 is `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. The [incomplete release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete) remains research input, not a mandatory implementation programme.

## Publication

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Actual diff/ref/readback and workflow status are reported there. No independent subagent review, donor/model/DB runtime, synthetic test, benchmark or Clippy run occurred. Source-described performance is not measured Eliot performance. Runtime, schemas, dependencies, CI, validators, ACTIVE registry, main and user data are unchanged. Product work follows documentation and the owner's product-code/minimum-Clippy/tests-later order.
