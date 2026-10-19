# Eliot Memory OS V3 — documentation

**Revision 0.6 · 2026-10-19 · documentation before the greenfield rewrite.** V1/V2 are donors, not active implementation programmes. This revision includes the previously unpublished 0.5 transfer work, removes inherited V3 bureaucracy and adds Harness2's recursive-improvement mechanism. It does not implement or qualify the runtime.

| Document | Read for |
|---|---|
| [Architecture](ARCHITECTURE.md) | Purpose, cognitive properties, automatic learning, modularity and boundaries |
| [Implementation](IMPLEMENTATION.md) | Store, intake, host/controller, jobs, supervision and recovery |
| [Cognition](COGNITION.md) | Current-state resolution, project views, applicability, transfer and two recursive loops |
| [Consolidated audit](AUDIT.md) | Source findings, alternatives, 34 requirements, 29 A15 cases and donor map including D44 |
| [Audit map](AUDIT-MAP.md) | What was actually read, what remains and the next connected source paths |

The audit map is navigation requested by the owner, not a runtime registry or approval gate. Findings live in the consolidated audit; algorithms have one home in Implementation/Cognition. Reading a donor does not authorize importing its whole architecture.

## Current changes

[Audit §4](AUDIT.md#4-что-точно-не-переносить-что-извлечь-из-v2) follows V2's write-admission, notification and cue-normalization machinery. [§18](AUDIT.md#18-cross-domain-learning-audit-05) preserves the prepared 0.5 cross-domain report; [§19](AUDIT.md#19-harness2-рекурсия-для-eliot-не-новый-агентный-runtime) studies Harness2; [§20](AUDIT.md#20-где-проектировщик-сам-вернул-бюрократию-и-что-изменено) identifies and removes our own overengineering.

The official network SDK is the initial Store choice without an inherited V2 veto. Provisional transfer is not blocked behind a universal promotion experiment. Ordinary helpers do not require digest closures, and mutation readback need not become another generic ledger. A real existing supervisor can be reused; absent that coverage, the standalone profile retains a small independent observer.

Harness2 contributes task-local Propose–Probe–Compose and cross-task lessons about how to improve. The existing modules, jobs and controller own both loops. Baseline/no-change remains eligible; neither a selected output nor repeated reflection proves benefit. No new swarm, model-weight training or benchmark runtime is imported.

## Preservation and remaining work

The consolidated audit was edited and reorganized, not merely appended. Its old detailed versions remain immutable in Git: [0.4](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c28359fc2716f3b498ea512ca24a57801d18014c/docs/v3/AUDIT.md). The 34 requirements, 29 original scenarios and original 43 donor identities remain; Harness2 is D44. Cognition retains thirty prior future cases and adds six recursive cases; Implementation retains S1–S26. They are not executed tests.

[Implementation §13](IMPLEMENTATION.md#13-remaining-concrete-integration-choices) lists exact interface/version choices still unqualified. The [map](AUDIT-MAP.md) distinguishes inherited research from fresh source reading; the archive ZIP and all donor repositories have not been re-audited wholesale.

V2 remains at `5aac094834fb5635921b550c821cb933a1196105`, V1 at `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`, and audit material at [the incomplete release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete). Preserve those sources in Git/history rather than copying them into another archive tree. Runtime, dependencies, CI, validators, ACTIVE registry and user data are unchanged here.

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Report actual publication/readback and CI status there. No independent subagent review is claimed for this pass; a branch commit is not a merge. After documentation, the owner's development order remains product code, minimum relevant checks/Clippy, tests after the product is built.
