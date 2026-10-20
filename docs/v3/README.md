# Eliot Memory OS V3 — documentation

**Revision 0.8 · 2026-10-19.** Documentation before the greenfield rewrite; V1/V2 remain donors. This revision removes dependencies that prevent useful memory from working. It does not change or implement the product runtime.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose, cognition, automatic learning and module boundaries; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Working capture/read path, independent background work, host/controller integration and practical recovery; now 0.8 |
| [Cognition](COGNITION.md) | Current-state resolution, project views, procedures, transfer and Harness2 recursion; remains 0.6 |
| [Consolidated audit](AUDIT.md) | Sources, rejected designs, 34 original requirements, 29 A15 cases and donors D01–D44 |
| [Audit map](AUDIT-MAP.md) | What was actually examined and the next connected paths |

## What changed

[Audit §23](AUDIT.md#23-working-memory-without-global-gates-08) follows the Store's 10,000-record refusal, optional graph/trace dependency, strict project-head job queue and session orientation cache. It also compares D16 LangMem's delayed-processing guide with its actual executor.

[Implementation](IMPLEMENTATION.md) now starts from native indexes over primary records. Ordinary reads do not await an entire project rebuild, fresh proof of every source, a graph threshold or diagnostic writes. Graph/vector enrichment remains useful but independent. Broad enumeration uses pages; a page size is not the total capacity of a project.

Independent jobs do not queue behind an unrelated blocked project operation. Debouncing combines pending work signals, not the source observations that must still be processed. Negative-memory advice does not automatically install a per-tool approval gate.

[Restore](IMPLEMENTATION.md#103-restore-usable-data-not-an-unattainable-proof) makes intact primary data available before rebuilding optional indexes. Known deletions are applied. If the owner restores a selected backup after losing deletion history, explain the gap and permit recovery rather than requiring an unobtainable proof or a new selective-import system. Old external jobs are reconciled separately, not automatically replayed.

No new service, semantic database, permission platform or checklist family is added. The 34 requirements, 29 A15 cases, D01–D44 and S1–S32 remain represented; the recovery scenario explicitly reflects the removed blanket restriction. The earlier cognitive and recursive cases remain in Cognition.

## Continuing work

[Implementation §13](IMPLEMENTATION.md#13-remaining-concrete-integration-choices) lists the actual interface/version choices left for implementation. The [map](AUDIT-MAP.md) prioritizes a connected success/failure → procedure → later useful context path, then remaining source/transport and ORS/process responsibilities. It is a reading aid, not a gate.

V2 source: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Earlier complete documentation remains in [Git history](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/81a9848bccd95bc9778c4f9e92c210d6349eb298/docs/v3); archived research remains in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Source reading is not a runtime test; publication is not a merge. This pass does not change CI, runtime, schemas, the old ACTIVE registry or user data, and does not claim independent subagent review. Product implementation follows documentation and the owner's code/minimum-Clippy/tests-later sequence.
