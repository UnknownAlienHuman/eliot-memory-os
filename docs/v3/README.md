# Eliot Memory OS V3 — documentation

**Revision 0.7 · 2026-10-19 · documentation before the greenfield rewrite.** V1/V2 remain donors. This pass follows connected control and retained MCP/context paths and refines the existing implementation contract. It does not implement the V3 runtime or change V2 code/CI.

| Document | Read for |
|---|---|
| [Architecture](ARCHITECTURE.md) | Purpose, cognition, automatic learning, modularity and boundaries; remains revision 0.6 |
| [Implementation](IMPLEMENTATION.md) | Runtime and data contracts, now including direct control, attention recurrence and truthful optional enrichment/delivery |
| [Cognition](COGNITION.md) | Current-state resolution, views, applicability, transfer and two recursive loops; remains revision 0.6 |
| [Consolidated audit](AUDIT.md) | Source findings, alternatives, 34 requirements, 29 A15 cases and D01–D44 |
| [Audit map](AUDIT-MAP.md) | Actually read paths/ranges, inherited findings, remaining gaps and next actions |

The map is navigation, not a runtime registry or approval gate. Findings have one home in the audit; changed algorithms and contracts belong to their existing chapters.

## Revision 0.7

[Audit §22](AUDIT.md#22-connected-control-and-context-audit-07) traces broker dispatch and acknowledgement, NotificationState persistence, retained MCP response enrichment, old cue normalization and source hydration. It records both failures and rejected suspicions: the SQL already uses revision CAS, valid directory cues require Prefix, and not every MCP branch propagates every telemetry failure.

[Implementation §9.4](IMPLEMENTATION.md#94-direct-local-control-and-attention-recurrence) makes local control operation-specific and separates an underlying problem from a new episode and late acknowledgement. Current-state updates do not replay/rewrite all historical events. [§§3.5–3.6](IMPLEMENTATION.md#35-optional-enrichment-cannot-rewrite-a-completed-operation) preserve a known primary result when optional enrichment fails, distinguish prepared from observed handoff, and avoid permanent repeat suppression from pre-send accounting. [§2.5](IMPLEMENTATION.md#25-exact-cues-and-advisory-aliases) separates exact resource identity from search aliases; [§4.1](IMPLEMENTATION.md#41-independent-candidates-and-truthful-resolution) hydrates selected IDs rather than project-wide payloads after a small match set.

These are changes inside the existing modules. No new delivery service, approval engine, semantic store or planner is ordered. A failed primary write and a real disclosure restriction still cannot be ignored merely by calling them optional logging.

## Preserved work and coverage

Audit sections 1–21 retain the preceding report with an explicit historical-scope notice; section 22 holds new findings. The 34 requirements, all 29 A15 scenarios and D01–D44 remain. Implementation retains S1–S26 and adds six future cases S27–S32. Cognition's thirty-six existing cases and Harness2 loops are unchanged; none is claimed as an executed product test.

Revision 0.6 remains the basis for removal of the inherited SDK veto, automatic provisional transfer, smaller operation readback and non-duplicated supervision. It also published the previously local 0.5 Hy transfer findings and added D44 Harness2. The [immutable 0.6 audit](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/73c34dcb906637f782e667a4ca4c347227806aa5/docs/v3/AUDIT.md) preserves that publication context. No fresh donor benchmark or whole-archive audit occurred in 0.7.

[Implementation §13](IMPLEMENTATION.md#13-remaining-concrete-integration-choices) retains exact interface/version choices still unqualified. The next source readings in the map target source-loader truncation, producer path bases, delivery-cache/transport boundaries and ORS/process ownership rather than repeating prior declarations.

## Source and publication boundaries

V2 donor: `5aac094834fb5635921b550c821cb933a1196105`; V1 donor: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`; archived research: [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete). Those sources remain in Git/history, not copied into another archive tree. Runtime, schema, dependencies, CI, validators, ACTIVE registry, main and user data are unchanged by this pass.

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Record actual commit/ref readback and current CI there. Source-level failures, four isolated ASCII helper examples and arithmetic history-work counts are not Windows, Rust, SurrealDB or full-product runs. No independent GPT Luna review is claimed; a branch commit is not a merge. After documentation, the owner's sequence remains product code, minimum relevant checks/Clippy, tests after the product is built.
