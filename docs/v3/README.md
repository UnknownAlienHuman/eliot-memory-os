# Eliot Memory OS V3 — documentation

**Navigation revision 0.18 · 2026-10-20.** Documentation before the greenfield rewrite. V1/V2 are donors; this is not an implemented product.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Purpose and ownership; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths and connected product work; remains 0.11 |
| [Cognition](COGNITION.md) | Cognitive mechanisms within the same modules; remains 0.16 |
| [Consolidated audit](AUDIT.md) | Source findings through §31; remains 0.17, including the 34 grouped requirements, 29 A15 cases and D01–D44 |
| [Audit map](AUDIT-MAP.md) | 0.18 reconciles actual donor/audit coverage and the remaining V3 design decisions |

## Coverage is not complete

The owner's question is answered directly in the [coverage map](AUDIT-MAP.md#1-what-can-honestly-be-claimed): not all donors or audits have been checked, and the V3 implementation model is not finished merely because its central concept is clear.

The [D01–D44 census](AUDIT-MAP.md#2-d01d44-conservative-coverage-census) distinguishes selected code excerpts, documentation/paper evidence and inherited/unreconciled entries. Thirteen entries have identifiable function-level findings in the maintained audit; this does not mean thirteen complete product audits. Hy-Memory, V1/V2 and additional candidates named in the supplied Claude report are outside that tally. In particular, claude-mem, OpenHands and several other explicitly named sources were missing from the D table's denominator.

The [audit-of-audits](AUDIT-MAP.md#4-audit-of-audits-what-is-and-is-not-checked) records the supplied Claude report, October owner/swarm reports, older Memory OS analyses and release archive separately. A historical recommendation is not automatically an instruction for V3. The September Cloudflare/D1 report belongs to the adjacent Research project; it is not a completed Memory OS audit. Full archive contents were not obtained in this pass.

[Remaining design work](AUDIT-MAP.md#5-what-remains-for-an-implementable-v3-model) is concrete: reconcile original purpose, choose actual host/controller request/result paths, specify minimal native storage operations, settle autonomous work selection and its next-context consumer, ground project views in a chosen source tool, and finish practical lifecycle/consistency choices. No new permission gate, registry, service or testing programme is introduced by listing that work. Current controller documentation still describes the Memory OS integration as requested and unimplemented; that context request does not qualify the reverse inference/embedding route.

## Product findings retained

[Audit §31](AUDIT.md#31-real-interpretation-not-validation-shaped-learning-017) follows capture into real projection maintenance and distinguishes it from the unconnected semantic interpretation path. The inspected Dreamer model stage validates a locally constructed draft rather than calling a model; its earlier refusal, candidate-only/partial fields and separate zero-call accounting limit the finding. Mem0 provides a concrete extraction/batched-write mechanism with its own tool-input and error-handling limitations.

The intended V3 path remains: preserve real events, interpret the relevant saved episode through an actual controller route when useful, save a lesson or a genuine keep, and deliver those same records through ordinary context/open. Direct corrections do not need a model. Index maintenance, shape validation and learning are not interchangeable.

Earlier donor findings and all existing requirement/scenario tables are unchanged by this coverage revision. Complete previous reading ranges remain linked from the map; unread callers are not silently marked reviewed.

## Publication

V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Historical research remains in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). This pass updates only the map and navigation, not runtime, schemas, dependencies, CI, ACTIVE registry or user data. It does not claim a new donor experiment, product test, independent subagent review or main merge. Product implementation follows documentation and the owner's product-code/minimum-Clippy/tests-later order.
