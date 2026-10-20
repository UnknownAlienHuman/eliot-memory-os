# Eliot Memory OS V3 — documentation

**Revision 0.16 · 2026-10-20.** Documentation before the greenfield rewrite. V1/V2 are donors; these documents do not implement the product.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose and ownership; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths and connected product work; remains 0.11 |
| [Cognition](COGNITION.md) | Algorithms within the same modules; 0.16 refines anticipation, question coverage and foreground capacity |
| [Consolidated audit](AUDIT.md) | Source findings, 34 requirements, 29 original A15 cases and donors D01–D44 |
| [Audit map](AUDIT-MAP.md) | Actual fresh/prior reading and the next useful source path |

## Current result

[Audit §30](AUDIT.md#30-everos-and-evermemos-anticipation-and-evidence-coverage-016) studies current D10 EverOS at `c4a20a280a4c8c4bd3a91174c57dd92ac6cfba18`, separately from the historical D11 EverMemOS paper. Current MemCell/Foresight names do not establish identical behavior across those versions.

The inspected foresight strategy is disabled by default, and the actual HTTP/service/search-manager path has no dedicated foresight output. Eliot therefore connects conditional anticipation to ordinary context: the useful precaution, its condition and source episode. An inferred expiry can reduce proactive exposure, but cannot establish that a planned action happened or erase an explicit commitment. No separate foresight store or predictor per message is added.

EverOS AGENTIC loads the complete eligible episode scope before selecting groups; other search modes are distinct. Its separate multi-round loop preserves sub-query evidence, but final packing can still omit selected core or leave no space for a per-query guarantee. Eliot fetches selected group members through native queries and retains the material parts of the question through final packing. Optional deeper refinement does not become a model-based admission step for ordinary recall.

Current embedding code separates query capacity from background batches. Eliot uses existing controller scheduling and the actual aggregate endpoint limit, not a second provider scheduler. Exact/lexical retrieval remains useful while vector work is unavailable.

These changes belong to existing [Cognition §§5.1–5.3](COGNITION.md#51-independent-candidates-not-a-dense-only-lexical-reranker), [§5.7](COGNITION.md#57-cover-the-missing-aspect-not-more-copies-of-the-same-answer) and [§7](COGNITION.md#7-attention-prediction-and-cognitive-failure). No new service, store, approval gate or checklist family is added.

## Prior findings remain

[Audit §29](AUDIT.md#29-magma-and-letta-relations-and-continuation-015) retains MAGMA's actual relation/traversal findings and Letta's distinction between context continuation and durable learning. Their broader unreviewed callers remain unreviewed; a new donor does not close them.

The audit was editorially consolidated in 0.15. Complete older detail remains in the immutable [0.14 audit](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT.md). This pass adds findings and targeted amendments without another consolidation. The 34 requirements, 29 original A15 cases, D01–D44 and thirty-six cognitive walkthroughs remain.

Earlier decisions remain: actual host observations rather than fabricated execution proofs; immediately useful provisional advice; independent primary retrieval; incremental episode interpretation; no self-reinforcement from injected context; same-aspect updates; multiple entrances to one lesson; low usage does not erase history or determine truth.

## Remaining work and publication

The next priority in the [map](AUDIT-MAP.md) is the real Eliot capture-to-interpretation trigger, followed by the remaining original autonomy, Graphiti/Hindsight caller and ORS/process questions where relevant. EverOS imported algorithm internals and the historical EverMemOS implementation were not qualified. They are not mandatory implementation dependencies.

V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Archived research remains in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Actual publication/diff/CI is reported there. No product or donor runtime, model call, benchmark, synthetic test or independent subagent review was performed in this pass. Runtime, schema, dependencies, CI, ACTIVE registry and user data are unchanged. Product implementation follows documentation and the owner's code/minimum-Clippy/tests-later order.
