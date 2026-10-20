# Eliot Memory OS V3 — documentation

**Revision 0.17 · 2026-10-20.** Documentation before the greenfield rewrite. V1/V2 are donors; these documents do not implement the product.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose and ownership; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths and connected product work; remains 0.11 |
| [Cognition](COGNITION.md) | Existing cognitive mechanisms; remains 0.16 |
| [Consolidated audit](AUDIT.md) | Source findings, 34 requirements, 29 original A15 cases and donors D01–D44; new §31 |
| [Audit map](AUDIT-MAP.md) | Actual fresh/prior reading, precise limits and the next source path |

## Current result

[Audit §31](AUDIT.md#31-real-interpretation-not-validation-shaped-learning-017) follows V2 capture through WriterWorker and its actual projection callback, then examines the Dreamer binary entry, submitted-job path, source material and model-stage implementation. D20 Mem0 supplies a contrasting real extraction call at `0724291bd864cf807e88ee8981c8226644e8fb42`.

The observed post-write worker updates search, cues and dependency state; it does not interpret an episode. That is a real maintenance path, not evidence that every automatic producer in the repository is absent. The inspected non-Curation Dreamer path stops at its previously known unresolved input; downstream, `run_admitted_model` only validates a locally constructed empty draft. Its handle-only bundle is not source content, and a separate text helper returns the question as a hypothesis. Removing the early refusal alone would not create an inference implementation. Partial/candidate-only outputs and separate zero-provider-call accounting limit the finding; no deployed fabricated success is claimed.

Mem0's synchronous `Memory.add` actually passes new text, recent context and existing memories to an LLM, then batches derived writes. Its formatter omits tool-role results, parse failure can return the same empty extraction as no-change, and even infer=false is embedding-dependent. Take the concrete extraction/batching mechanism, not a raw-first guarantee, all of its stores or managed-platform benchmark scores.

[Audit §31.7](AUDIT.md#317-конкретная-соединённая-реализация-v3) makes the existing V3 path concrete: save actual source events and necessary pending work; let the existing job worker read the unprocessed episode; call the real controller with content; save useful proposals or a genuine keep; make those same records available through normal context/open. Direct explicit corrections need no model call. Index completion, local validation and model interpretation are not interchangeable results.

Architecture, Implementation and Cognition already specify the required ownership. They are not rewritten just to repeat these findings. No new source-reading certificate, model-call proof layer, extra scheduler or store is added.

## Prior findings remain

[Audit §30](AUDIT.md#30-everos-and-evermemos-anticipation-and-evidence-coverage-016) retains EverOS anticipation, selected-group retrieval, material question coverage and foreground-capacity decisions. [§29](AUDIT.md#29-magma-and-letta-relations-and-continuation-015) retains MAGMA relations and Letta continuation versus durable learning.

The audit was editorially consolidated in 0.15. Complete older detail remains in the immutable [0.14 audit](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT.md). This pass appends §31 and makes targeted navigation updates, without another consolidation. The 34 requirements, 29 original A15 cases, D01–D44 and thirty-six cognitive walkthroughs remain.

Earlier decisions remain: real host outcomes rather than fabricated execution proofs; immediately useful provisional advice; independent primary retrieval; incremental episode interpretation; no self-reinforcement from injected context; same-aspect updates; multiple entrances to one lesson; low usage does not erase history or determine truth.

## Remaining work and publication

The [map](AUDIT-MAP.md) now distinguishes the examined projection path from alternative semantic scheduling. Next is a concrete external controller request/result from an actual caller and the material reaching it, followed by remaining original autonomy and ORS/process questions. A type, internal cycle helper or status receipt does not qualify that integration. Donor paths not read remain explicitly partial.

V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Archived research remains in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Actual publication/diff/CI is reported there. No product or donor runtime, model call, benchmark, synthetic test, Clippy run or independent subagent review occurred in this pass. Existing test source was read only to identify what it counts. Runtime, schema, dependencies, CI, ACTIVE registry and user data are unchanged. Product implementation follows documentation and the owner's product-code/minimum-Clippy/tests-later order.
