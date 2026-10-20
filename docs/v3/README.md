# Eliot Memory OS V3 — documentation

**Revision 0.15 · 2026-10-20.** Documentation before the greenfield rewrite. V1/V2 are donors; these documents do not implement the product.

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Product purpose and ownership; remains 0.6 |
| [Implementation](IMPLEMENTATION.md) | Native Store/host/controller paths and connected product work; remains 0.11 |
| [Cognition](COGNITION.md) | Algorithms within the same modules; 0.15 adds targeted relation expansion and continuation |
| [Consolidated audit](AUDIT.md) | Source findings, 34 requirements, 29 original A15 cases and donors D01–D44 |
| [Audit map](AUDIT-MAP.md) | Actual fresh/prior reading and the next useful source path |

## Current result

[Audit §29](AUDIT.md#29-magma-and-letta-relations-and-continuation-015) studies D42 MAGMA and current D17 Letta Code, distinguishing source, paper, actual caller and proposed Eliot mechanism.

MAGMA contributes question-relevant relations. Its inspected query path also performs a whole-node scan, repeated link scans and fresh encoding of visited text, filters bridges by query words, and treats a multi-type preference as an exclusive temporal branch. Its Q&A expansion may be clipped after final top-k. Eliot uses indexed directed relations and existing embeddings, expanding only useful missing context before packing. A separate graph runtime or compulsory model router is not needed.

Letta's real local compaction path summarizes an older portion and retains recent context. Its reflection preparation has a different purpose: reusable knowledge from actual transcript slices. Eliot therefore distinguishes a continuation view from a durable lesson. The host/controller owns window compaction; Eliot supplies source-linked context without becoming another host context manager. Full automatic/cloud reflection execution was not qualified by the prompt or enqueue command alone.

[Cognition §5.5](COGNITION.md#55-expand-the-relation-that-supplies-missing-information) and [§5.6](COGNITION.md#56-continuation-is-not-durable-learning) place those mechanisms in existing `context`, `memory` and jobs/controller paths. No new service, store, approval gate or checklist family is added.

## Prior findings remain

The audit consolidates repeated older prose while retaining the requirement/scenario/donor identities and source finding families. Complete detail remains in the immutable [0.14 audit](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/841c807659727cd7fb5730331190ee27cd50f47d/docs/v3/AUDIT.md); this is not a claim that old sections are byte-identical. Cognition keeps its existing thirty-six walkthroughs.

Earlier decisions remain: actual host observations rather than fabricated execution proofs; immediate useful provisional advice; independent primary retrieval; incremental episode interpretation; no self-reinforcement from injected context; same-aspect updates; multiple entrances to one lesson; low usage does not erase history or determine truth.

## Remaining work and publication

The [map](AUDIT-MAP.md) retains the unresolved Eliot capture-to-interpretation trigger, Graphiti/Hindsight caller gaps, original autonomy requirements and ORS/process work. The next new donor direction is D10/D11 context/anticipation, after distinguishing their current and historical sources. Failed fetches and unreviewed reflection scheduling are not marked complete.

V2: `5aac094834fb5635921b550c821cb933a1196105`; V1: `b5c84d4e53292dbc8996917c63448d5ee96c4bc7`. Archived research remains in the [incomplete audit release](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete).

Work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Actual publication/diff/CI is reported there. No product or donor runtime, model call, benchmark, synthetic test or independent subagent review was performed in this pass. Runtime, schema, dependencies, CI, ACTIVE registry and user data are unchanged. Product implementation follows documentation and the owner's code/minimum-Clippy/tests-later order.
