# Eliot Memory OS V3 — documentation

**Revision 0.1 · 2026-10-18 · documentation stage.** V1/V2 are donors. V3 is to be implemented from scratch after the design is refined. This revision implements no runtime capability and does not mark the proposed architecture as fully accepted.

## Reading order

| Document | Read it for |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Purpose, full preserved behavior, product ownership, and proposed simple topology |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Concrete operations, state changes, failures, controller boundary, learning, and recovery |
| [AUDIT.md](AUDIT.md) | Consolidated Russian evidence and reasoning: 34 original requirements, 29 A15 scenarios, Claude corrections, Hy-Memory, SurrealDB, controller gaps, and 43 donor entries |

Read Architecture and Implementation together before changing a contract. Use the relevant audit section to check its rationale and pinned sources. Project documentation is English; the consolidated audit is Russian for the owner. New research is evidence for a decision, not automatic permission to add a new subsystem.

## Design direction

The initial proposal is one demand-start `eliotd` with ordinary internal modules, one supervised SurrealDB child, and one durable background-work queue. Dreamer and embeddings use a real external `eliot-swarm-controller` contract; deterministic capture and exact/lexical retrieval remain available during model-route outages. Vector retrieval belongs to the full product.

Memory must influence subsequent work: preserve observations, supply proactive scoped context, build source-grounded project/concept views, distinguish hypotheses and causality, learn local procedures automatically within existing policy, evaluate wider reuse independently, and reverse harmful or stale influence. A passive search-only host is a limited integration profile.

The full product also retains operator control, independent process observation, workspace/report gap detection, privacy deletion and safe restore. The first vertical path is a construction sequence, not permission to discard these requirements.

## Open documentation decisions

[Implementation §13](IMPLEMENTATION.md#13-open-decisions-for-the-next-documentation-stage) defines six bounded decisions: first host, real controller/model/embedding contract, durable intake and deletion/restore protection, exact database/interface/schema behavior, first learning consumer/evaluation, and OS observer/control surface. Review concrete normal/failure/recovery examples before calling the design ready for implementation.

A real controller Memory ModelJob/result/embedding integration is not established by the inspected controller source. Provider independence is a contract goal; quality across models must later be evaluated. Neither this draft nor Hy-Memory's results prove a 50-fold reduction in implementation cost.

## Donor freeze and source pins

| Donor/evidence | Pinned source |
|---|---|
| V2 code and normative fragments | [5aac094834fb5635921b550c821cb933a1196105](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105) |
| V1 original design | [b5c84d4e53292dbc8996917c63448d5ee96c4bc7](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7) |
| Incomplete V2 audit archive | [audit-2026-10-16-incomplete](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete) |
| Hy-Memory | [7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a](https://github.com/Tencent-Hunyuan/Hy-Memory/tree/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a), [paper v1](https://arxiv.org/html/2610.22196v1) |
| Controller boundary examined | [513f9698c268753dc6f2a6c0cf4d9a53f7f5e472](https://github.com/UnknownAlienHuman/eliot-swarm-controller/tree/513f9698c268753dc6f2a6c0cf4d9a53f7f5e472) |

Old Rust crates, V2 shards, validation scripts, and `workstreams/ACTIVE.toml` remain historical source material. Their active/accepted language describes the old programme and does not authorize new V2 work. V3 has no adoption receipt yet. See [architecture authority](../ARCHITECTURE_CONTRACT.md).

The V2 ACTIVE registry and its validators remain unchanged, with their existing active values. The current issue and owner instruction define the documentation scope; this revision does not claim a machine-enforced freeze or migrate/close the old programmes.

## Delivery record

This stage belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324). It changes documentation and navigation only. Source code, CI, dependencies, user data, and runtime state are outside the change. The issue/PR records executed checks, independent review, and evidence limits. Future implementation starts after the documentation stage is agreed, with the owner's sequence of product code, minimum relevant checks/Clippy, and tests after the product is built.
