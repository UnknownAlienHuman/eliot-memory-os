# Eliot Memory OS V3 — documentation

**Revision 0.2 · 2026-10-19 · documentation stage.** V1/V2 are donors. V3 will be written from scratch after documentation is agreed. No runtime, database migration or model integration is implemented by this revision.

## Reading order

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Concise product manifesto: purpose, preserved cognition/learning, ownership and boundaries |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | One concrete design for host timing, source semantics, storage, jobs, controller execution, learning and recovery |
| [AUDIT.md](AUDIT.md) | Russian consolidated findings and rationale; 34 requirements, all 29 original scenarios and 43 donor entries |

Read Architecture and Implementation together for a contract change. Use the audit to check exact sources, rejected mechanisms and evidence limits. A new donor or research result does not automatically authorize another subsystem.

## What revision 0.2 changes

Historical evidence is separated from current applicability so ordinary source changes do not erase experience. Advisory context is distinguished from a real pending-action gate. Local worker recovery retains the same external execution identity rather than silently repeating paid work. Learning counts distinct observed outcomes, not repeated induction examples. Embedding profiles are independent of the Dreamer model.

Backup now has a conservative quiesced-export procedure and a finite staged-input cutoff, rather than an undefined fast snapshot. Restore applies current restrictions and reconciles old external jobs. A small independent supervisor can run only while the demand-start daemon is active; the full proposed profile counts supervisor, daemon and database as three owned processes, not three memory writers.

The previous scattered §3.3/§6.4 additions are integrated into the appropriate contracts. The earlier source analysis and publication history remain available in the [preceding audit](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/3512f6e4f4c9ce59ba2959193e92c0728fadf00c/docs/v3/AUDIT.md); its old test/review statements do not certify new bytes.

## Remaining decisions

[Implementation §13](IMPLEMENTATION.md#13-open-decisions-for-the-next-documentation-stage) distinguishes concrete proposals from the remaining interface/version choices and future runtime qualification. The outstanding SDK versus historical direct-RPC constraint is explicit; neither client is silently declared approved or implemented. Controller-to-memory context and memory-to-controller inference are different directions.

The full product retains vectors, automatic local learning, project/concept understanding, negative memory, independent observation, privacy/restore and operator control. Exact/lexical operation during model outages is a degraded profile, not the whole product. A search-only host does not demonstrate the complete cognitive loop.

## Source pins and donor freeze

| Source | Pin |
|---|---|
| V2 | [5aac094834fb5635921b550c821cb933a1196105](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/5aac094834fb5635921b550c821cb933a1196105) |
| V1 | [b5c84d4e53292dbc8996917c63448d5ee96c4bc7](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/b5c84d4e53292dbc8996917c63448d5ee96c4bc7) |
| Incomplete audit | [audit-2026-10-16-incomplete](https://github.com/UnknownAlienHuman/eliot-memory-os/releases/tag/audit-2026-10-16-incomplete) |
| Hy-Memory | [7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a](https://github.com/Tencent-Hunyuan/Hy-Memory/tree/7b7fd217a8084fe0d5f9c196d9e4cb88dbba570a), [paper v1](https://arxiv.org/html/2610.22196v1) |
| Controller source boundary | [96a0d5a6632cfbd541e804d7969d3e76e716bf6a](https://github.com/UnknownAlienHuman/eliot-swarm-controller/tree/96a0d5a6632cfbd541e804d7969d3e76e716bf6a) |
| Selected MemOS mechanism | [a7367d07e55db61099f7b4e2c1108bc5831a24f3](https://github.com/MemTensor/MemOS/tree/a7367d07e55db61099f7b4e2c1108bc5831a24f3) |

Old source/shards stay recoverable as donors. Do not duplicate them in an archive tree or resume their old implementation programmes. `workstreams/ACTIVE.toml`, its validators, CI and user data are unchanged; their old active values are not a machine-enforced V3 freeze. See [architecture authority](../ARCHITECTURE_CONTRACT.md).

## Publication and verification

This work belongs to [issue #5324](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5324) and [PR #5325](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5325). Record actual changed-document checks and remote readback there. Current-pass authorship is solo; do not reuse old independent-review attestations as review of this candidate. Required CI and independent integration are not bypassed, and publication to the branch is not a merge to main.

Product development starts after the documentation stage, with the owner's sequence: product code, minimum relevant checks/Clippy, tests after the product is built. The future behavioral scenarios are not claimed to have run in this pass.
