# Bounded Opus 5 decision: run006 public projection loss

You are the senior architecture reviewer. Inspect only the exact files named below when useful.
Do not write files, run commands, invoke providers/MCP, or ask questions. We need one concrete,
fail-closed decision. Prefer recovery that preserves canonical evidence; do not weaken authority,
provenance, immutability, candidate-only boundaries, or semantic qualification gates.

## Current contract

- Repository: `eliot-memory-os`, branch `codex/cognitive-completion-v2`, HEAD `94a96b0`.
- Active product binary source: `e18811953451138e3d6647f0d389c4edc7ca8447`, SHA-256
  `9c98d96a1aa6b1982e1236117fd928283cabf805dda4486f5e6f99a24e71e87c`.
- Task: Recovery Plan v3 Task 02R2, then Tasks 03-06.
- Continuation run: `cq-core-20260730-006`; predecessor run005 is immutable BLOCKED evidence.
- Fresh run006 provider calls: zero. Expected calls remain eight, absolute maximum nine.
- All four accepted U03 roles are reused; only U06/U11 are fresh.
- P009 tuple-exact legacy admission was implemented in commit `8d2db4a`.
- Generation-1 partial seal was recovered by the later typed authority-lifecycle implementation.
  Its record is `Abandoned`, the recovery receipt is `complete`, all sessions/leases are retired,
  staged artifacts were hash-preservingly quarantined, and it authorizes replacement generation 2.
- Existing Opus decisions on P009 and missing WorkItems are in:
  `.eliot/consultations/20260731T025200Z-opus5-p009-partial-seal.md` and
  `.eliot/consultations/20260731-opus5-run006-missing-workitems-decision-response.md`.

## Newly discovered problem

The ignored public report roots are absent:

```
reports/cognitive-field/core-qualification/cq-core-20260729-003
reports/cognitive-field/core-qualification/cq-core-20260730-005
reports/cognitive-field/core-qualification/cq-core-20260730-006
```

They are absent from the working copy, all Git refs, the local Recycle Bin, and a bounded local
search. They were never tracked. The complete private roots remain under:

```
C:\Users\kleym\AppData\Local\Eliot\cognitive-field\core-qualification\<run-id>
```

The private roots retain provider receipts and raw/output artifacts, deterministic command
receipts/logs, hashes, prompts, schemas, oracles, worktrees, contamination evidence and run006's
role-evidence plan. Run006's role-evidence plan still binds absolute paths and SHA-256 values for
public deterministic/verifier reports from run003/run005, plus the immutable run005
role-evidence-plan hash. Those public bytes are missing.

A zero-provider/zero-authority probe ran current `cognitive-field prepare` against a new scratch
report root using run006's preserved 9e6d916 worktrees and private suite. It passed and reproduced
suite/schema facts, but necessarily minted a new output root/timestamp/contract hash. It is only a
reconstruction probe, not accepted evidence.

The current seal implementation is in
`crates/eliot-app/src/cognitive_field_runner.rs`, especially:

- `seal_provider_plan_with_mode`;
- `load_core_role_evidence_plan` / accepted prior-role validation;
- `materialize_accepted_prior_roles`;
- generation/recovery record validation around `ProviderPlanSealRecord` and
  `AbandonedSealAttemptRecord`.

The exact Task 02R2 contract is:
`C:\Users\kleym\Downloads\ELIOT_COGNITIVE_COMPLETION_RECOVERY_PLAN_v3_0\ELIOT_TASK_02R2_RUNTIME_BOUND_CONTINUATION_v1_0.md`.

## Required decision

1. Does loss of the public sanitized projection invalidate the accepted U03 private evidence, or
   is it a recoverable projection-loss incident when all load-bearing private bytes/hashes remain?
2. May `run006 generation 2` continue? If yes, specify the smallest typed recovery transaction:
   exact inputs, hashes, before/after records, allowed reconstructed files, and validation order.
3. Must restored public files be byte-identical to the missing originals? If that is impossible,
   may a new projection version bind reconstructed bytes to the preserved private source evidence
   without rewriting the historical acceptance, or is that a provenance weakening?
4. Should this repair live in generic code (public projection is disposable/derivable from private
   canonical evidence) or be a one-run tuple-exact admission? Identify any security hole in either.
5. If run006 cannot continue, choose the minimal valid alternative: new run007 with four reused U03
   roles, new run007 with fresh U03 (raising the call plan), or full Task-02 restart. Reconcile that
   with the explicit eight-call/max-nine contract.
6. Give exact focused tests and live no-provider gates before any generation-2 seal.
7. Explicit do-not-do list and stop condition.

Return a compact decision with:

1. root-cause/provenance verdict;
2. chosen path;
3. minimal code/data changes;
4. exact tests/gates;
5. do-not-do list;
6. whether run006 generation 2 remains valid.
