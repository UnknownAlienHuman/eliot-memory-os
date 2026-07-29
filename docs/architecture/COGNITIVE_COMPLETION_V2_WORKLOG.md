# Cognitive Completion v2 — recovery worklog

This file is the durable recovery checkpoint for
`ELIOT_Cognitive_Completion_Memory_Distillation_Field_Certification_v2_0.md`.
Update it after every accepted phase, material failure, external-model call,
or change to the next action.

## Contract and branch

- Contract SHA-256:
  `757883D21DA2E3AB23C304D444699DB1DB03E02FC09599B66C1BBA222749107C`.
- Repository: `projects/eliot-memory-os`.
- Branch: `codex/cognitive-completion-v2`.
- Baseline: `bccb334021749854df1c10733d0e2fadd4b704ca`.
- User-owned `.eliot/` is out of scope and must remain untracked.

## Accepted phases

| Phase | Commit | Accepted result |
|---|---|---|
| C1 | `bfea61a` | Correct material stub, Unicode task classification, exact Codex worker surface/doctor parity, latest-per-target beyond 128, metacognition v2. |
| C2 | `6358b5d` | Six-hop typed project-understanding model, continuity/history, CodeCortex freshness/scope, host matrices, budget ladder, exact claim-only gating. |
| C3 | `115babb` | Unified paged projection, revision fence/restart, lifecycle/scope and request context, inspectable ranking, dedup/supersession, operator fields. |
| C4 | `305d84c` | Canonical utility ledger, pure distillation plan and governed apply, exact-only reversible automation, lifecycle/tier controls, bounded sleep, stable paging beyond 1,000. |

## Material attempts and timing evidence

- C2 used one Claude Code Opus 5 Max escalation for a material architecture
  decision. No Claude request was used for C3 or C4.
- C3 isolated store tests timed out twice at 15 seconds and then passed
  unchanged in 23.02 seconds. Classified as a timing/build-harness flake.
- C4 direct ignored live test failed before test execution with
  `Error: NotPresent` because `ELIOT_TEST_SURREAL_PASSWORD_FILE` was absent.
  The official isolated harness then passed.
- C4 live SurrealDB gate: 1,011 canonical records, restart, revision fence,
  no gaps or duplicates; 16.286 seconds test body, 31.956 seconds end to end.
- C4 engine/sleep: 18/18, 0.01 seconds test logic, 19.647 seconds end to end.
- C4 final targeted reruns: types 11.62 seconds, engine 24.69 seconds,
  app protocol 46.85 seconds. Cargo cache/build locks and linking dominated.
- Repeated 60-second combined app test/help invocation expired while
  compilation continued; after the build completed, the test passed in
  0.252 seconds and CLI help passed in 0.836 seconds.

## Current checkpoint: C5

No C5 source edit has been made yet.

Confirmed gap:

- current `WriterActor` owns the redb `ControlWal`, the single bounded input
  queue, and every SurrealDB transaction;
- it therefore preserves serial order but prevents independent projects from
  committing concurrently;
- the external `WriterHandle` / `WriterActor::channel` API is used widely and
  should remain source-compatible.

Confirmed existing foundations:

- `write_id` idempotency and unknown-commit lookup already exist;
- host identity is separate from task role;
- scoped `TaskRoleLease` and candidate-only worker/auditor output checks exist;
- the four canonical skill bodies and host-package parity lint exist.

Next actions:

1. Add one `ControlWalActor` as the sole short redb writer owner.
2. Add a bounded `WriterCoordinator` with
   `min(4, logical_cpu_count)` default workers.
3. Preserve strict per-project FIFO and one canonical transaction in flight per
   project while allowing independent projects to progress concurrently.
4. Reconcile ambiguous commits by `write_id`; if still unknowable, pause only
   that project and never report success or failure as known.
5. Add reliability tests for 32 sessions / 8 projects, four agents on one
   project, retry isolation, restart/unknown commit, deduplication, and secret
   rejection.
6. Re-run host-package parity and seven-tool semantic checks.

## Logging rule

For each next step, record:

- exact product change or observation;
- failed attempt and terminal classification;
- verifier command, pass/fail, test-body time, and end-to-end time;
- any Claude or Antigravity model actually resolved and why the call was worth
  its quota;
- corresponding candidate-only Eliot writeback receipt before final reporting.
