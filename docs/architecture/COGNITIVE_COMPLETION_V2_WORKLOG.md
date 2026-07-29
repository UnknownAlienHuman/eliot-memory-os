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
| C5 | `90ad9cc` | Project-local bounded writer lanes, sole batched WAL actor, retry/unknown isolation, four-host seven-tool parity, concurrency/recovery/outage/secret gates. |

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

## Phase C5 acceptance record

C5 is accepted at `90ad9cc`. C6 cognitive field certification is now in
progress.

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

1. Inventory the existing cognitive runner, sealed oracle/reader/judge
   contracts, fixtures, second-repository path, and provider adapters.
2. Build deterministic and integration tiers before any quota-bearing provider
   call.
3. Run fresh Claude and Antigravity field cases only after the local C6 gates
   are green, recording the actual resolved model and sealed verdicts.

### 2026-07-29 implementation log

- Added `ControlWal::append_pending_batch`; one short redb transaction stages a
  bounded group.
- Added `ControlWalActor` as the only runtime owner of `ControlWal`.
- Added `WriterCoordinator` with bounded ingress/internal queues and default
  lane count `min(4, logical_cpu_count)`.
- Added strict one-active-job-per-project scheduling. Independent projects can
  occupy separate lanes.
- Delayed unknown-commit retry returns its lane before the timer starts; the
  affected project remains active, so unrelated projects are not blocked and
  same-project order cannot pass the retry.
- Added exact `write_id` reconciliation and explicit `UnknownCommit` /
  `ProjectWritePaused` terminal classifications. Unknowable outcome is never
  rewritten as known failure or success.
- Added metrics for configured lanes, maximum concurrent projects,
  backpressure, retry scheduling, and paused projects.
- During review, found a cross-project idempotency race in separate WAL
  `get`/`append` commands. Replaced them with actor-owned batched
  `stage-if-absent`, so two projects cannot both stage the same `write_id`.
- First engine/store all-target compile gate: PASS, 30.926 seconds. It reported
  only dead-code warnings for the metrics snapshot before public handle access
  was wired.
- Full `eliot-app --all-targets` compile gate after metrics and staging-race
  repair: PASS without warnings, 41.878 seconds.
- Writer unit gate: 3/3 passed. It proves CPU-bounded defaults,
  cross-project same-`write_id` staging admits exactly one pending record, and
  secret-bearing ingress is rejected before WAL staging. Latest incremental
  run: 0.08 seconds test body, 5.483 seconds end to end.
- Isolated C5 concurrency gate: 2/2 passed in 5.036 seconds test time and
  26.097 seconds end to end. It covers 32 sessions across 8 projects and
  single-lane retry isolation.
- Combined recovery gate initially failed 1/2. Separate evidence-log reruns
  classified `recovery_pending_replay_applies_once` as PASS and
  `recovery_unknown_commit_reconciles_by_write_id` as product failure:
  reconciliation returned the original receipt as `Committed` instead of
  classifying the current request as `IdempotentReplay`. No duplicate record or
  ordering failure occurred.
- Applied the replay-status repair at WAL hit, unknown preflight, concurrent
  stage hit, and exact reconciliation. Focused unknown-commit recovery then
  passed in 2.036 seconds test time and 10.373 seconds end to end.
- Host/session boundary suite: 12/12 passed in 0.01 seconds test time and
  5.004 seconds end to end. It covers host/role separation, immutable scoped
  session bindings, role inversion, candidate-only results, provider session
  identity, idempotent receipts, secret-free normalized events, and exact
  four-package skill hashes.
- Added a protocol equality test for Codex, Claude, Antigravity, and OpenCode:
  all four resolve to exactly the same seven names, input field names, schemas,
  and role-neutral instructions. PASS in 0.02 seconds test time and
  43.300 seconds end to end; compilation dominated.
- Found that the OpenCode bootstrap referenced three tools outside the exact
  seven-tool worker surface and that `ul doctor` omitted OpenCode. Repaired the
  bootstrap and added the fourth doctor host with config/plugin/skill checks.
- First four-host doctor compile failed because the new JSON comparison used an
  unimported `json!` macro. Replaced it with the fully qualified macro.
- Second doctor attempt compiled but exposed a real CLI identity mismatch:
  clap derived `open-code` while every canonical host/config field is
  `opencode`. Added the explicit value name.
- Four-host doctor then passed in 0.73 seconds test time and 20.241 seconds end
  to end.
- Canonical idempotency live gate passed 2/2 in 5.381 seconds test time and
  20.547 seconds end to end.
- Ten-agent / 100-write same-project ordering gate passed in 7.576 seconds test
  time and 9.291 seconds end to end.
- Clippy required four bounded repair passes: 11 findings in 8.710 seconds
  (manual clamp, documentation markup, large/long types, expect usage, and
  duplicate match arms); two remaining findings in 7.349 seconds; one
  remaining configuration-construction finding in 27.462 seconds; final pass
  in 0.811 seconds. A later parallel final pass also succeeded in 26.454
  seconds while waiting on the Cargo build lock.
- Added a pure `ProjectPauseTable` test after final scheduler review. The
  writer unit suite passed 4/4; the 0.04-second test body took 33.950 seconds
  end to end because a concurrent build held the shared target lock.
- Found a missing known-outage classification during final C5 review:
  `ServerNotFound`, `ServerStartFailed`, and `ServerAuthFailed` would have been
  made permanent on the first attempt. Added `FailedRetryable` WAL state, one
  bounded delayed retry, and `RetryableWriteUnavailable`; the affected project
  pauses on the exact unresolved `write_id`, while permanent and dead-letter
  counts remain unchanged.
- The focused no-server outage test passed as part of writer 5/5: 0.09 seconds
  test body, 8.772 seconds end to end. It proves one scheduled retry, one
  paused project, rejection of a later same-project write, one pending
  `FailedRetryable` record, and zero permanent/dead-letter records.
- Final format and diff checks passed.
- Final clippy gate for `eliot-store`, `eliot-engine`, and `eliot-app`, all
  targets with warnings denied: PASS in 20.695 seconds.
- Final isolated live C5 gate: 2/2 passed in 5.292 seconds test time and
  24.416 seconds end to end. The bounded harness reported no timeout, cleanup
  failure, secret leak, process leak, provider call, or host-configuration
  change; evidence log SHA-256
  `82d589819f7bb24d37d9a5eef4a51d1a0415b3b8f1eb8e87307be356a76352cd`.

## Current checkpoint: C6

C6 has not yet been accepted. The first action is a bounded inventory of the
existing cognitive certification implementation against the master contract;
do not spend provider quota until the deterministic and integration tiers are
green.

### 2026-07-29 C6 implementation log

- Cargo metadata confirms the five-crate workspace boundary. Fresh CodeCortex
  graph search found the existing managed `cognitive_runner`, canonical
  18-call contract, provider attestation, and old 12-case sealed suite.
- Rust LSP workspace-symbol search returned an empty result for `Cognitive`;
  source/metadata and the current code graph are the bounded fallback. No code
  claim relies on the missing LSP result.
- Confirmed product gap: no field-v2 48-case manifest, `TaskIntentOracle`,
  `CognitiveUnderstandingAnswer`, `CognitiveJudgeResult`, field grader, or
  field runner exists. The old runner remains the provider-process isolation
  layer rather than being replaced.
- Added the first field-v2 contract acceptance test. Its intended baseline
  failure is `E0432` for the nine absent field-v2 exports; 0.355 seconds end to
  end. No provider call occurred.
- First contract implementation compile failed because `JsonSchema` required
  an explicit string projection for the RFC3339 seal timestamp: `E0573`,
  23.215 seconds. Added the published string schema projection.
- Reader/Judge schema roundtrip then passed; the second contract test failed
  only because the field-v2 manifest did not yet exist, 27.595 seconds.
- Added the exact 48-case manifest with family counts U12/M8/D10/A6/H6/R6,
  provider cap 24, real-second-repository policy, shared zero-tolerance gates,
  reader/judge schemas, contamination rules, and role prompts.
- Field contract gate passed 2/2 in 0.01 seconds test time and 0.165 seconds end
  to end.
- Added the first field-grading acceptance test. Its intended baseline failure
  was absent `CognitiveFieldGradingService` (`E0432`), 40.151 seconds.
- Initial grader implementation passed 2/3 but incorrectly treated a
  Reader-discovered required verifier as an oracle leak. This was a product
  semantics error, not a test issue: pre-dispatch surfaces must hide oracle
  fields, while the externally graded answer may independently recover the
  correct verifier. Restricted output scanning to exact forbidden/private
  conclusions and retained full scanning for pre-dispatch surfaces.
- Field grader gate then passed 3/3: 0.00 seconds test time, 7.928 seconds end
  to end. It proves aggregate invalid-input reporting, stable oracle sealing,
  hidden-value scanning without raw-value persistence, score thresholds,
  memory-free zero-exposure, and deterministic hard-gate precedence.
- Added `cognitive-field validate/schema/prepare/grade`. The prepare path
  separates sanitized report output from a hashed private certification root,
  seals primary and second-repository Git SHAs, generates private per-case
  oracles before role execution, performs reader-surface leak scans, consumes
  zero providers, and is idempotently resumable only for an identical sealed
  request. Grade never upgrades missing evidence: it writes durable aggregate
  outputs and returns the blocked status until every expected execution passes.
- Initial CLI acceptance baseline failed 2/2 exactly because
  `cognitive-field` did not exist; 0.64 seconds test body, 84.906 seconds end
  to end due first full app link.
- CLI validation/schema/help then passed 2/2 in 0.65 seconds test time and
  38.597 seconds end to end.
- The remembered `projects/eliot-governor` second-repository path was absent.
  A bounded local scan confirmed that `eliot-memory-os` is the only current
  Rust Git repository under the workspace. Cloned the real MIT-licensed
  `BurntSushi/ripgrep` repository outside the workspace as the contract's
  network fallback; sealed candidate SHA
  `dffd776a737dc19a48b758dd6a621de113794121`.
- C6 clippy repair attempts: three findings in 25.691 seconds (explicit policy
  booleans and fallible schema serialization), one formatting lint in 33.728
  seconds, one standard-library lint in 24.197 seconds, final PASS in 17.028
  seconds.
- Combined C6 deterministic gate passed 7/7: 0.63 seconds test bodies,
  26.424 seconds end to end. No provider call occurred.
- First zero-provider prepare correctly failed closed in 8.048 seconds because
  generated U01 `required_verifier_refs` duplicated values present in the
  Git-visible suite. Classified as real oracle contamination, not a scanner
  false positive.
- Separated public routing/verifier execution refs from run-salted private
  oracle acceptance/invariant/verifier identifiers. The first focused
  regression command used `--exact` with an incomplete test name and selected
  0 tests (38.148 seconds, dominated by relink); the corrected filter passed
  the intended 48-oracle leak regression in 0.08 seconds test time and 0.288
  seconds end to end.
- The first post-fix `clippy` result was lost when the client truncated the
  tool output, so it was not credited. A bounded rerun passed with exit 0 in
  0.323 seconds (incremental), followed by `cargo fmt --all -- --check` in
  1.476 seconds and a clean `git diff --check`.

## Logging rule

For each next step, record:

- exact product change or observation;
- failed attempt and terminal classification;
- verifier command, pass/fail, test-body time, and end-to-end time;
- any Claude or Antigravity model actually resolved and why the call was worth
  its quota;
- corresponding candidate-only Eliot writeback receipt before final reporting.
