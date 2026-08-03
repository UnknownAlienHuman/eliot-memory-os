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
- Zero-provider prepare on source commit
  `97257a3fb9789a2fe6ef1c90d13c507349b4cc06` passed in 0.472 seconds for
  all 48 cases. It sealed ripgrep commit
  `dffd776a737dc19a48b758dd6a621de113794121`, consumed 0 provider calls,
  and produced contract hash
  `blake3:486a0ccfcc019a8a43f7a262a7beb6c51172a56610706ce2f643613f1730541a`.
- An identical prepare resume passed in 0.358 seconds with identical contract,
  plan, and private-root hashes. The sanitized report root contained four
  files and the private root exactly 48 oracle files.
- The intentional no-evidence grade took 0.500 seconds, emitted all four
  required aggregate artifacts, reported 0 passed and 61 missing executions,
  and exited nonzero with
  `MECHANISMS_COMPLETE_FIELD_CERTIFICATION_BLOCKED`. This is the required
  fail-closed result, not a claimed field failure. A raw private-value scan
  across all eight sanitized report artifacts was clean.
- Added a fail-closed deterministic-evidence importer. It accepts only the
  exact sealed run/case/condition/source binding, exact registered verifier
  coverage, zero provider calls, unchanged truth revision, zero exit codes,
  and SHA-256 readback of stdout/stderr files canonicalized under the private
  certification root. Only hashes, durations, command refs, and the sealed
  deterministic report enter the sanitized report tree.
- The importer and 48-oracle contamination regressions passed 2/2 in 0.08
  seconds test time and 47.655 seconds end to end; 47.11 seconds were compile
  and link time. The CLI surface passed 2/2 in 0.62 seconds test time and
  26.992 seconds end to end, again dominated by a 26.23-second relink.
- Added the required resumable PowerShell certification orchestrator. Every
  verifier batch is source/argv/output-hash bound and reusable after a client
  disconnect. It keeps raw logs outside Git, runs the workspace gate and real
  isolated SurrealDB suites, and emits all 61 planned deterministic
  case/condition receipts. PowerShell parsing passed with 1,891 tokens.
- Added an ignored real-SurrealDB R01 scale gate for 100,000 mixed logical
  records, 5,000 historical versions, 25 warm L0/L2 samples, and the exact
  75/150 ms p95 thresholds. Compile-only validation passed in 20.027 seconds;
  the measured run remains pending until this source state is committed and
  sealed.
- Focused clippy attempt 1 found only two test-harness policy findings
  (`too_many_lines` and intentional benchmark JSON stdout), 32.432 seconds.
  Attempt 2 found one uninlined format argument, 15.900 seconds. After narrow
  fixes, clippy passed in 15.935 seconds.
- The first committed orchestrator prepare on source
  `2d683c1952109db3c0cd991d65bde1043d545c81` passed in 8.953 seconds,
  including 7.85 seconds to rebuild the Governor. It wrote the required
  versioned report layout and kept all 48 raw oracles outside Git.
- The first background deterministic run stopped after `workspace-verify`.
  Metadata, formatting, check, and clippy passed; app unit tests passed 152,
  failed 1, and ignored 2. Total time to the fail-closed receipt was 123.542
  seconds. The failure was a stale assertion that forbade all `PostToolUse`
  hooks even though C5 intentionally added a mutation-filtered asynchronous
  observation hook.
- Updated the host contract test to require exact Pre/Post mutation matcher
  parity, the dedicated `post-tool-use` handler, passive unbound behavior, and
  asynchronous observation. The focused regression passed 1/1 with 0.00
  seconds test time and 10.670 seconds end to end (10.23-second relink).
- The second sealed run prepared on source
  `0e8c1df4918c5f696b2002d32387836641a49d8e` in 8.221 seconds. Its
  `workspace-verify` passed metadata, formatting, check, clippy, the repaired
  app unit suite, and subsequent integration binaries before failing in
  `ul_control_treatment` after 142.711 seconds.
- The second failure was another stale pre-C2 assertion: an explicit invariant
  waiver correctly clears `missing_capsule_invariants`, but it must not bypass
  the newer `blind_subsystem` discriminative-probe gate. Updated the test to
  require `require_probe`, prove the invariant-specific gate is gone, and
  require a non-empty suggested probe. The focused credential-gated regression
  passed parent and child 1/1 in 12.39 seconds test time and 14.410 seconds end
  to end.
- The third sealed run prepared on source
  `3cffdf5b3346bc21abe315f7c82e2ea34cc3d6f7` in 8.464 seconds. Its
  `workspace-verify` advanced through the complete application and integration
  surface before failing after 326.801 seconds in the engine unit regression
  `budget_drops_auto_codecortex_before_requested_handles`.
- The diagnostic rerun failed in 7.362 seconds and made the ordering defect
  exact: the packet reported
  `codecortex.full_to_scope_summary`,
  `codecortex.scope_summary_to_handle`,
  `codecortex.handle_dropped`, and then `known_decisions`. The requested handle
  survived, but the audit report's growing verbose truncation list was itself
  included in every token estimate. Its self-accounting overhead therefore
  forced an unrelated decision out after CodeCortex had already reached its
  floor.
- This was the third distinct late-suite incompatibility, so it crossed the
  agreed escalation threshold. The open Claude Desktop session was verified as
  `Opus 5` with `Max` effort, but Terminator could not place text into the
  prompt and no request was sent. The first non-interactive Claude Code attempt
  also stopped before dispatch in 0.505 seconds because the supplied empty MCP
  JSON lacked the required `mcpServers` record. It produced no stdout, only the
  local validation error, and therefore consumed no provider call. Raw
  provider-attempt evidence remains under the private certification root.
- The corrected no-tool Claude Code consultation completed in 158.991 seconds
  with exit 0. The requested CLI alias was `opus` at `max` effort, but the
  returned provider accounting resolved it to backend model
  `claude-opus-4-8`, not the `Opus 5` label visible in Claude Desktop. This
  mismatch is recorded explicitly and the result is not represented as an
  Opus 5 certification. The raw JSON is
  SHA-256
  `fe66a874e15a1daedbd089892a3e79d590f86c589db49d7d62cb5ba0b476b300`;
  stderr was empty.
- The consultation classified the token-budget failure as a product defect:
  mutating an in-band audit while measuring the same packet creates
  self-accounting pressure. It recommended bounded reservation/finalization,
  compact codes or a sidecar, exact-cap checks, and a typed error when
  protected content plus audit cannot fit.
- Chose the smallest non-breaking repair: retain the readable public
  `Vec<String>` audit schema, perform content trimming against a fixed empty
  report, finalize the complete audit once, and return
  `PacketFloorExceedsBudget` if mandatory audit metadata alone crosses the cap.
  The function no longer evicts later decision state merely to fund its own
  growing report, never raises the cap, and preserves exact-cap semantics.
- Focused repair attempt 1 stopped at compile time after 7.275 seconds because
  `ClaimCard` intentionally lacks `PartialEq`; attempt 2 stopped after 2.459
  seconds because an assertion moved a required-handle `String`. Both were
  narrow test-harness defects and never exercised the algorithm. Canonical JSON
  comparison and borrowed-slice assertions fixed them.
- The repaired budget regression then passed 1/1 in 0.00 seconds test-body time
  and 33.076 seconds end to end, including 24.67 seconds of relinking. It proves
  that the tight cap fails closed without dropping `known_decisions`, while a
  fresh packet at the exact reported minimum cap succeeds with equality.
- Focused clippy attempt 1 found one borrowed-slice improvement and three
  forbidden test `expect` calls in 36.216 seconds. After the narrow repair,
  clippy passed in 8.937 seconds and formatting passed in 1.586 seconds.
- The fourth sealed run prepared on source
  `04b18c79080ec23c01df15be17a9787e9260ddfe` in 11.473 seconds with 48
  private oracles, 0 provider calls, and contract hash
  `blake3:8e18dd3bd13360cd7c07bbeba8b607c6ce8188afa62a27b4ab6f4789ee59a0b3`.
- Its workspace verifier reached the late `ul_prediction` binary before
  failing after 432.870 seconds. The sole terminal failure was
  `t07_skill_and_description_budget`: C3 had intentionally replaced the old
  keyword-only `recall_l0` description with the current multi-kind,
  lifecycle-first, inspectable-ranking description, while the test still
  required the retired literal. Updated only that expected literal and
  retained the 90-token budget assertion. The focused regression passed 1/1
  in 0.00 seconds test time and 3.779 seconds end to end.
- The same parallel workspace run logged one transient SurrealDB bind
  `os error 10048`; it was not the terminal failure and the surrounding test
  process continued. It remains infrastructure-noise evidence for the final
  duration/reliability report.
- A CodeCortex causal slice exposed a separate C6 acceptance gap before any
  quota-bearing field calls: `cognitive_field_runner` imports deterministic
  receipts but merely trusts the presence of `reader.json` and `judge.json`;
  it has no sealed provider plan or provider-owned Worker/Reader/Judge
  provenance. The older managed `cognitive_runner` has strong pinned-process,
  secret-boundary, and UnknownOutcome controls, but its exact grammar is a
  separate 18-call OpenCode/Antigravity contract and cannot be silently reused
  as field-v2 evidence. Rust LSP reported the field files as unlinked from its
  current workspace; Cargo metadata and verifiers remain the source of truth.
- Added a field-v2-specific sealed provider plan instead of weakening or
  silently reinterpreting the older runner. Every call now binds an exact
  call number/id, isolated role, host, explicit versioned requested model,
  provider-executable SHA-256, private prompt path/hash, smoke/cap policy, and
  the exact case/condition executions it may produce. The validator requires
  complete Worker/Reader/Judge coverage exactly once, four separately
  accounted provider smokes, and no more than 24 non-smoke calls.
- Added provider-owned evidence receipts and sanitized per-role projections.
  Import now fails closed on alias/resolved-model mismatch, binary or prompt
  drift, source movement, timeout/unknown/controller substitution, multiple
  provider calls, nonzero exit, missing read-only role proof, oracle exposure
  outside Judge, Worker-transcript exposure, duplicate sessions/receipts,
  output-set drift, memory in a control execution, or missing M08 influence
  evidence. Worker, Reader, and Judge outputs are typed and bound to the same
  deterministic execution; the grader no longer accepts unproven loose
  `reader.json`/`judge.json` files.
- Added `cognitive-field seal-provider-plan`, `record-provider`, the Worker
  schema, and resumable PowerShell `SealProviderPlan`/`RecordProvider` modes.
  A constructed complete plan contains 23 capped calls plus four provider
  smokes and passed its first focused gate 1/1 in 50.373 seconds end to end.
  The provider envelope and plan gate passed 2/2 in 14.676 seconds.
- The first provider-importer compile attempt stopped after 3.141 seconds
  because a fixture replacement targeted the wrong similarly named receipt;
  no runtime evidence was accepted. After correcting the fixture binding, the
  end-to-end importer passed 1/1 in 19.233 seconds (0.09-second test body) and
  proved that only a sanitized, output-hash-bound Reader projection enters the
  report tree.
- Parallel provider-grader and CLI gates passed 3/3 in 26.911 seconds and 2/2
  in 56.028 seconds. The first provider-layer clippy run stopped after 99.267
  seconds on two bounded orchestration-size lints and one needless
  `drop` of a non-`Drop` value. Two narrow function-level allowances and
  removal of the needless drop produced a 16.260-second clippy pass.
- A post-implementation secret-boundary review found that exact provider
  binding alone did not scan the raw receipt, prompt, stdout, stderr, and
  structured output for common credential forms. Added zero-tolerance scans
  before parsing or publishing any of them. The resulting clippy run passed in
  8.165 seconds, provider tests passed 3/3 in 12.281 seconds, and CLI tests
  passed 2/2 in 12.506 seconds. The PowerShell orchestrator parser reported
  zero errors across 2,079 tokens.
- The first negative grade against the older `cognitive-field-04b18c7` sealed
  run exposed a Windows path-identity defect: `fs::canonicalize` produced a
  verbatim `\\?\C:\...` path while the contract stored slash-normalized
  `C:/...`, so the command failed before grading. Canonical identities now
  strip the Windows verbatim prefix while legacy contract hashes remain
  readable. A dedicated regression passed 1/1 in 0.00 seconds test time and
  0.6 seconds end to end.
- Two verifier-command corrections were required after the connection resumed:
  `eliot-app` has no library target (2.1 seconds), and its binary is
  `eliot-governor`, not `eliot` (0.5 seconds). Both were pre-test command
  errors, not product failures. The corrected provider-filter run passed
  13/13 in 13.7 seconds end to end.
- The repaired negative grade completed its evidence aggregation in 14.2
  seconds and then returned the expected nonzero
  `MECHANISMS_COMPLETE_FIELD_CERTIFICATION_BLOCKED`: 61/61 model executions
  remain absent, zero provider calls were consumed, and neither a provider
  plan nor provider evidence was falsely inferred from the old run.
- Added a checked-in isolated `CodexWorker` prompt with explicit no-oracle,
  no-self-grading, no-invented-evidence, control-isolation, and secret-boundary
  rules. Zero-provider prepare now scans it together with the Reader prompt,
  Reader schema, and public suite for every private oracle value. The final
  focused CLI gate passed 2/2 and focused all-target clippy passed with
  warnings denied in 24.4 seconds total.
- Committed the sealed provider-role evidence layer as
  `ff3ca775279558ff9f955d047d460dd0574f678b`. A new zero-provider prepare
  completed in 10.0 seconds, sealed all 48 cases and ripgrep
  `dffd776a737dc19a48b758dd6a621de113794121`, consumed zero provider calls,
  and produced contract
  `blake3:bcf851b40dee063adf96d13196de5ba009a5ef7bf89cd496c6c278bf5aaa1f77`.
- The resumable deterministic run proved the final local suite substantially
  farther than every previous attempt. `workspace-verify` passed with an exact
  receipt in 509,994 ms. The four real isolated SurrealDB batches also passed:
  context packets 2,387 ms, memory retrieval 20,757 ms, lifecycle 2,583 ms,
  and writer recovery 2,099 ms. Their stdout/stderr hashes are sealed under
  the private run root.
- The outer tool envelope expired after 904.040 seconds while R01 was still
  seeding. It killed the visible controller but left the process-guardian tree
  alive. The first inspection incorrectly looked only for a direct controller
  descendant and therefore missed the orphan. A second same-RunId R01 was
  launched, after preserving the two zero-byte unsealed outer logs; subsequent
  full process inspection found both 100k tests and both isolated SurrealDB
  instances running concurrently.
- No timing from the concurrent interval is accepted as a clean benchmark.
  The exact old guardian/tree was reconciled and stopped; the second tree later
  lost its nextest child without writing a final status while both guardians
  and the PowerShell controller remained waiting. Its receipt, outer stdout,
  and outer stderr were also absent/empty. This is classified
  `UNKNOWN_INTERRUPTED`, not a test pass or failure. The exact remaining
  guardians, SurrealDB child, and controller were then stopped through their
  own stop-file/exact-PID boundaries; zero matching processes remained.
- The R01 behavior is a separate test-infrastructure concern: on the target
  Ryzen 9 9950X, the test writes 100,000 mixed records in 100 sequential
  1,000-record governed envelopes plus 5,000 history updates before measuring
  25 L0/L2 samples. Its serial seeding and guardian disconnect behavior need
  dedicated study, but optimizing that test is outside this task. A single
  clean final-head retry remains required; neither interrupted attempt is
  counted.
- Antigravity preflight used the authorized desktop app without sending a
  prompt. Version 2.3.1 executable SHA-256 is
  `df97dea5fbd72adfd36abcc6806c6855564979f945ef0ab897dde3dfeba2ad07`.
  The actual selector currently offers Gemini 3.6 Flash High/Medium/Low,
  Gemini 3.5 Flash High/Medium/Low, Gemini 3.1 Pro High/Low, Claude Sonnet 4.6
  Thinking, Claude Opus 4.6 Thinking, and GPT-OSS 120B Medium. It does not
  expose Opus 5. No model call was consumed.
- Provider executable preflight recorded Claude Code 2.1.219 SHA-256
  `10f4c1f85b07f3cf6b8fff930fd26ecd475bd146a378acfafa559a6db9d89637`
  and OpenCode 1.4.3 SHA-256
  `619233c27bd8433cd8ea5aa8f6336404c31cc3872d5212685d5e5b279778a217`.
  OpenCode reports authenticated OpenAI and Anthropic OAuth routes. Its model
  catalog includes explicit `openai/gpt-5.4` and
  `openrouter/anthropic/claude-opus-5`, but no paid OpenRouter route was used.
- Direct execution of the Codex Desktop binary inside WindowsApps failed
  pre-dispatch with ACL `Access is denied`. An exact-hash copy under the
  private certification root ran successfully as `codex-cli
  0.146.0-alpha.3.1`; both source and copy hash to
  `39e9e041ea33ac34aad9578adfe660c5c7a6dc8f82620b77623960f9352a6ef3`.
  Only `--version` and `exec --help` were run, so no provider call was
  consumed.
- Provider-plan review found a hard isolation defect before dispatch: the
  previous chunking could combine treatment and memory-free-control executions
  in one provider session. Empty control output fields would not prove zero
  memory influence after a treatment in the same context. Validation now
  rejects every mixed-condition call. The exact 24-call plan allocates, for
  each role, four treatment calls, two control calls, one raw-corpus call, and
  one distilled-corpus call; the four host smokes remain outside the cap.
  The focused 24-call/isolation regression passed 1/1 and clippy passed with
  warnings denied in 27.7 seconds total.
- Committed the memory-condition isolation fix as
  `0d752c521126b5c28892847efc2505055dcaaf82`. Its sealed prepare completed in
  13.5 seconds with contract
  `blake3:0be0fe8640a3e69cb658a20fe6d93740dc541c0df03da0dd829732889dd5eb86`
  and zero provider calls.
- The `0d752c5` full local gate passed again with materially improved duration:
  `workspace-verify` 406,584 ms, context packets 2,575 ms, memory retrieval
  19,963 ms, lifecycle 2,336 ms, and writer recovery 2,145 ms. Every completed
  batch has an exit-0 hash-bound receipt. R01 had started as exactly one
  controller/nextest/test/SurrealDB tree when the next final-head issue was
  found; it was stopped through the exact test guardian and Surreal stop-file,
  leaving zero matching processes. It is not counted as an R01 result.
- Built a private, non-dispatching provider-plan generator. Its first parser
  pass found one PowerShell interpolation ambiguity (`$runId:`); runtime pass
  then found the reserved read-only `$Host` name. Both were generator-only
  pre-dispatch failures and consumed no model calls. The repaired generator
  produced exactly 28 calls: 24 condition-isolated capped calls and four
  smokes, with calls JSON SHA-256
  `3abdf0dd40bb6ed4b4e1476c47ed73169756eac58b9c9c20f9979d077e03fc92`.
- The private route assigns Codex Worker/Judge to explicit
  `gpt-5.6-sol`; the Claude smoke and one complex U06/U07/U08 Reader block to
  `claude-opus-5`; four Antigravity Reader calls including smoke, Russian,
  unseen-repository, and control scenarios to
  `google-antigravity/gemini-3.6-flash-high`; and the remaining Reader calls
  to `openai/gpt-5.4` through OpenCode. The plan remains unsealed until the
  final source SHA has complete deterministic evidence.
- Final provider rehearsal exposed one more practical Judge-input omission:
  engine grading independently checks the Judge's BLAKE3
  `reader_output_hash`, but Reader import published no Governor-computed hash
  for a fresh read-only Judge. Requiring the model to reproduce Rust's typed
  serialization would create false failures. Reader import now writes a
  sanitized `eliot-cognitive-reader-binding-v1` containing the typed BLAKE3
  hash, source/run/case/condition binding, and raw output SHA-256. Final grade
  still recomputes the hash independently.
- The first focused reader-binding compile attempt stopped after 5.8 seconds
  because the test module referenced unimported `Value`/`read_json`; replacing
  those with fully qualified `serde_json` parsing fixed only the fixture.
  Reader import, 24-call plan, and clippy then passed in 26.8 seconds total.
- The final `cognitive-field-67f6c6d` deterministic attempt terminated
  cleanly after 115,350 ms with `workspace-verify` exit 1. The exact failure
  was `c3_unified_projection_pages_beyond_512_and_preserves_filters_and_dedup`:
  its daemon could not persist a new 32-byte Operator cursor key through
  Windows `CredWriteW`, which returned `os error 8` (`Not enough memory
  resources`). The source had 0 logical test failures before this environment
  boundary; the failure receipt and raw logs remain under the run's private
  verifier directory.
- An isolated retry reproduced the same terminal failure in 31,028 ms despite
  roughly 90 GiB of free physical memory. `cmdkey /list` then showed 837
  current-user credentials, including 736 stale
  `EliotGovernor/operator-cursor/isolated-*` records produced by prior unique
  test runtimes. This was Credential Manager exhaustion, not host RAM
  exhaustion or retrieval logic.
- The first deletion preflight failed closed without deleting anything because
  its process filter also matched the live default Antigravity MCP daemon and
  the cleanup PowerShell itself. The corrected preflight matched only
  `--instance isolated-*` or exact Rust test executables. It deleted exactly
  the 736 pre-enumerated `operator-cursor/isolated-*` credentials with 0
  failures and left production/default, local-dev, l15-cert, Surreal, and
  round-trip credentials untouched.
- All credential-gated Rust test harnesses now set the existing
  `ELIOT_TEST_ALLOW_LEGACY_OPERATOR_CURSOR_KEY_FILE=1` boundary for their
  subprocesses and direct test daemon commands. This keeps ephemeral cursor
  keys in each access-restricted test runtime instead of leaking unique
  credentials into the user store. The exact C3 test then passed 1/1 in
  14,035 ms end to end (11.94 seconds test body), and isolated Credential
  Manager records remained exactly 0 before and after the test.
- The next immutable run, `cognitive-field-40b0d7a`, prepared in 11.3 seconds
  with zero provider calls. A first private provider-plan generation stopped
  before dispatch because the new run root lacked its verified Codex binary
  copy. After copying the prior exact-hash binary
  (`39e9e041...6ef3`), generation produced 24 capped calls plus four smokes;
  calls JSON SHA-256 is `ec9426a8...e27ca`. No model was called.
- Its deterministic `workspace-verify` passed in 407,480 ms. The live receipts
  also passed: context packets 2,131 ms, memory retrieval 19,296 ms, lifecycle
  2,129 ms, and writer recovery 2,033 ms. R01 ran as exactly one process tree,
  remained CPU-active with an approximately 350-440 MiB isolated SurrealDB
  working set, and terminated without timeout or orphan after 2,179,092 ms
  (36.3 minutes) with nextest exit 100.
- The R01 wrapper retained only the terminal summary (`0 passed, 1 failed`).
  Guardian metadata proved that 10,747 stderr bytes existed inside the owned
  temporary root, but `run-isolated-tests.ps1` removed that root before the
  optional evidence path had been used. The outer verifier stderr was empty.
  Therefore no lost seed, L0, or L2 metric is reported or inferred as an
  observed result.
- This repeated long-test blocker was escalated once to Claude Code with
  explicit `claude-opus-5`, high effort, plan mode, read-only Read/Grep/Glob,
  and a strict empty MCP config. The first-party response was successful:
  session `2fbf68f1-a243-4224-987e-ac8256447196`, 21 turns, 412,938 ms,
  31,640 output tokens, no web search, and USD 2.090176 reported by the CLI.
  Opus confirmed the evidence-publication defect and identified a separate
  source-provable fixture bug: the first needle claim was included in the
  5,000 history IDs and then replaced through `UPSERT ... CONTENT` before the
  test queried its old statement.
- Local source verification accepted both findings. The bounded fix now
  publishes a redacted, 64-KiB-tail-bounded failure excerpt to hash-bound
  stderr before exact cleanup, optionally writes the same redacted evidence
  outside the cleanup root, and receipts byte/truncation/path/detail fields.
  Passing batches remain silent. R01 now excludes ordinal zero from historical
  updates and has a fast regression for the exact history-selection boundary.
  Corpus size, 75/150 ms SLOs, scan cap, provider isolation, and cleanup were
  not weakened.
- Focused harness evidence:
  - failure probe: expected exit 41 in 2,062 ms, 68-byte stderr and external
    evidence with the same SHA-256 as the merged nextest log;
  - success probe: exit 0 in 1,974 ms, zero-byte stderr with SHA-256
    `e3b0c442...b855`, zero failure excerpt;
  - retained-descendant probe: expected exit 42 in 2,013 ms, excerpt retained,
    all process receipts stopped, exact roots removed;
  - harness-security PASS (provider calls zero and exact cleanup preserved);
  - real-nextest empty filter: expected exit 4 in 3,433 ms, 521-byte bounded
    excerpt / 474-byte captured stderr, exact roots removed;
  - fixture regression PASS in 1,342 ms and app/store test Clippy PASS in
    924 ms.
- An attempted execution of the ignored `fwl_static_safety_boundaries_hold`
  body stopped in 389 ms because its provisioned first-working-loop recipe was
  absent. This is the test's declared environment precondition, not an
  acceptance result; static anchors still compile and the directly exercised
  security probes cover the changed harness behavior.

## Terminal R01 diagnostic and blocked handoff

- Commit `94af919` was tested with one final, exact R01 diagnostic under
  `%LOCALAPPDATA%\Eliot\cognitive-field\diagnostics\r01-94af919`. The wrapper
  used an external evidence path, one owned process tree, the unchanged
  100,000-record / 5,000-history / four-kind fixture, 25 samples, and the
  unchanged 75/150 ms SLOs.
- The diagnostic ended `FAILED_VERIFIER`, not timeout, after nextest reported
  2,569.350 seconds (42.82 minutes). Seeding took 76,218 ms. The exact result
  was:
  - warm L0 p95 `93058.839 ms` versus `75 ms` (`1240.78452x` over);
  - small L2 p95 `237.4652 ms` versus `150 ms` (`1.58310x` over).
- All owned process receipts were stopped, temporary and secret roots were
  removed, and cleanup failures/pending lists were empty. The retained
  evidence is 10,880 bytes with SHA-256
  `84c623da4b882339d95fa2fb12a355d47eafe8271461c25705ad9d5d0467f764`.
  Wrapper stderr is 10,821 bytes with SHA-256
  `2f4fc0c2d9420c2e444ba435a5185d8ab162b81e8c91e1993f2f84c0df6944a9`;
  stdout is 2,194 bytes with SHA-256
  `ec764c1cce829d60a6229ce4e4d228a2ef3b46bc4d8f6d4e5787297db4e3dbf7`.
- This is a product/architecture performance failure on the requested Ryzen 9
  9950X host with fast memory, not host RAM exhaustion. The certification task
  intentionally did not weaken the SLO, corpus, sampling, scan cap, or query
  semantics and did not expand into an open-ended retrieval optimization.
- The contract order therefore stopped before provider-plan sealing. No
  Worker/Reader/Judge certification calls, Antigravity cognitive-field calls,
  grade, PR, merge, or CI were performed or claimed. The earlier explicit
  `claude-opus-5` call remains a read-only engineering consultation, not a
  certification provider call.

## Eliot durable writeback

- The first atomic write attempt safely rolled back because the live
  `task_contract` schema requires `acceptance`, `expected_artifacts`, `goal`,
  `non_goals`, and object `scope`; no partial records were left.
- The schema-aligned retry committed and exact readback confirmed one blocked
  task contract, one contract source snapshot, three evidence atoms, one
  verified blocking claim, one verification run, five initial failure
  fingerprints, one trace span, one context packet, and one each of
  `supports`, `verified_by`, `belongs_to`, and `produces`.
- The repository `graph_health.surql` could not run unchanged against the live
  global Eliot schema: it references absent `produced_by` and
  `invalidated_by` relation tables and would also query absent `scope_head`;
  the live relation is `produces`. This tooling/schema drift was recorded as a
  sixth failure fingerprint. A bounded equivalent over the live tables passed
  in 1.356 ms with zero orphan, weak, contested, or duplicate-write findings.
- Inbox sources are
  `.eliot/inbox/20260729T123511Z-cognitive-completion-v2-blocked.surql` and
  `.eliot/inbox/20260729T124426Z-graph-health-schema-drift.surql`. They remain
  untracked project-local state and are not part of the Git commit.
- The final 339-line / 23,107-byte report was written to
  `reports/cognitive-field/COGNITIVE_COMPLETION_V2_BLOCKED_REPORT_20260729.md`
  with SHA-256
  `8f691e07215f8ad61171b1841c2f82d499632f8a31dac5979fd8a525028c079c`.
  A third inbox write added this report as
  `evidence_atom:cognitive_completion_v2_blocked_report_20260729`; exact
  readback confirmed its checksum and a typed record reference in the context
  packet.

## Final disposition

- Product implementation through the C6 harness is committed on
  `codex/cognitive-completion-v2`, but the master package is not certified.
- Terminal state is `BLOCKED / FAILED_VERIFIER` at R01. The next honest work
  package is a bounded retrieval/query performance investigation followed by
  exactly one unchanged R01 rerun. Only after that gate passes may the sealed
  provider sequence resume.

## Logging rule

For each next step, record:

- exact product change or observation;
- failed attempt and terminal classification;
- verifier command, pass/fail, test-body time, and end-to-end time;
- any Claude or Antigravity model actually resolved and why the call was worth
  its quota;
- corresponding candidate-only Eliot writeback receipt before final reporting.

## 2026-08-01 Task 03 retrieval hot-path investigation

- Recovery Task 03 resumed from the terminal R01 evidence without weakening the
  100,000-record corpus, 5,000-history fixture, 75/150 ms SLOs, or 2-second
  per-query timeout. Baseline store retrieval remained 5/5 green before the
  change.
- Root cause was confirmed in source: normal L0 paged six record kinds in
  128-row RPCs, scanned as many as 65,536 candidates, then decoded and ranked
  the entire set in Rust. The old audit path is now isolated behind
  `lifecycle_audit`; normal recall uses a derived projection.
- Added `memory_search_projection`, `memory_search_token`,
  `memory_search_state`, and `memory_search_outbox` with composite project,
  handle, lifecycle, token, and revision indexes. Canonical writes commit first,
  leave a pending outbox record, then idempotently replace the handle's posting
  set and advance the derived-state revision. A failed derived dispatch is
  repaired by replaying the same canonical write. Canonical rows remain truth.
- Added deterministic rebuild from canonical rows, revision equality checks
  before normal recall, exact-handle lookup, bounded 256-handle candidate load,
  Rust final ranking, an index-plan probe, and rebuild/restart determinism
  coverage. Lifecycle audit continues to use the historical paged loader.
- A live unique-index failure proved that colon-bearing strings such as
  `claim:<uuid>` were being coerced by SurrealDB into record identities. The
  established character-fragment transport boundary was applied to handles and
  record references. A second live failure proved that one-row subqueries may
  unwrap to objects in SurrealDB 3.1.4; every affected result is normalized with
  a wrapper/flatten/filter before array operations, and final row order is
  restored from an authoritative handle list in Rust.
- The first focused isolated runs failed 2/5 and then 2/5 for those two exact
  transport/query-shape causes. After the repairs, the broad focused test passed
  1/1 and the real retrieval suite passed 5/5 in 35.744 s. The added EXPLAIN and
  deterministic rebuild assertions then passed 1/1 in 10.740 s.
- PF1 was first accidentally interrupted by a 60-second outer shell limit, not
  by the test's 600-second guardian. The exact owned Surreal guardian and child
  were stopped through their own stop file. The interrupted temp/secret roots
  remain at run id `ec58419dc22849e1aa6d1a96ef5d798d` because a later exact
  recursive cleanup command was blocked by the host policy; no process from the
  run remains.
- The retained PF1 evidence for the correctness-first projection is 10,000
  logical records, 500 historical updates, four kinds, seed 48,732 ms, measured
  L0 680.3451 ms, L2 486.3797 ms, and query wall 1,166 ms. PF1 passed its
  2-second readiness timeout but missed the eventual SLO by a wide margin.
- A bounded per-term posting experiment reduced the same PF1 to seed 55,620 ms,
  L0 236.7372 ms, L2 80.1493 ms, and query wall 316 ms. Its retained evidence is
  `%LOCALAPPDATA%/Eliot/cognitive-field/recovery-v3-task03/pf1-bounded-postings.json`.
  It was not retained in product state because removing the ambient small-corpus
  fill exposed neutral-paraphrase recall regressions.
- A conditional bigram/trigram primary plus unigram fallback was rejected. It
  improved the suite from 2/5 to 3/5 but still suppressed a provider/argv/opaque
  identifier paraphrase, and long n-gram posting sets could evict unigram
  postings under the per-row cap. A subsequent concurrent Rust-union prototype
  also failed that neutral case. Both experiments were rolled back.
- Two quota-worthy consultations used the existing Claude Code session
  `703f5a06-7b30-4783-bce1-e74d4de580ba` headlessly with exact model
  `claude-opus-5`, max effort, plan mode, strict empty MCP, and read-only tools.
  The first (117.4 s wall / 114.102 s API; CLI-reported USD 2.342597) confirmed
  the scalar/array normalization and order-preservation repair. The second
  (144.2 s wall / 141.458 s API; CLI-reported USD 2.449322) rejected conditional
  fallback and recommended an always-on <=12-term union, concurrent posting
  pages, Rust aggregation, deterministic content-only posting selection, and
  advisory recomputed DF. Neither call used web, MCP, writes, or permissions.
- The performance branches were stopped after repeated cognitive regressions,
  per the two-attempt rule. The repository was restored to the last
  correctness-proven projection. SurrealQL validation, `cargo check -p
  eliot-store`, and the isolated real retrieval suite then passed 5/5 in 36.756
  s (54.786 s end to end).
- Task 03 disposition is therefore `BLOCKED / SLO_NOT_MET`, not complete. PF2,
  PF3, and exact R01 were not run because PF1 already failed the readiness
  threshold. The next bounded experiment must first preserve the complete
  neutral-paraphrase set while separating posting-page, aggregate/rank, and
  final-row-fetch timings. Stop if the final 256-row fetch alone exceeds about
  50 ms or capped lookup still scales approximately linearly with corpus size.
- Eliot handoff was completed through the live sealed daemon and exact named-pipe
  MCP path. Candidate `claim:b0c14f5f-569d-42ca-8966-32f71bf5dc28` committed at
  revision 12 with explicit file cues and remained `candidate_only`; detailed
  observation `observation:7b319d25-6a2a-4945-a6ca-1d23b6cf0727` committed at
  revision 13. Exact `eliot_fetch_l2` readback returned both handles and the
  expected full payloads. A preceding L0 probe with `scope=candidate_only`
  produced an honest scope mismatch and was not treated as failed persistence.
- The writeback used existing product project/task scope
  `461b9de3-26e9-8f15-89b1-fb3944e22941` /
  `019fbc2c-9872-7ac3-9112-766c57674ed8`. Recovery Task 03 had not created a
  separate canonical product task. The raw global Surreal MCP tool was not
  exposed, so no competing embedded owner was started and `.eliot/` was not
  modified or staged.
- Final `clippy -D warnings` exposed a 20-positional-argument retrieval-row
  constructor. It was replaced with named `RecallCandidateInput` fields; narrow
  documented lint exceptions remain only for the exhaustive enum-to-SQL table
  and the scale harness's machine-readable stdout contract. Final clippy passed
  in 0.812 s, fmt plus diff check passed in 2.200 s, and all six touched SurrealQL
  files validated in 1.790 s.
- A first post-refactor isolated invocation spawned a child PowerShell that
  rejected the script under ExecutionPolicy in 0.623 s before tests started.
  Running in the already authorized host passed all 5 retrieval tests in 36.049
  s / 48.394 s end to end, made zero provider calls, removed its exact temp and
  secret roots, and left no owned process or cleanup failure.
- The final check bundle was stored and read back exactly as
  `observation:e445da7f-9a3e-40ab-bf6a-7da4bb8a5b59` at memory revision 14.

## Ultra Master v4.1 continuation

### 2026-08-01 Phase 0 start

- The controlling contract is now
  `ELIOT_COGNITIVE_COMPLETION_ULTRA_MASTER_FINAL_v4_1.md`, SHA-256
  `3579eca01e2118ce80fb9735d833363d25e282dc9fbb903ebe51cce7ced16627`.
  It supersedes the earlier Task03R and unstarted Task04/Task05 repair prompts.
- The verified starting point is branch `codex/cognitive-completion-v2` at
  `88a5f049d71a9c535f51811eb7da273416c27118`; the only pre-existing untracked
  path is operator-owned `.eliot/`, which remains out of scope.
- Archive ref `archive/cognitive-completion-ultra-pre-v4-88a5f04` was created
  locally and pushed to `origin` at the exact starting commit. The first push
  command made no repository change because PowerShell parsed an unbraced
  variable adjacent to `:`; the corrected explicit refspec succeeded.
- The installed child-agent surface exposes spawn, message, follow-up,
  interrupt, list, and wait operations. A no-write child audit completed and
  confirmed the contract ordering. The orchestration response does not expose
  the resolved child model or reasoning effort, so those values remain
  explicitly unverified rather than inferred.
- Current code graph and exact source anchors show the Phase 0 defect:
  canonical MCP task completion performs receipt/scope checks and then mutates
  the task directly to `DoneVerified`, bypassing `CompletionGate`,
  `CompletionProof`, coordination state, WorkItem verifier evidence, and
  CandidateReview acceptance.
- Cached rust-analyzer diagnostics were empty for the candidate types, engine,
  worktree, coordination, and MCP task files before editing.
- An initial structural-search invocation used an unsupported `sg scan --lang`
  form; the supported `sg run -l rust -p` form then produced the bounded
  hard-coded `DONE_VERIFIED` inventory. This was a command-syntax issue, not a
  product failure.
- Phase 0 implementation is constrained to the existing completion owners:
  canonical evidence is assembled into `CompletionProof`, the existing
  `CompletionGate` makes the sole task-level decision, coordination/work/review
  state becomes required evidence, and subordinate reports use operation-level
  statuses rather than task-level `DONE_VERIFIED`.

### 2026-08-01 Phase 0 acceptance

- `TaskContract` now persists a nested `CompletionProof`; the canonical MCP
  completion route validates exact project/task, goal, changed-artifact,
  acceptance-item, observation, verifier, and scope bindings before delegating
  the only task-level terminal decision to `CompletionGate`. Canonical replay
  requires the same proof hash instead of accepting a different proof for an
  already completed task.
- `CompletionGate::decide_for_task` now combines the existing incident and
  completion owners with exact-scope `StopCoordinationGate` state, all required
  `WorkItem` verifier receipts, and the latest non-empty candidate diff plus an
  accepted receipted `CandidateReview`. `WorkQueueService::complete_verified`
  records the verifier/review references and has no unchecked completion path.
  Write admission remains the fail-closed storage backstop.
- Suboperation and report state now uses typed `OperationStatus` values
  `OPERATION_COMPLETED`, `ACTIVE`, `BLOCKED`, and `FAILED`. A bounded literal
  audit left `DONE_VERIFIED` only on true task completion and explicit
  guard/replay probes; no ad-hoc JSON `final_status` literals remain.
- Provider-free Phase 0 behavior passed after the final refactor: completion
  truth 7/7 in 7.524 s, work/lease 19/19 in 3.289 s, nested task proof 5/5 in
  34.841 s, and exact-scope stop coordination 1/1 in 0.297 s. Earlier
  post-hardening patch and worktree completion checks passed 1/1 in 5.543 s
  and 1/1 in 5.133 s. The complete positive proof and negatives cover empty
  acceptance, missing verifier evidence, pending controller acknowledgement,
  open blocker, unresolved conflict, and missing/rejected/unreceipted review.
- The affected-package all-target `cargo check` passed in 9.959 s. The first
  `clippy -D warnings` exposed three local quality defects in the new code; a
  second pass advanced to test `expect` calls, one 101-line validator, and an
  unboxed dispatcher future; a third reached two fixture-only style findings.
  These finite findings were fixed without lint suppression. The final
  all-target clippy passed in 0.703 s on a warm cache. `cargo fmt --check`,
  both changed SurrealQL validations, capability-matrix JSON parsing, and
  `git diff --check` passed.
- Test duration remains dominated by Cargo compilation/build-lock overhead on
  this Ryzen 9 9950X host: the final app proof test body reported 0.00 s while
  wall time was 34.841 s. Earlier tiny focused tests took 31.073 s, 48.066 s,
  and 112.615 s wall; one incorrect exact-name filter consumed 116.750 s and
  ran zero tests, so it is explicitly not evidence. This is a later harness
  investigation candidate, not part of the Phase 0 product repair.
- A candidate-only Eliot checkpoint was staged as
  `%USERPROFILE%\OneDrive\Documents\MCP\.eliot\inbox\2026-08-01T190033-0400_eliot_memory_os_ultra_v4_phase0_checkpoint.surql`
  and passed `surreal validate` in 0.7 s. The native `eliot_surrealdb` MCP tool
  is not exposed in this Codex task, while the sealed SurrealKV owner is already
  running; no competing embedded owner was started. The checkpoint therefore
  remains honestly staged, not applied or read back.
- Phase 0 is accepted locally and unlocks Phase 1 only after the exact commit
  `COG-00: make cognitive capability and completion evidence truthful` is
  created and pushed. No provider cognition or Claude/Antigravity quota was
  used because no repeated architecture uncertainty remained.

### 2026-08-01 Phase 1 start

- Phase 0 was committed and pushed as
  `77b1b876ff8a9da37f430c05942baba1496fffe6` with the exact required subject;
  `ls-remote` returned the same SHA. The only remaining worktree path was the
  pre-existing operator-owned untracked `.eliot/`.
- Two independent read-only preflights confirmed the C7-03A defect. The daemon
  owns a long-lived `ReadySurrealServer`, but `McpDaemon` builds a separate
  config-only `CanonicalStore`; each of its 50 direct `execute_value` paths
  creates, authenticates, and shuts down a new transport. The accepted repair
  is one daemon-owned shared `DbClientSet`: one server lease/generation, four
  read transports, one FIFO write transport, and one admin/health transport.
  Fatal connections are invalidated without replaying the current request;
  reconnect is bounded and applies only to a later request. Shutdown is
  explicit/idempotent and preserves an external server.
- Local `surreal.exe` reports exact version 3.1.4. A bounded ephemeral in-memory
  probe passed analyzer/FULLTEXT/BM25 creation, bound `@OR@`, Unicode, opaque
  identifiers, logical project isolation, and EXPLAIN `FullTextScan`. The owned
  probe stopped and port 19471 was independently verified closed. EXPLAIN
  applies the project filter after the global FTS scan, so multi-project scale
  remains a measured gate rather than an assumed property.
- Exact C7-03B/C gaps are also located: the base tokenizer incorrectly caps at
  12; `BTreeSet` sorts before both caps; manual token postings, aggregation,
  posting EXPLAIN, and ambient fill remain active; `recall_l0` may rebuild a
  whole project synchronously; and the scale harness reseeds stages instead of
  reusing one verified 100k corpus. Rust final ranking remains the required
  owner after FTS candidate generation.
- No provider was called. The local FTS proof and matching static architecture
  leave no two-option ambiguity. Claude escalation is reserved for a failed
  real 5/5, restart determinism, R01, or a genuine recovery-policy conflict.

### 2026-08-01 C7-03A pre-commit audit

- The first persistent-client implementation passed compile, strict Clippy,
  four FIFO/no-replay/shutdown unit cases, two exhaustive access-class cases,
  and one isolated real-database case. The live case retained six sessions
  across 100 warm reads, bounded 16 delayed readers to a peak of four, kept two
  project filters isolated, returned one stable outcome to concurrent shutdown
  callers, and preserved the external guardian PID and TCP endpoint.
- Acceptance was intentionally withheld after an independent audit found four
  boundary defects: caller-supplied raw SQL could forge its access class; the
  bootstrap admin socket had a second strong owner; daemon construction loaded
  config twice; and cancellation/partial-start failure could discard the only
  owned-server cleanup authority.
- The systemic repair removes public raw execution, transfers the bootstrap
  transport out of the lease owner, derives `CanonicalStore` configuration from
  `DbClientSet`, passes one immutable config snapshot into `McpDaemon`, and
  makes owned cleanup cancellation-safe while retaining cleanup errors. The
  isolated harness gains a library-target route so the delayed raw probe stays
  private test code.
- CodeCortex surfaced the existing `no_public_raw_sql_or_direct_transport`
  invariant while confirming the affected daemon/lease anchors. These are
  bounded local corrections, so no Claude or Antigravity call was warranted.
- Re-audit confirmed those four repairs, but correctly kept C7-03A blocked on a
  deeper pre-`ReadySurrealServer` branch: after spawning a detached child,
  PID-receipt, `try_wait`, timeout-finalization, or Ready-construction failure
  could drop Tokio's `Child` without terminating the process. The accepted
  repair is one post-spawn finalizer which kills/waits the exact child and
  preserves primary plus cleanup errors; a real PID-write failure injection on
  a fresh root/port must prove that no child or listener survives.

### 2026-08-01 C7-03A acceptance

- `DbClientSet` now owns one database lease/generation, four fixed read
  transports, one FIFO write transport and one admin/health transport. Named
  operations derive their exhaustive access class internally; raw classified
  execution is private test code. Fatal transport results invalidate their slot
  without replaying the current request; reconnect is available only to a later
  request and remains bounded.
- `CanonicalStore` clones share the one client set and derive their database
  configuration from it. Daemon construction passes the same already-loaded
  Governor config snapshot to `McpDaemon`, eliminating a mixed-generation
  config race. Explicit shutdown is detached single-flight and idempotent;
  start adoption and shutdown waiters are cancellation-safe.
- `ReadySurrealServer` transfers the bootstrap admin socket instead of retaining
  a second strong owner. Its post-spawn guard covers process identity, PID
  receipt, readiness, and Ready/client-lease creation; every error kills and
  bounded-waits the exact child and preserves cleanup failures. Successful
  readiness explicitly disarms the guard. The rare cold-start future is boxed
  at its single call boundary to prevent its state size from propagating into
  hot/scale futures.
- Focused final unit evidence: client ownership/FIFO/no-current-replay cases
  6/6 in 3.848 s; Ready lifecycle 6/6 in 0.227 s; exhaustive access classes 2/2
  in 0.8 s; repository no-public-raw-SQL invariant 1/1 in 50.3 s wall with a
  zero-second test body (49.30 s compilation).
- Real external-server gate passed 1/1 with a 2.344 s body and 39.393 s wall:
  the production path `Arc<DbClientSet> -> CanonicalStore::from_client_set ->
  migrate -> cloned typed read` retained six sessions; 100 warm reads created
  no new sessions; 16 delayed readers reached exactly four; project-filtered
  rows did not mix; concurrent/late shutdown agreed; external PID/TCP survived.
  Evidence SHA-256:
  `e693f1ac0d9469acc3e4a8318608eb1613c9dc884cbe486257a7ac822d683a9b`.
- Real post-spawn failure injection passed 1/1 with a 3.636 s body and 21.628 s
  harness wall. Making `tmp/surreal.pid` a directory forced PID-receipt failure
  after spawn; the exact parsed PID was dead, the fresh port was closed and the
  runtime root was removable. Evidence SHA-256:
  `593179b9973a51aa34048b795b191214c607fabaf038bd5c5dd17ec2b040d231`.
- Both live harnesses removed temporary and secret roots, reported empty
  cleanup failure/pending arrays, stopped every owned guardian and made zero
  host configuration changes. The system Eliot MCP process was never touched.
  Two independent audit passes ended in `ACCEPT`. Provider calls remained zero.
- Final affected-crate verification after the post-spawn finalizer passed:
  `cargo check -p eliot-store -p eliot-app --all-targets` in 22.608 s wall and
  strict `cargo clippy` for the same targets in 29.689 s wall. Formatting,
  capability-matrix JSON parsing and `git diff --check` also passed.
- The post-change fast CodeCortex refresh completed without a repository
  artifact: 20,462 nodes and 94,109 edges. The only untracked repository path
  remains the pre-existing operator-owned `.eliot/`; it was not read as task
  truth, modified, staged or deleted.
- C7-03A is therefore accepted for the exact commit
  `C7-03A: persist daemon database clients`. A higher-level writer may
  explicitly retry a reconciled write with the same receipt/id; this is a
  governed application decision and is distinct from forbidden silent
  transport replay of the current call.

### 2026-08-01 C7-03B acceptance

- The base `normalize_query_tokens` is now genuinely uncapped and retains the
  first occurrence without sorting. The three non-retrieval consumers whose
  prior behavior depended on the old hidden cap now state their own local
  twelve-token boundary: fallback task classification, distillation identity,
  and UL fallback matching. Focused tokenizer/consumer gates passed 4/4,
  4/4, 8/8 and the two local-cap cases; their test bodies were 0.00-0.06 s,
  while cold/shared-build wall times ranged from 0.208 s to 79.763 s.
- Retrieval now has stable ordered selectors. Query candidates are selected in
  query, task-cue, concept order and capped at 12 after deduplication. Projection
  documents select handle/record ref, cues, concepts, preview and remaining
  search/scope text in that order and cap at 2,048. Six selector, persistence
  and format-fence unit tests passed in a 4.481 s compile/run wall.
- Additive migration 010 defines versioned `eliot_memory_search_v1` and
  `idx_memory_search_projection_fts_v1` with `IF NOT EXISTS`, so routine daemon
  migration does not rebuild an unchanged index. The typed read binds
  `search_document @OR@ $query_text`, filters by project before its 257-handle
  sentinel limit, returns at most 256 compact rows and delegates every final
  relevance decision to the existing Rust ranker. All four changed/new SurQL
  resources validated on exact SurrealDB 3.1.4 in 0.500 s; registry tests
  passed 18/18.
- The format fence is explicit: ordinary incremental dispatch supplies no
  projection format and therefore cannot promote a partially upgraded legacy
  project. Only a completed full rebuild records `fts_v1`; the private FTS
  loader requires both that format and exact head revision. The public legacy
  recall and its posting EXPLAIN remain unchanged until C7-03C. This avoids a
  test-only cutover and preserves rollback while C7-03B proves the additive
  production implementation.
- The real provider-free FTS gate used one external guardian, one daemon-owned
  `DbClientSet`, two typed project envelopes, complete format-fenced rebuilds
  and the existing Rust rank. It passed all five cases: English target amid
  distractors, Unicode, opaque exact handle, empty/missing terms yielding
  `no_useful_memory`, and a local hit despite 260 foreign same-term records.
  EXPLAIN contained `FullTextScan` and the versioned index. Final v2 test body
  was 5.746 s and harness wall 17.385 s; provider calls and host changes were
  zero, all roots/processes cleaned, and evidence SHA-256 is
  `f98947e31cae7a922b1c523fdf9a2477b10dd32c044f14a8bc2c56988a8b1c65`.
- The changed legacy retrieval regression suite passed 5/5 in 14.904 s body
  and 20.966 s harness wall, proving the additive phase did not alter public
  recall before cutover. Harness security passed in 1.570 s. Final affected-
  crate all-target `cargo check` passed in 13.378 s and strict Clippy in
  20.690 s; format, JSON, PowerShell parser and diff checks passed.
- Two issues were corrected before acceptance. The first compile of the new
  live module exposed one concrete `Box<StoreError>`/`Box<dyn Error>` branch
  mismatch; the explicit coercion fixed it and the next run passed. Independent
  audit then found that repointing the public query-plan diagnostic would make
  legacy behavior and its test disagree; the public diagnostic was restored
  and the FTS EXPLAIN kept private until cutover.
- The live harness also exposed a Phase 0 evidence-report residue:
  `run-isolated-tests.ps1` still emitted a raw subordinate
  `final_status=DONE_VERIFIED`. It now emits typed
  `operation_status=OPERATION_COMPLETED|FAILED`, and the harness-security gate
  rejects any returned `final_status`. The first otherwise-passing FTS log is
  retained only as diagnostic history; the accepted v2 evidence was generated
  after this repair. Similar task-level wording in two subagent chat summaries
  was treated as non-authoritative tool text and was not persisted as product
  completion evidence.
- An independent no-edit audit returned `ACCEPT`: no public/raw SQL seam, no
  partial-state promotion, no database final ranking and no premature C7-03C
  deletion/cutover remain. No provider cognition was used. C7-03B is accepted
  for the exact commit `C7-03B: prove ordered SurrealDB FTS candidates`.
- The final fast CodeCortex refresh completed without a repository artifact at
  20,462 nodes and 94,109 edges. The only unrelated untracked path remains the
  operator-owned `.eliot/`, which was not staged, modified or deleted.

## 2026-08-02 — C7-03C final execution / Block A closure

| Slice | Commit | Accepted result |
|---|---|---|
| C0 | `53817fa4c42be07889fda689496a5ba3460be9d8` | Acceptance daemon runtime state is isolated from host authority state. |
| C1 | `545d0858a8ccbda7e8bf517a03ea655c21ab6631` | Response provenance is separate from immutable packet-commit identity; exact replay uses the original stored effects. |
| C2 | `3b6ebbc04e114e2ebdf48de4d564fd2b2e776c25` | Lossless parent/page/segment memory, native FTS admission, complete cue overflow, and one durable projection owner are finalized. |
| C3 | `a4ffaa20e0e7e9fc809b74806ca6c5135eee6787` | Packet persistence is append-only, restart-recoverable, bounded, effects-once, and supports canonical plus legacy task handles. |

### Closed architecture

- Packet content identity, response provenance and state-changing operation
  identity are distinct domains.
- Immutable intent plus append-only state events is the sole packet outbox
  authority. Startup recovery inventories every task deterministically, attempts
  at most 32 pending replays, isolates corrupt neighbors and reports residuals.
- Canonical task replay preserves the string serializer, global task mutex and
  cross-process transition lock order. Legacy handles remain local-only.
- Canonical memory pages and cue overflow are lossless. SurrealDB FTS/BM25 only
  admits bounded candidates; deterministic Rust ranking remains final.
- `ProjectionCoordinator` is the single lifecycle owner for focused projection
  builders. It arms recovery before daemon READY; inventory and rebuild work
  then drains on its owned background task.
- Windows atomic replacement now canonicalizes only the parent into
  extended-length form, preserving leaf and `MoveFileExW` replacement semantics.

### Acceptance evidence

- C1 focused U9.6 regression passed with stable packet/operation identities,
  byte/hash-identical replay, no repeated `ul_fired`, and unchanged authority,
  intent, event history, effects, receipts and revision.
- C2 focused source/unit gates passed; live store and app gates covered FTS,
  lossless L2, projection lease barriers, cue firing, 512+ retrieval, cold
  recovery and session dedup. Provider calls were zero and cleanup was clean.
- C3 packet units passed 17/17. Windows atomic replacement passed 3/3,
  including an extended-length path.
- C3 U9.8 passed with canonical and legacy recovery, byte-identical projection
  repair, exactly three outbox events ending in `complete`, effects-once across
  a second restart, 300 corrupt predecessors, and a misplaced authority.
- App checks, strict affected-target Clippy, format and diff checks passed.
  Focused isolated gates reported `provider_calls=0`, no timeout, no cleanup
  failure and no retained run-owned process or secret root.

### Escalation and exclusions

- Claude Code Opus 5 at Max effort was used read-only for the ambiguous packet
  identity/recovery decisions. Its rulings were accepted only where current
  source and deterministic verification supported them.
- No provider cognition, full workspace verification, release build, final
  scale ladder or 48-case evaluation was used as Block A evidence.
- Preserved drafts for hot understanding/admission, utility/distillation and
  final scale certification are explicitly excluded from this closure and are
  not acceptance evidence.

**Block A result: PASS.** The next allowed implementation item is Block B1,
engine-owned `UnderstandingRuntime`, from the exact aggregate head.

## 2026-08-03 — C7-04A / Block B1 implementation checkpoint

### Ownership and production cutover

- Kept one engine `UnderstandingRuntime`, the existing
  `CognitiveProjectionCoordinator`, and Writer/CanonicalStore as the durable
  restart authority. Deleted the constructible app `UlRuntime` owner and
  `McpState.ul`; `McpDaemon` now constructs and shares one runtime.
- Project snapshots are immutable, revision-fenced and bounded to 64 MiB of
  conservatively charged requested allocations. Cue keys, all handles and
  mandatory negative/invariant payloads remain hot; optional bodies are
  deterministically elided before an explicit mandatory-minimum rejection.
- `CueIndexService` keeps only a weak routing alias after runtime adoption.
  Runtime eviction releases the active hot cue allocation, and every rejected,
  failed or superseded candidate releases the service's staged strong owner.

### Hot semantics and restart authority

- Cue firing, bounded activation and injection selection consume immutable
  snapshots and return deterministic plans without owning Store or Writer.
  Direct cues fire with zero edges; depth-two spread remains gated at the
  unchanged 500-edge threshold. Tier-T remains bounded to 3 items / 400 units.
- Pending injection is one deterministic, bounded, failure-atomic WriterActor
  batch. SurrealDB stores exact base64 payload bytes, rejects conflicting batch
  reuse, reloads at most 256 items, and atomically deletes only the exact
  `(item_ref, fingerprint)` acknowledged by an injection receipt.
- App dispatch persists the exact candidate queue before installing that same
  queue in the session mirror. Restart and `max_sessions=1` eviction hydrate
  pending items plus delivered receipts and preserve effects-once behavior.
  Freshness, request-time novelty, packet revision and mutation staleness remain
  snapshot/session-owned and revision-fenced.

### Verification evidence

- Strict Clippy passed for `eliot-types`, `eliot-store`, `eliot-engine` and
  `eliot-app`; format and diff checks passed.
- Engine runtime passed 15/15, injection selection 4/4, cue ownership/budget
  3/3 and coordinator units 7/7 (one isolated guardian intentionally ignored by
  ordinary Cargo). Store SurQL contracts passed 27/27; the live atomic pending
  batch/restart/exact-dequeue test passed 1/1.
- App cutover passed 3/3, full push 4/4 and pyramid delivery 5/5. Isolated
  projection lease/retry/block, full-wake recovery and same-revision dirty-fence
  guardians each passed 1/1 with `provider_calls=0`, no timeout, no cleanup
  failure and no retained run-owned process or secret root.

### Acceptance blockers found by final audit

- Hydration and tool execution are not covered by the same pending-commit
  critical section. A concurrent `max_sessions` eviction can recreate an empty
  mirror and atomically replace an older durable pending queue with only the new
  plan.
- Candidate admission retains already delivered/stale entries until later
  selection. They can consume the mandatory cap and create a false overflow or
  a runtime/durable mismatch.
- WriterActor short-circuits an idempotent observability receipt before the
  store transaction, so replay of an injection receipt can bypass the exact
  pending-row cleanup performed by `apply_observability.surql`.

**C7-04A result: CHECKPOINT — NOT ACCEPTED.** The implementation and recorded
tests are committed for preservation, but Block B1 remains open and C7-04B must
not start until these three production paths have focused regressions and pass.
