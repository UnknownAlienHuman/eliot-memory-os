# REPORT - issue #66, W1 attempt 2 (`issue/66-W1-2`)

## Outcome

CODE CHANGES PUSHED. This attempt answers the 2026-09-24 cross-check that
refuted 7 MET claims of attempt 1 (REMAINING.md: C4, C5, C7, A2, A3, A5, W2):
2 production fixes (Kernel single-admission, Governor actual-candidate
ambiguity), 4 evidence-anchor corrections (stale lines after main drift),
1 confirmed-with-drift-report (C5 wire naming).

Checklist: 21 items (C1-C8, A1-A8, W1-W5) - 18 MET, 3 TEST-PHASE (A8 live
Product Pulse proof; W4 Kernel mapping runtime proof; W5 attach/onboarding
edge + Pulse). 0 GAP, 0 BLOCKED-BY.

## What changed (branch `issue/66-W1-2` vs `origin/main` 7f3ec0c)

1. `bins/eliot-kernel/src/lib.rs` - `claim_at` admits each ticket at most
   once (C4/A3). A result-less ticket whose claim was already admitted is
   never re-queued: the lease mark is a single-admission record, not a retry
   timer. Reconsideration requires a retained typed transient (`NotReady`)
   result with a changed-dependency discriminator via the gated superseding
   submit path. An unanswered ticket rests until the Kernel-owned deadline,
   which projects result-less `SemanticResolutionUnavailable` instead of
   looping the resolver. Comments updated; no new types, no shims.
2. `crates/governor/eliot-governor/src/composition.rs` - ambiguity names the
   actual candidates (A2). `resolve_activation_outcome` re-reads the live
   coordination selection on an ambiguity finding and builds
   `scope:candidate:{work_item_id}` handles (sorted, deduped, bounded by
   `eliot_protocol::MAX_AGENT_ACTIVATION_CANDIDATES` = 32, `Partial`
   coverage on truncation); <2 distinct candidates -> `FailedInternal`,
   never placeholders, never task selection. The pure string classifier can
   no longer manufacture handles: an ambiguity error reaching it without
   selection access maps to `FailedInternal`. No `scope:candidate:a/b`
   string remains in production code.
3. `bins/eliot-kernel/src/tests/activation.rs` - the lease test encoded the
   refuted behavior (`...retries_transient_resolution...` with no transient
   result); replaced with `activation_claim_is_single_admission_without_
   result_less_recycle` asserting single admission + no re-queue after the
   mark passes + rest-until-deadline. Equally strong (exact, no weakening).
4. Worktree-root deliverables: `CHECKLIST.json` (21 items, current-HEAD
   anchors), `VERIFY.md` (per-item re-verification + refutation responses),
   `REPORT.md` (this file), `PUSHED` (after push).

## Docs receipts

- `gh issue view 66 --comments` (full thread incl. audit v2, MGR-A/MGR-B,
  PR #2431 merge, W1 attempt-1 comment, code-complete + cross-check
  refutation comments).
- REMAINING.md, CHECKLIST.prev.json, PLAN.md, VERIFY.md, REPORT.md (attempt 1).
- COMMON-RULES.md (full), root AGENTS.md, nearest AGENTS.md
  (`bins/AGENTS.md`, `crates/AGENTS.md`, `crates/governor/AGENTS.md`),
  WORKFLOW.md.
- Fragments read directly: I04-04-01 (`:78` intake example, `:92`
  `TASK_SELECTION_REQUIRED`/`AMBIGUOUS_RESULT` prose),
  I07-20 (`:14` catalogue/alias boundary, `:67` disposition+reason+directive).
- Docs route: `python scripts/docs_read.py read --path
  crates/governor/eliot-governor/src/composition.rs --path
  bins/eliot-kernel/src/lib.rs --path
  bins/eliot-kernel/src/tests/activation.rs --topic "Return typed
  semantic-resolution failure instead of silently re-claiming tickets"` ->
  route `sha256:ceafeffca13b8e7962df1235c5fcb4cd8d250570cec70d4586e99a4d3cb825c0`,
  read receipt `sha256:893e688c923d35de08fe3612337fde432e6decbb6e6f7783ba07a53b23664070`,
  39 required items, bundle
  `sha256:4412e27529a986de64df02538bd50b1c14988ce6c6a8732bbb08264e383a41bf`.
  Reading attestation: every required bundle item opened and read before
  mutation (AGENTS.md, WORKFLOW.md, bins/crates/governor AGENTS.md,
  ARCHITECTURE_CONTRACT.md, READING_PROTOCOL.md, A/A10/A12/A13/I fragments
  in bundle). No normative prose changed.
- Normative sentences relied on: I04-04-01:92 (selection/ambiguity must be
  typed and immediate); I07-20:67 (disposition + exact reason_code +
  directive + operation identity; bridges switch on disposition);
  I07-20:14 (aliases only at migration/compatibility boundaries - hence no
  unilateral `AMBIGUOUS_RESULT` alias invented here).

## Gate (all with `$env:CARGO_TARGET_DIR='...\targets\W1-2'`)

- `cargo fmt -p eliot-governor -p eliot-kernel` -> exit 0, no changes.
- `cargo check --locked -p eliot-governor -p eliot-kernel --all-targets` -> exit 0.
- `cargo clippy --offline -p eliot-governor --lib` -> 54 warnings, exit 0;
  baseline (stashed, main): 54. NEW: zero. No warning in edited regions.
- `cargo clippy --offline -p eliot-kernel --lib` -> 17 warnings, exit 0;
  baseline: 17. NEW: zero.
- `cargo check --locked --workspace --all-targets --keep-going` -> 1 broken
  target: `eliot-platform-windows` lib test (E0382 `descriptor_digest`),
  proven pre-existing by re-running that package check on stashed main
  (same error). NEW broken targets vs main: zero. (Attempt-1 round also saw
  `eliot-native-worker` E0433; on this base it compiles.)
- `cargo test`: NOT run (owner order COMMON-RULES + manager brief gate
  "no test"; existing tests still compile via `--all-targets` check).
  Deviation from generic worker gate recorded here explicitly.

## Verifier result

Self-verification by direct re-read of every impl+caller anchor on the
pushed HEAD (no fresh-context subagent exists in this worker session):
18 MET / 3 TEST-PHASE / 0 standing refutations. Full table in VERIFY.md.

## Residual / reported (not acted on - out of scope)

- Doc-vs-code naming drift (REPORTED per authority rule, no third design
  invented): I04-04-01:92 prose and the I7.20 catalogue say
  `AMBIGUOUS_RESULT`; the stable activation-denial wire string is
  `SCOPE_AMBIGUOUS` (`crates/foundation/eliot-protocol/src/lib.rs:146`,
  surfaced via `AgentBridgeActivationDenialCode::ScopeAmbiguous::as_str()`).
  Functional contract holds (immediate typed projection; I7.20
  state/conflict disposition `STALE_OR_CONFLICT` + candidate-recovery
  directive + exact reason). Fix belongs to doc prose (preferred) or a
  migration-boundary alias, owned by the #204 agent-facing edge; a wire
  rename here would break the pinned 6-code vocabulary (roundtrip test
  `lib.rs:4103-4141) and widen scope into another sub-issue.
- Branch name `issue/66-W1-2` does not match the generic
  `^(work|fix|...)/...` form; kept per explicit manager brief (existing
  branch, continue). Rebase is a no-op: branch == `origin/main` 7f3ec0c
  (verified `git status`, no fetch per WORKFLOW worker rules).
- Remaining work is runtime/acceptance proof only (live edge run + #11
  Product Pulse, closure of #203/#204 and parent #66).

## Outputs (worktree root, per brief)

- `CHECKLIST.json`, `VERIFY.md`, `REPORT.md` (this file), `PUSHED`.
- ONE Russian issue comment (checklist table + branch@sha).
