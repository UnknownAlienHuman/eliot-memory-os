# work/18-*|19-* reconciliation addendum — 2026-09-21 (worker A2)

- Worker: A2, Line A (manager ses_f3967c915ffe37azHENefcpkV6).
- Worktree: `A-store-task-binding-20260921`, branch
  `codex/1929-task-binding-runtime` (HEAD `d259c73f` preserved; this
  addendum is a local-only commit on top, no push/fetch/merge).
- Base re-verified: `main` at
  `5d92bd7f89df55f8257858a98b266cdeda008f5b` (newer than the
  disposition base `649a2c0ac5b2f60ae1d0d761c82572f67aac4789`;
  `git merge-base --is-ancestor 649a2c0a main` = yes, exit 0).
- Sources (read-only): `CONTROL/18-19-complete-branch-dispositions.md`
  and `CONTROL/store-work1819-dispositions.md`. Finished rows are NOT
  rewritten here; this file only records re-verification at the new
  base plus head changes since the dispositions were written.
- Method (same as base docs): `git rev-list main..TIP --no-merges`,
  then behavior tracing on `main` via `git grep`/`git show`
  (`main:<path>`). Only TRUE hunk/behavior correspondence counts.

## Result

**Truly useful missing behavior: none. Bounded carry proposals: none.**
All 18 remaining rows trace to same-behavior successors on
`main@5d92bd7f`. Root integrates nothing from this set on Store
grounds; lane owners keep their rows.

(Retired by root — not re-traced, refs observed preserved locally:
`work/1911-contracts-verify` now at `aec79ac2` (see flag below),
`work/1961-failure-verify` at `429f47c2`,
`work/1964-plugin-doctor-verify` at `37e66004`.)

## Per-branch re-verification (TIP verified + main-side evidence)

### work/18-t11-1-daemon-client @ 38fda171 (same as disposition)

- Unique: `38fda171` (count 1, unchanged).
- Main: `bins/eliotd/src/daemon_kernel_client.rs` 8 hits +
  `kernel_context_read_client.rs` 37 hits for
  `DaemonKernelClient|KernelContextReadClient`.
- Verdict: on-main.

### work/18-t11-1-daemon-e2e4 @ bbc23b86 (same)

- Unique: `d6686405`, `bbc23b86` (count 2, unchanged).
- Main: `live_surreal_evidence_pack_e2e` present in
  `crates/kernel/eliot-kernel-service/src/store_gateway.rs`.
- Verdict: on-main.

### work/18-t11-1-daemon-query-e2e-retake @ 68a50b65 (same)

- Unique: `68a50b65` (count 1, unchanged). Same main evidence as e2e4.
- Verdict: on-main (duplicate retake).

### work/18-t11-3-a-governor @ a398f2da (same)

- Unique: `a398f2da` (count 1, unchanged).
- Main: `seven-role|seven_role` x5 in `context_inputs.rs`;
  `zero-edge|zero_edge` x3 in `cue_composition.rs`.
- Verdict: on-main.

### work/18-t11-3-b-store @ b9f6d9e8 (same)

- Unique: `b9f6d9e8` (count 1, unchanged).
- Main: the four cognitive reads present in `read_boundary.rs`
  (19 hits; count drifted from 25 by refactor, behavior present).
- Verdict: on-main (stale Sep-15 variant; main fuller).

### work/18-t11-3-c-daemon @ 339e5ba0 (same)

- Unique: `339e5ba0` (count 1, unchanged).
- Main: `ContextReconstruction` x4 (`daemon_runtime.rs`), x6
  (`eliot-read` lib), x28 (`eliot-mcp` core).
- Verdict: on-main.

### work/18-t11-3-seven-provider @ ed22ab8c (same)

- Unique: `ed22ab8c`, `b9f6d9e8`, `339e5ba0`, `a398f2da`
  (count 4, unchanged).
- Main: `enforce_catalogue_gate` x2 in
  `crates/storage/eliot-store-memory/src/lib.rs`.
- Verdict: on-main.

### work/1882-catalogue-verify — HEAD MOVED to b68d5732 (merge only)

- `b68d5732` = merge of main-side `59861b8d` into `0ea1b20b`
  (main-sync, non-source). No-merge uniques unchanged:
  `56f00a52`, `0ea1b20b`. Disposition SHA `0ea1b20b` confirmed
  ancestor of current tip.
- Main: `Hotset|activation_display` x67 in
  `crates/governor/eliot-skill/src/catalogue.rs`.
- Verdict: on-main. Ref preserved, nothing new to trace.

### work/19-task-lifecycle-activation @ 5acc600e (same)

- Unique: 7 commits (unchanged). Disposition successor `78769d5a`
  confirmed ancestor of `main`.
- Main (evolved form): `UpdateTaskState` x6 in `task_lifecycle.rs`,
  x5 in `operation_catalogue.rs`; digest-deref micro-fix verbatim at
  `task_lifecycle.rs:551`
  (`|| receipt.operation_manifest_digest != *manifest_digest`);
  daemon forwarding arm evolved to `ForwardingTaskLifecycle`
  (`view`/`propose_task`/`apply_task`), wired at
  `bins/eliotd/src/lib.rs:1030-1045`; `UpdateTaskState` catalogue
  membership asserted in `bins/eliotd/tests/epistemic_readback.rs:85`.
- Verdict: on-main in full (successor evolved past the branch arm).

### work/1956-wasm-verify — HEAD MOVED to 5c658bbe (merge only)

- `5c658bbe` = merge of main-side `6b523bdd` into `a6b112e7`
  (main-sync, non-source). No-merge uniques unchanged: `ea568d97`,
  `f13cd8ed`, `53502a8d`, `a6b112e7`. Disposition SHA `a6b112e7`
  confirmed ancestor of current tip.
- Main: divergent fixture
  `bins/eliot-wasm-host/tests/fixtures/guest-conformance-divergent.wat`
  exists; `rollback` x32 in
  `crates/modules/eliot-wasm-runtime/src/lifecycle.rs`.
- Verdict: on-main. Ref preserved, nothing new to trace.

### work/1958-route-separation @ 0cf256e9 (same)

- Unique: `0cf256e9` (count 1, unchanged).
- Main: requested-vs-observed separation documented and enforced in
  `bins/eliotd/src/route_receipts.rs` (module doc: requested route
  vs `RuntimeObservedFacts` observed fingerprint, divergence
  classification, no second fingerprint type).
- Verdict: on-main.

### work/1958-route-verify @ 5fed1d3c (same)

- Unique: `0cf256e9` + `5fed1d3c` (count 2, unchanged).
- Main: same separation plus hardenings visible (`unknown`-marker
  rejection at `route_receipts.rs:99-101`, attempt/receipt
  requested-route binding at :106-107).
- Verdict: on-main.

### work/1959-admission-callsites @ f5bb73d6 (same)

- Unique: 2 commits (unchanged).
- Main: `capability_admission` module present;
  `CapabilityAdmission` wiring x15 in `bins/eliotd/src/lib.rs`.
- Verdict: on-main.

### work/1959-admission-evidence @ 985637ae (same)

- Unique: `985637ae` (count 1, unchanged).
- Main: freshness/quarantine/requalification language x10 (ci) in
  `capability_admission.rs`.
- Verdict: on-main.

### work/1959-admission-verify @ d2ec37c1 (same)

- Unique: `985637ae` + `d2ec37c1` (count 2, unchanged).
- Main: broken/unsupported handling x21 (ci) in
  `capability_admission.rs`.
- Verdict: on-main.

### work/1962-firstrun-verify — HEAD MOVED to 00b379ab (ONE NEW SOURCE COMMIT, traced)

- `00b379ab` = merge of main-side `d0b8ac3f` (confirmed on main)
  into the branch. No-merge uniques now 3 (was 2): `bf851a07`,
  `b46a3bec`, plus NEW branch-side `fbce51f6` (child of `b46a3bec`,
  NOT on main): "2258: wire automation flags, legacy gate, and
  settings payload through setup" (`first_run_flow.rs` +159,
  `main.rs` +46, `eliot-config first_run.rs` +41:
  `apply_automation_update`, `FirstRunAutomation` parse, `--automation`/
  `--owner-ref`, canonical `Setting` payload in receipts,
  legacy `governor.toml` rejection in `run_setup`).
- Main-side coverage of the new commit's behavior:
  - `apply_automation_update` + `FirstRunAutomation` parsing
    (`suggest_only`/`manual`/`idle_only`/`scheduled`/`continuous`/
    `off`), non-blank `owner_ref` gate, and
    "setup set requires --route, --automation, or both" all present
    in `bins/eliot/src/first_run_flow.rs` (lines 17-18, 42-191);
    introducing main-side commit `fb745e0f` ("Add explicit
    first-run setup choices and guarded settings preparation",
    `-S apply_automation_update` / `-S 'setup set requires'`).
  - Legacy gate present in evolved form:
    `gate_legacy_config_observation` + `revalidate_legacy_governor_gate`
    (`bins/eliot/src/main.rs:103-107, 1074-1093, 1342, 2318`).
  - Base behaviors intact: hidden-paid/unassigned x4
    (`first_run_wiring.rs`), x22 (`eliot-config first_run.rs`).
- Verdict: on-main, INCLUDING the new commit. No carry.
- Ref preserved (`b46a3bec` confirmed ancestor of `00b379ab`).

### work/1963-staffing-verify @ f61291cc (same)

- Unique: 3 commits (unchanged).
- Main: "A caller cannot widen..." verbatim x1 in
  `bins/eliotd/src/staffing_policy.rs`.
- Verdict: on-main.

### work/1966-config-verify @ 4f9409c6 (same)

- Unique: 4 commits (unchanged).
- Main: strict-sub-envelope / stale-grant / duplicate-layer /
  abstain language x10 in `canonical_config_precedence.rs`.
- Verdict: on-main.

## Missing-behavior list

Empty. No row carries behavior absent from `main@5d92bd7f`.

## Carry proposals

None.

## Flags for root (no action taken; read-only observation)

1. `work/1911-contracts-verify` (already retired by root) now resolves
   to `aec79ac2`, one commit past the disposition SHA `0f6a7349`:
   "1911: gate main drive and stdio paths on carried action
   envelopes end to end". If retirement meant exact preservation at
   `0f6a7349`, the extra child commit is unexpected — root may want
   to confirm it is benign/intended. Untouched by this worker.
2. `CONTROL` (`C:/Development/Rust` repo tree) was left untouched:
   this addendum lives in the worker worktree only (local commit, no
   push). Root owns integrating these findings into
   `CONTROL/18-19-complete-branch-dispositions.md` /
   `CONTROL/store-work1819-dispositions.md` if desired.
3. Worktree HEAD `d259c73f` (1779 automation wire contract draft +
   bulk bound rename, WIP transfer) preserved; this addendum commits
   on top locally without modifying any WIP content.

## Freeze / remaining work

- Freeze for this lane: 15 of 18 rows are byte-identical tips to the
  dispositions (re-verified, no change); 2 rows advanced by main-sync
  merges only (1882, wasm-verify); 1 row (firstrun-verify) gained one
  source commit (`fbce51f6`) which is fully traced to main-side
  `fb745e0f` + legacy-gate successors — nothing duplicative of, or
  replaced by, active Store/task-binding work.
- Remaining: none in this lane. All 18 remain retired-in-place
  (already-on-main); no Store-hunk carry; no held conflicts.
