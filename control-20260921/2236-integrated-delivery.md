# 2236 integrated delivery — exec identity binding (leaf scope)

Leaf: OpenCode Muse1.3, worktree `B-2236-integration-20260921`,
branch `codex/1805-exec-identity-integration`, candidate `94763444`.
Issue #1805 / original PR #2236 (`work/1805-exec-identity` @ `30358ba3`).
LOCAL commits only; no fetch/push/PR/main mutation by this leaf.

## Status / HEAD (observed 2026-09-21)

- `git status --short --branch`: clean, on
  `codex/1805-exec-identity-integration`.
- `HEAD` = `94763444` (merge of `origin/main` into the leaf branch).
- Ancestry preserved: `30358ba3` present in
  `git log --oneline origin/main..HEAD`
  (`13e0b067`, `c4699c9f`, `30358ba3`, `94763444`).
- `origin/main` is an ancestor of `HEAD` (`merge-base --is-ancestor` exit 0);
  `1a18895e` (clean-merged main per root brief) is an ancestor (exit 0).
- Working tree clean after verification: **no new code commit required**;
  candidate frozen at `94763444`.

## Scope owned / touched

Owned (this leaf): `crates/instrument/eliot-process-executor/**`,
`crates/instrument/eliot-instrument-runner/**`,
`crates/eliot-engine/src/verification/current.rs`, plus the necessary
`crates/instrument/eliot-instrument-runner/Cargo.toml` + `Cargo.lock`
(one added intra-workspace dep line each). Not edited: Governor/eliotd,
Kernel/Host, worker (Turing's joint-proof surface). No API change was made,
so no control-handoff coordination was triggered.

## What was verified complete (no code delta needed)

Prepared implementation already delivers actual executable identity binding;
verification below confirms it is executable-path code, not helper-only:

- Executor (`eliot-process-executor/src/lib.rs`): `ExecutableObservation`
  with machine-hashed canonical path + SHA-256 content bytes
  (`observe_at_path` canonicalizes and hashes file bytes; Windows open uses
  deny-write + reparse-point refusal mirroring the launch lease posture),
  `observe_from_intent` (re-hash must equal intent-sealed
  `executable_sha256`, else `DigestMismatch`), `verify_against_intent`
  (re-hash + argv + env re-check at evidence time), `environment_projection_digest`
  (sorted non-secret map + inheritance + secret refs, no secret material),
  `resolve_executable_in_path` (PATHEXT / separator-file / Unix exec-bit).
  Error taxonomy: `Missing`/`Unreadable` → `Unavailable` (transient);
  `DigestMismatch`/`ArgvMismatch`/malformed → `UnknownOutcome` (binding
  verdict, never retried). `ArgvMismatch` is never transient.
- Runner (`eliot-instrument-runner/src/lib.rs` + `registry.rs`):
  `InstrumentRunner::launch_verified` checks the machine-derived observation
  against the registry entry AND the sealed request argv (argv-to-argv, never
  argv-to-invocation-filters) BEFORE `executor.start` (real spawn);
  `GovernedInstrumentResult::require_authoritative_pass` refuses PASS on
  missing/diverged identity, argv sealed-at-launch divergence, unretained raw
  output, or non-`Succeeded` execution; `bridge_executor_observation`
  re-validates every field under the claiming instrument;
  `From<ExecutableObservation>` moves already-shaped fields.
  Honest bounds kept in prose: version/env are attested (no `--version`
  execution); hash race narrowed to the observation instant; retained
  cross-launch pin stays with the kernel lease (other owner).
- Engine (`eliot-engine/src/verification/current.rs`): `run_current`
  resolves the invocation through `ProviderRegistry`, pins nextest
  adapter/parser/verifier bindings, enforces
  `check_resolved_executable` (swapped/renamed/missing executable rejected
  before evaluation), required set from the admitted plan only.

## Checks (single runs, no loops)

- `cargo test -p eliot-instrument-runner --lib`: **11/11 pass**.
- `cargo test -p eliot-process-executor --lib`: **30/30 pass**.
- `cargo test -p eliot-engine --lib verification::current::current_tests`:
  **3/3 pass** (includes a REAL `cargo nextest` process run in an isolated
  target dir and a REAL compiled probe binary executed for evidence bytes).
- `cargo fmt -p eliot-instrument-runner -p eliot-process-executor
  -p eliot-engine -- --check`: clean.
- `cargo clippy -p eliot-instrument-runner -p eliot-process-executor
  --all-targets`: zero new hits (4 pre-existing `expect_used` in executor
  test helpers, matching the original PR gate note).
- CBM navigation: `list_projects` reachable; indexed project
  `C-Development-Rust-projects-eliot-memory-os` is pinned at main
  `f37966c30` so `search_code` for `launch_verified` returns 0 matches —
  expected: the identity surface is new to this branch, confirmed absent on
  indexed main. No global repair attempted (per brief).

## Documentation routing receipt (full)

- Route receipt: `sha256:e5811876580d12360a6cc75925fa3212b4131f22c56cd3b385d3c9a60ed1383d`
- Read receipt: `sha256:e9e24b4857921fb12eb16d4d1475b152e1765566fc4e335592fa5477ce1619b8`
- Normative pair: `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`
- Matched routes: `generic-source`, `instrument-verification`,
  `workspace-governance`, `repository-root`.
- Required items: 59; verified bundle SHA-256:
  `e2b2172244f475a3508c85aa0becda9ff276a76882b035cb8504d39221ff5f56`
  (179138 bytes, 3856 lines; `.eliot/docs-read-bundle.md` /
  `.eliot/docs-read-receipt.json`, local-only, uncommitted).
- Required handles: A0.1, A0.2, A0.3, A0.4, A0.6, A2.3, A5.5, A10.4, A10.8,
  A14.6, A14.7, A14.8, APPENDIX-J, APPENDIX-P, I0.3, I0.4, I0.5, I0.13,
  I0.14, I2.17, I2.20, I2.21, I2.22, I2.23, I10.8.1–I10.8.19, I10.8, I10.9,
  I10.10, I16.17, I17, I18; plus files AGENTS.md(`e2508482…`), Cargo.toml
  (`55334d49…`), WORKFLOW.md(`ba111992…`), crates/AGENTS.md(`91459415…`),
  crates/instrument/AGENTS.md(`82a07e3e…`), ARCHITECTURE_CONTRACT.md
  (`d1e4c393…`), DEPENDENCY_POLICY.md(`a69844d6…`), READING_PROTOCOL.md
  (`fc2ac357…`), scripts/verify.ps1(`40deea22…`), workstreams/ACTIVE.toml
  (`2bf61c09…`) — full per-item SHA-256 in the read receipt JSON.
- Owning fragments read directly (router matched generic routes):
  `docs/architecture/I18-01-purpose-proof-scope-and-canonical-owner.md`
  (2292 B, sha256 `e2b2b680…3a32a`);
  `docs/architecture/I18-02-discriminator-first-repair.md`
  (1036 B, sha256 `df328516…e554bd`);
  `docs/architecture/I18-06-canonical-instrumentrunner-test-discovery-and-dev-fast.md`
  (2271 B, sha256 `d6317991…aa84c0b`);
  `docs/architecture/I18-08-instrument-plane-self-tests-and-fault-contracts.md`
  (1554 B, sha256 `d2e1b9db…13a2c`).
- Reading attestation: I opened the verified bundle and read all 59
  required items (lines 1–3856) before any mutation decision, plus the
  nearest AGENTS.md files, issue #1805 and PR #2236 bodies (gh read-only),
  and the four owning I18 fragments above. No mutation was then required
  (tree verified clean and green), so no receipt-scope expansion occurred.

## Acceptance vs #1805

- Governed result carries machine-derived path + digest, tool version, env
  projection identity, exact argv, candidate/worktree identity, raw handle:
  YES (`ExecutableObservation` 5 fields + `GovernedInstrumentResult`
  invocation/adapter/generation/argv/raw/execution).
- Replacing the executable between identical invocations yields different
  identities: YES (`observed_executable_replacement_changes_identity`,
  `replaced_executable_yields_different_identity`,
  `intent_binding_detects_replacement_and_argv_drift`,
  `current_run_rejects_swapped_executable_identity`).
- Result lacking executable/version identity cannot take PASS: YES
  (`result_without_executable_identity_cannot_pass`,
  `observation_without_version_is_never_complete`,
  `decoder_only_entry_rejects_any_executable`, engine missing-identity
  rejection).

## Gaps / non-goals (for root integration)

- Tool version and environment digest are caller-attested, not independently
  observed (documented in code; unknown version blocks PASS).
- Observation-instant hash race only narrowed (deny-write open); retained
  cross-launch pin remains the kernel lease (Kernel owner, untouched).
- Production composition-root wiring (machine resolution at launch inside
  eliotd/testd) belongs to Governor/eliotd owners; worker/Kernel joint
  proof belongs to Turing. This leaf made no API change, so no handoff is
  pending from this scope.
- No new approval flow created. Root owns fetch/push/PR/main actions.
