# T12-09 writer record — protected Dreamer launch + LeaseExact (Kernel part, Implements #702)

Writer: WRITER-T12-09 (ELIOT manager MGR01 lane).
Claim: MGR01-T12-09 covers exactly `bins/eliot-kernel/src/dreamer_dispatch_launch.rs` (NEW),
`bins/eliot-kernel/src/dispatch_launch.rs`, `bins/eliot-kernel/src/dreamer_job_dispatch.rs`.
No other source path was mutated. `bins/eliot-dreamer/*` was not touched (MGR02 lane).

## 1. Authority and routing

- Base commit: `01868163df39bfe06c377be7f21d7d14f74eaafb` (== `origin/main` at provisioning).
- Worktree: `C:/Development/Rust/projects/eliot-swarm/item-T12-09` (detached at base, clean at start).
- Branch: `work/702-dreamer-launch-leaseexact` (created fresh from base in the worktree).
- T12 slice: `T12.md` sections 3 (current code reality) and 5 (slice plan, T12-09 launch/claim
  acceptance) read in the worktree before mutation.
- Documentation routing (run from the repository root before any mutation):
  - command: `python scripts/docs_read.py read --path bins/eliot-kernel/src/dispatch_launch.rs
    --path bins/eliot-kernel/src/dreamer_job_dispatch.rs
    --path bins/eliot-kernel/src/dreamer_dispatch_launch.rs
    --topic "protected Dreamer launch LeaseExact"
    --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json`
  - result: `DOC_READ: PASS`
  - route receipt ID: `sha256:fe07d72989abc8ec286c17a7a6b0f0407198a19a081e24404bc7fe2e8ff7b199`
  - read receipt ID: `sha256:2b1710cd205fee08f0d4b3e58c5a9a6893f098469cb2814582912ce571519aa8`
  - matched routes: `generic-source`, `host-kernel`, `dreamer`
  - required handles: 39 required items (AGENTS.md, WORKFLOW.md, bins/AGENTS.md,
    ARCHITECTURE_CONTRACT.md, DEPENDENCY_POLICY.md, READING_PROTOCOL.md, ACTIVE.toml,
    fragments A0.1–A0.4, A0.6, A2.2, A2.3, A9, A10.4, A12.2, A13.2, A14.8, I0.3–I0.5,
    I0.13, I0.14, I1.1–I1.8, I2.17, I2.20, I5.5, I9, I14.14, I16.17, I18)
  - verified bundle SHA-256: `3fff61d5b887dee5b423076f2844d25cd8db3293aab594acf5fb787ca389b9f5`
  - normative pair key: `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`
- Reading attestation: the writer opened `.eliot/docs-read-bundle.md` (2688 lines) and read all
  39 required items before mutation. Load-bearing rules applied: I1.5 demand-start/on-demand
  Dreamer with idle drain and no-orphan lineage discipline; I1.8 exact ownership and call paths
  (Kernel verifies identity/authority/fence/idempotency, no second writer); I1.3 on-demand
  `eliot-dreamer.exe`; A12.2 session-derived (never self-declared) identity; A13.2 Kernel
  independence from Dreamer; ARCH-MOD-01/03 one owner, one proof; I2.17 write isolation;
  bins/AGENTS.md composition-root limits (no production `todo!`/`unimplemented!`, no Dreamer
  semantics in the binary — this slice adds launch/claim mechanics only, no model/source
  admission); AGENTS.md/WORKFLOW.md branch, hygiene, and audit-escalation rules.
- No fetch/pull was executed. Push at checkpoints is explicitly authorized by the owning
  manager task ("commit + push at checkpoints"); the push below is recorded as
  manager-authorized, not an uncoordinated network operation.

## 2. What was implemented (Kernel part only)

### 2.1 NEW `bins/eliot-kernel/src/dreamer_dispatch_launch.rs` (1179 lines)

Dreamer lineage + nonce + grant + reconcile material, mirroring Doctor/testd/native
`dispatched_material` and bound to the admitted Dreamer job, never to caller bytes:

- Canonical seam constants: `DREAMER_MODULE_ID` (`"eliot-dreamer"`, line 70),
  `DREAMER_MATERIAL_FILE_NAME` (`"eliot-dreamer.admitted-job.json"`, line 78),
  256 KiB bound, nonce shape bounds, `dreamer-dispatch` / `dreamer-launch` prefixes.
- `DreamerDispatchedEnvelope` (`deny_unknown_fields`): job/attempt/revision/scope-id/fence
  (ledger-bound) + live epoch/generation + deterministic nonce + shared `DispatchGrant`.
- `dreamer_material_bytes` (bounded serialize), `parse_dreamer_material_bytes` (closed parse),
  `validate_dreamer_material` (fail-closed against the live epoch: identity shapes, revision,
  fence-plus-generation agreement, exact-tuple epoch equality, nonce shape, grant through the
  exact broker constructors via `DispatchGrant::validate_for_child`).
- `mint_dreamer_nonce`: deterministic per (job, attempt, revision, live epoch, live
  generation, pinned executable digest); replay-stable, so replays rewrite byte-identical
  material and reconcile by the original identity.
- Process-local lineage table keyed by job identity: `reserve_dreamer_launch`
  (insert-or-replay-original, `ChangedTerms` on changed terms — no second worker),
  `retain_dreamer_launch_as`, `reconcile_dreamer_launch` (exact expectation plus
  same-authority live epoch; persisted nonce alone is never authority),
  `release_dreamer_launch` (grant-digest-gated), `dreamer_launch_permits_lease` (exact
  job/scope/revision/fence match, closed lineage denies).
- The concrete `ProcessRequest` is never serialized: the child derives its one-shot permit
  in-process from `grant` (#1460 broker pattern). No new transport/pipe/listener.
- Pure unit tests (3): nonce determinism/shape, material round-trip + forgery denial
  (widened wire, tampered nonce, foreign epoch, stale generation, foreign grant),
  lineage single-flight + reconcile/release.

### 2.2 `bins/eliot-kernel/src/dispatch_launch.rs` (+563/−~0)

Dreamer arm wired through the admitted contour (Doctor/testd/native behavior untouched):

- `#[path = "dreamer_dispatch_launch.rs"] pub(crate) mod dreamer_dispatch_launch;` (line 129):
  the new file is wired as a contour submodule so **no neighbouring composition root
  (`lib.rs`, `main.rs`) needed to change in this slice**; the manager-serialized `lib.rs`
  re-export + `main` binding injection is a tracked residual (see section 5).
- `DispatchedWorkerKind::Dreamer` (line 168) with `module_id` / `wire_id`
  (`eliot.kernel.dreamer-job`) / `material_file_name` / `nonce_prefix` /
  `operation_prefix` arms, reusing `dispatch_grant_for`, `spawn_ready_child`
  (empty argv, secret-free env, bounded limits, pinned path proof, Kernel-owned owner),
  and `write_material_file` unchanged for existing kinds.
- Arm entries (lines ~3580–4080): `DreamerLaunchMaterial` (caller keys + Kernel-loaded
  `QUEUED` response + composition-pinned child binding), `prepare_dreamer_launch`
  (K0-validate response, require `QUEUED`, require keys answered, live epoch/generation
  from `KernelService`, single-flight reserve with replay-original, grant mint,
  closed-loop child-contract proof + parse readback before staging, protected file write),
  `start_ready_dreamer_launch`, `launch_admitted_dreamer_attempt` (spawn settle →
  Launched/Unreconciled retention; failure reaps + releases), `reconcile_launched_dreamer_attempt`
  (reaps on converge). Refusals/skips never stage files or retain slots.

### 2.3 `bins/eliot-kernel/src/dreamer_job_dispatch.rs` (+562/−18)

Bound-worker `LeaseExact` arm on the K2 route (requester behavior untouched):

- `admit_dreamer_worker_lease` (line 219): derives `Worker` from the authenticated
  `eliot-dreamer` session module only; requires the Dreamer wire capability; admits
  **only** `LeaseExact` (launch/claim only — Renew/Start/Checkpoint/Publish/Status through
  this session fence even though K0 would permit some); requires presented role agreement,
  `permits()`, session/context fence equality, and an exact retained launch lineage
  (`dreamer_launch_permits_lease`). Any mismatch fences **before any store call**.
- `admit_dreamer_envelope` (line 261) routes by session module; `execute_dreamer_request`
  accepts the Dreamer module alongside `eliotd`. No spawn on either path.
- `FakeDreamerLedger` gains an exact `LeaseExact` arm (single lease per job; deterministic
  `already leased` / `selector mismatch` refusals). Existing tests asserting zero store
  calls on denied paths are unaffected (fence precedes the store).
- Focused test `managed_child_claims_exact_queued_job_forged_replay_denied` (line 1748):
  real managed-child claim of the exact queued job; forged job/scope/revision, foreign
  module, and off-arm operation all fence with zero new store calls; exact replay gets a
  typed store refusal (no second lease) plus a byte-identical launch replay (no second
  worker); reconcile closes the slot and reaps the file; stale release never frees;
  executor-less launch fails closed with no orphan file or slot.

## 3. Gates (scoped)

All with `CARGO_TARGET_DIR=C:/Development/Rust/projects/eliot-swarm/MGR01-target-2` and `--locked`.
Logs under `items/T12-09/`.

1. `cargo clippy --locked -p eliot-kernel --all-targets`: exit 0; **zero warnings in the
   three touched files** (verified via `--message-format short` grep; see
   `items/T12-09/clippy.log`). Staged production entry points carry the established
   `#[allow(dead_code, reason = "production call-in lands with the manager-serialized lib.rs
   re-export; tests drive it meanwhile")]` precedent (same as `trigger_admitted_doctor_launch`).
2. `cargo test --locked -p eliot-kernel`: green — 157 passed / 0 failed (lib), 10 passed
   (bin), 0 doc-tests; see `items/T12-09/test.log`. Includes the focused T12-09 test and
   3 new unit tests; all 7 pre-existing K2 tests and all dispatch-contour tests still pass.
3. Public API change (`DispatchedWorkerKind::Dreamer` variant on the root-re-exported enum):
   users enumerated via `git grep` — in-crate contour only, `lib.rs` re-export list (types,
   not variants; no change needed), doc-only mentions in `bins/eliot-testd`; no
   `dispatch_launch::` users outside `bins/eliot-kernel`. Direct dependent
   `eliot-r13-harness` (uses only `SERVICE_NAME`/`KernelComposition`/`KernelConfig`):
   `cargo check --locked -p eliot-r13-harness` green.
4. `cargo fmt --check -p eliot-kernel`: all added lines clean. The remaining hunks in the
   touched files are **pre-existing rustfmt-version drift, verified present at base**
   (`git show HEAD:…` + `rustfmt --edition 2024 --check`: 20 hunks in
   `dreamer_job_dispatch.rs`, 5 in `dispatch_launch.rs` at base) and were deliberately left
   untouched per minimal-scope discipline. The new file is fully fmt-clean.

## 4. Diff stat

```text
 bins/eliot-kernel/src/dispatch_launch.rs      | 563 ++++++++++++++++++++++++-
 bins/eliot-kernel/src/dreamer_job_dispatch.rs | 580 +++++++++++++++++++++++++-
 bins/eliot-kernel/src/dreamer_dispatch_launch.rs | NEW, 1179 lines
 2 files changed, 1118 insertions(+), 25 deletions(-)  (+1 new file)
```

Full stat in `items/T12-09/diffstat.txt`; clippy/test/fmt evidence in
`items/T12-09/clippy.log`, `items/T12-09/test.log`, `items/T12-09/fmt-mine.log`.

## 5. MGR02 handoff spec — `bins/eliot-dreamer/src/kernel_port.rs` + `lib.rs` registration

Out-of-lane for this writer; MGR02 owns `bins/eliot-dreamer/*`. Exact contract to implement:

1. NEW `bins/eliot-dreamer/src/kernel_port.rs` — child-side reader + local dispatch
   authority (mirror `bins/eliot-doctor/src/dispatched_material.rs:94,257-286` and
   `bins/eliot-user-broker/src/lib.rs:146-193` constructors; no new transport):
   - Locator: `<current_exe_dir>/eliot-dreamer.admitted-job.json`
     (exact `DREAMER_MATERIAL_FILE_NAME`, never argv/stdin/env).
   - Closed parse with `deny_unknown_fields` over exactly
     `{job_id, attempt_id, revision, scope_id, fence, epoch, generation, nonce, grant}`
     (shapes in `dreamer_dispatch_launch.rs: DreamerDispatchedEnvelope`); bound
     256 KiB; consume-once (best-effort remove after validated read; missing file =
     `DenyNoPresentedAttempt`, never a drive).
   - Validation order (fail-closed to exit 78, no effect): nonce shape
     (`DREAMER_NONCE_MIN/MAX_LEN`, `[A-Za-z0-9-_.]`); live-epoch exact-tuple equality for
     `epoch` AND `grant.authority_epoch`; `generation` non-zero, equal to the fence
     generation and to `grant.fence_generation`; grant through `FencingToken::new` +
     `ActionLeaseRef::new` with well-formed digest/expiry; revision non-zero.
   - Local authority: build the one-shot permit **in-process** from the validated grant
     (`DispatchPermitAuthority::activate`, then `FencingToken::new` + `PermitIssuance::new`
     + `DispatchValidationContext::new` + `ProcessRequest::new` through
     `WindowsProcessExecutor::new(authority)`); never deserialize `ProcessRequest`.
   - Claim: bind the `eliot-dreamer` session over the pipe-authenticated peer, then
     `LeaseExact` with the exact retained values (`job_id`, `selector.scope_id`,
     `selector.expected_revision`, `selector.expected_fence`); afterwards `Start`
     under the issued lease. `LeaseNext` must not be used by the child.
2. `bins/eliot-dreamer/src/lib.rs` — replace the `dreamer.claim` refusal
   (`AuthenticatedKernelJobPort::connect`, lines 130–148) with the real
   session-bound claim path consuming (1); keep failing closed (exit 78) until the
   handoff validates.
3. `bins/eliot-dreamer/src/main.rs` — replace the unconditional exit-78 shutdown
   (lines 17–25) with the one-orientation driver only after (1)–(2) land (T12-10).
4. MGR02 acceptance: managed child claims the exact queued job; tampered/foreign/replayed
   material or a second concurrent claimant starts no second worker; termination observed
   with no orphan file or slot (reconcile + release paths above).
5. Kernel-side residuals awaiting manager serialization (NOT MGR02): `lib.rs`
   `dispatch_launch` re-export of the Dreamer arm names + `main` Host-injected
   `DreamerChildBinding` composition (installed executable digest) + optional dedicated
   front-door Dreamer session bind (least-privilege capability intersection; the K2 arm
   already enforces module + capability + lineage without it).

## 6. Residuals and non-goals

- No `main`/`lib.rs`/front-door wiring in this slice (manager-serialized; see section 5.5).
- No Store/Governor/model/source changes; no K0/S0/S1/S2/K1 changes; Doctor/testd/native
  paths byte-identical in behavior (all their tests green).
- Cross-kind identity note: the Dreamer lineage table is keyed by Dreamer job identity and
  does not consult the Doctor/testd/native launch table; a literal cross-family identity
  collision would still be fenced at claim time by the exact scope/fence/executable match,
  but a shared cross-kind reservation table is deferred to the production composition turn
  if the manager wants it.
- Evidence kept out of git history per hygiene: `.eliot/` bundles/receipts are untracked
  and uncommitted; only `items/T12-09/` evidence rides this branch for review.

## 7. Verification log

- Branch: `work/702-dreamer-launch-leaseexact`
- Base SHA: `01868163df39bfe06c377be7f21d7d14f74eaafb`
- Commit SHA: `adacaece6efcfa1a2352b5f0a5d143729720fcbc` (pushed to
  `origin/work/702-dreamer-launch-leaseexact`; this record's SHA line added in the
  follow-up evidence commit).
- Commands (all `--locked`, target dir `C:/Development/Rust/projects/eliot-swarm/MGR01-target-2`):
  - `cargo clippy --locked -p eliot-kernel --all-targets` → exit 0, zero warnings in
    the three files (`items/T12-09/clippy.log`).
  - `cargo test --locked -p eliot-kernel` → green (`items/T12-09/test.log`).
  - `cargo check --locked -p eliot-r13-harness` → green (direct dependent).
  - `cargo fmt --check -p eliot-kernel` → added lines clean; rest is base drift.
- Skipped/failed/simulated/unavailable checks: none — every scoped gate executed for real.
  No full-workspace suite (change closure is `eliot-kernel` + one dependent check).
