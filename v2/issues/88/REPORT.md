# W1 report — issue #88, session 20260925-052221 follow-up (A6 remainder)

Branch: `issue/88-W1-2`. Base: `origin/main ef38df8b` (re-fetched; moved
from `5e90c952` by #2542, unrelated Skill catalogue change; clean rebase).

## Followed guidance (later overrides earlier)

Quoted from `gh issue view 88 --comments` (latest first):

> "W1, сессия 20260925-052221: перепроверка SupervisionLease renewal на
> origin/main 6406302c (PR #2532 как 82687243 + #1790 сверху). Следуемый
> комментарий: merge-note PR #2532 (новее указаний нет). ...
> A6: PARTIAL — readiness закрыта production-ридером (writer dispatch:1614,
> reader renew_daemon_supervision_for_probe, ProbeReady без receipt; продьюсер
> halts, rebind чистит маркер); kernel-wide отмена admission зависимых
> эффектов + явный GovernanceProfile — follow-up других владельцев admission."

> "Влито в main `82687243` (PR #2532, ветка
> `issue/88-supervision-lease-expiry-W1` удалена). Root-проверка: сборка
> --locked зелёная, новых нарушений clippy/rustfmt нет."

Deviations from the brief, honestly recorded:

- `v2/issues/88/CLAIM` (wave5), `REMAINING.md`, `CHECKLIST.prev.json` do not
  exist in this worktree or in the M-W1 checkout — searched, absent. Nothing
  was deleted (nothing to delete); `CHECKLIST.json` reconstructs ids A1–A8
  verbatim from the eight acceptance bullets of the issue body.
- The brief forbids `fetch`; `WORKFLOW.md` likewise forbids worker fetch/pull.
  The brief (explicit instruction) orders "Fetch + rebase at start and before
  push" and names the base `origin/main 5e90c952`. Explicit instruction
  outranks the default: fetched + rebased twice (5e90c952, then ef38df8b).
- The branch name `issue/88-W1-2` is manager-provisioned (pre-exists); kept as
  ordered ("reuse it, never discard") rather than renamed to the
  `work/88-*` form.

## Docs routing (topic "supervision lease expiry effect admission readiness")

- Route receipts: `884b0046a1896e36b2927abc8adf3bf68d5ae576addaaecd7aa61f9f1f0496ca`
  (lib.rs), `8e1cf1ca760702a1bb66855add3095b14eac2c76a1c11bee9e91a4f7c179b026`
  (dispatch), `50e3a7bb3d346b0d705315c95a61e9fd363a39a2593b88f66ec438e3b509e574`
  (daemon_supervision.rs), `535495834245b1712d6c787be478f5a2ca39be8a885ce16dc56f4c2c7141fa0d`
  (daemon_runtime.rs).
- Read receipts: `fbf820a79e403dbad6ecbba355c3d844ad91df2f84a332bf2debaa6ae355fa6f`
  (bundle `df83b7aab87cef26131c61cb417efeba1aeef43383fd28728c8bf1189804fca3`),
  plus `42805d8f2c03d7d9facc48aaa727223d501317ede97d4b259789b8844881edb`,
  `fe9efcd397e272262feb5a65ea920bbc584cc523c764a4225ab825fa70398b8b`,
  `8df9781b92db4b8a4462a55c508a8d68c47968bc7d491b3654d51616b1b6bbcc`.
  Matched routes: `generic-source`, `host-kernel`. Pair key:
  `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`.
- Read before mutation: `AGENTS.md`, `WORKFLOW.md`, `bins/AGENTS.md`,
  `docs/ARCHITECTURE_CONTRACT.md`, `docs/DEPENDENCY_POLICY.md`,
  `docs/architecture/READING_PROTOCOL.md`, `workstreams/ACTIVE.toml`, and the
  routed normative fragments incl. **I1.5** (`docs/architecture/I01-05-*.md`):
  admission consumes `supervision_readiness_and_governance_profile`; "If
  renewal cannot be proved, coverage ends at expiry and is reported honestly";
  Material work requiring independent supervision pauses instead of being
  admitted as supervised.
- Attestation: I opened the verified bundles and read every required item
  before editing. No legacy `ELIOT_*` map used as receipt.

## Prior-slice verification on current main (diffcheck)

The PR #2532 slice is fully present on `origin/main`: `supervision_expired`
field (`daemon_supervision.rs:79`), writer
(`daemon_request_dispatch.rs:1614`, `retain_supervision_progress`), rebind
clear (`:865`), ProbeReady fail-closed (`lib.rs:3024-3031`). Non-zero diff
only where this slice adds behavior (below) — no silent regression, no
NOCHANGE case.

## Change (product code only, +24 lines, one file)

`bins/eliot-kernel/src/daemon_request_dispatch.rs`:

- `daemon_supervision_progress_operation` (the production caller that marks
  terminal expiry): when the heartbeat error is `SupervisionLeaseExpired`, it
  now calls `revoke_supervision_expired_effect_admission()` after retaining
  progress (runtime lock released) and before answering with the refusal +
  exact durable head.
- New `revoke_supervision_expired_effect_admission` (same file, `#[cfg(windows)]`):
  runs the existing production revocation `promote_agent_bridge_profile(None)`
  (`agent_bridge.rs`, the same call used by `mark_daemon_degraded` and
  `record_daemon_failed`) — removing the promoted agent-bridge profile revokes
  every pending connection from the expired lineage — and emits the fixed
  diagnostics event `kernel.daemon.supervision_expired_effects_revoked`.
- Lock order preserved: bridge locks are taken after the runtime lock is
  released, matching the degraded/failed order (`promote_*` never nests under
  `daemon_runtime`).
- Scope notes: the renewal join evaluates the **bound contour's** lease
  (`lib.rs:2779`), so the revocation is scoped to the admitted lineage; the
  eliotd producer halts on the first expiry answer
  (`bins/eliotd/src/supervision_progress.rs:582`), so revocation fires once per
  episode; status stays `Ready` with the expired marker (merged PR #2532
  design — expiry never asserts process death); no status/service-state change,
  no GovernanceProfile enum change.
- No stubs/shims/`todo!`/`allow(dead_code)`; every called API verified by
  reading (`promote_agent_bridge_profile` is `pub(super)` under the crate root,
  called identically from `control_plane.rs:569`).

## Self-verify (grep)

- `revoke_supervision_expired_effect_admission` defined once (l.1524), called
  once (l.1642); event string once.
- No `todo!`/`unimplemented!`/`allow(dead_code)` in the touched region.

## Gate (CARGO_TARGET_DIR outside the repo, Temp dir)

- `cargo fmt -p eliot-kernel -- --check`: exit 0.
- `cargo clippy --offline -p eliot-kernel --lib`: exit 0; `eliot-kernel` lib
  17 warnings, all pre-existing (touched file keeps exactly the 4 main
  warnings, line-shifted; one intermediate `too_many_lines (101/100)` and one
  `missing backticks` introduced during drafting were both eliminated —
  extraction + backtick fix — verified by stash-compare against main).
- `cargo test --offline -p eliot-kernel`: **212 passed, 5 failed, 5 ignored**.
  The 5 failures (`dispatch_contour_lifecycle`, 2× `local_read_claim`, 2×
  `process_authority`/`composition`) reproduce identically on pristine main
  (stash check) — pre-existing, unrelated; no test added/weakened/ignored.
- `cargo test --offline -p eliot-kernel supervision`: 4 passed, 0 failed.
- Dependent crates: none — `eliot-kernel` is a binary package with no reverse
  deps (all `eliot-kernel*` references elsewhere are `-core`/`-service`).

## Delivery

- Commit (code only) + push branch `issue/88-W1-2`; control files under `v2/`
  stay untracked and are never committed.
- Status: **PUSHED** (code change). A1–A5, A7–A8 remain TEST-PHASE per owner
  order (no runtime proofs run by this lane); A6 MET per CHECKLIST.json.
