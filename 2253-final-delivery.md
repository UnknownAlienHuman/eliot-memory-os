# 2253 final delivery — issue #1796 verify + harden (candidate branch)

- Branch: `codex/b-2253-contract-rejection-verify` (verify-lane name per Line-B brief; integration target remains PR #2253 / `work/1796-contract-rejection` — root owns fast-forward, PR, merge).
- Final SHA: `0ab26c31` — merge of `origin/main` (`52941612`, "977: complete Bridge output and diagnostic profile limits") into prior candidate `d0a8287a`, clean with no conflicts (merge performed by root).
- Prior candidate base: `c19a0390` (PR #2253 head, "1796: typed pre-stage contract rejection with retry identity (go22)").

## Changed by this verify lane (owned files only)

- `crates/governor/eliot-canonical/src/contract_rejection.rs` (+7/−1): `AdmissionRejection::validate` enforces lowercase-hex `canonical_request_hash`, not length-only.
- `crates/kernel/eliot-kernel-service/src/contract_rejection_gate.rs` (+37/−1): `PreStageRejection::validate` rejects blank `proposed_operation_id` / `idempotency_key`, non-hex hash, blank/control-char `defect_codes`, blank retry-rule/next-action — mirroring the Governor owner.
- Fenced `crates/kernel/eliot-kernel-service/src/lib.rs` NOT touched (Line A owns the PR2310 write-coordinator slice). No new public types were introduced, so no lib.rs hunk is required from this lane.

## Documentation routing (current merged tree)

- `python scripts/docs_read.py read --path crates/governor/eliot-canonical --path crates/kernel/eliot-kernel-service --topic "typed contract rejection pre-stage"` → `DOC_READ: PASS`.
- Read receipt: `sha256:1ef904f87621a1661397cbdae77265a29914eb1cbb418482fa7fc5bfdfe510bb`; route: `sha256:054867593729619f1e553446e521bd051756f035358b228e1e427cfa280568c1`; matched routes: `generic-source`, `host-kernel`; required items: 40; bundle SHA-256: `cfbf8f23894dff634cfc8f5c7c7627e0e86d1a719a5f5b0e7510b727e9fb4a5c`; normative pair: `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`.
- Reading attestation: every required bundle item was opened and read (bundle lines 1–end, all 40 required files/fragments), plus the issue-named governing docs `docs/architecture/I06-08-contract-rejection.md` and `docs/architecture/I06-06-action-contract.md` read directly (the route did not include them), plus in-bundle `I05-05-write-envelope.md`; nearest `AGENTS.md` (root, `crates/governor`, `crates/kernel`) read before mutation. Receipts alone were not treated as reading. (Prior candidate run: receipt `sha256:0abeafbf…`, bundle `0f1e06b4…` — superseded by the above on the merged tree.)
- CBM: indexed project for this tree unavailable via direct CLI (`project not found`, 17 unrelated projects listed) — disclosed; all cross-crate APIs verified by exact grep (`eliot-store-api::canonical_request_hash` / `verify_canonical_request_hash` / `CanonicalRequestView::from_apply`, `eliot-contracts::{OperationId, sha256_hex, contract_identity}`, `eliot-store-api::effect_is_at_most`). Kernel-service has no `eliot-canonical` dependency, so the mirrored Kernel constants/types are architecturally required, not duplication.

## Actual checks

Current merged tree (final SHA), isolated target, `--offline`:

- `cargo check --offline -p eliot-canonical --lib` → exit 0.
- `cargo check --offline -p eliot-kernel-service --lib` → exit 0.
- Composition exports confirmed present post-merge: canonical `pub mod contract_rejection` + re-exports (`ContractAdmissionJournal`, …); kernel `mod contract_rejection_gate` + re-exports (`pre_stage_check`, `PreStageIdentityCache`, …). Merge did not touch either rejection file; no new failure appeared, so no repair beyond the prior candidate hardenings was needed.

Prior candidate evidence (labelled prior; NOT rerun on the merged tree per root order):

- `cargo test --offline -p eliot-canonical` → 2 passed, 0 failed (matches PR-body claim 2/2).
- `cargo test --offline -p eliot-kernel-service` → 209 passed, 0 failed (PR body claimed 210/210 — off by one, no old-worker logs to cross-check; no failure hidden).
- `cargo fmt --check`: owned files clean; pre-existing diffs in untouched `doctor.rs`, `host_request_binding.rs`, `lifecycle.rs`, `tests/commit_recovery_unknown_commit.rs`.
- `cargo clippy -p eliot-canonical --all-targets --no-deps -- -D warnings` → clean. Kernel-service `--all-targets -- -D warnings` fails only on known baseline lints in untouched files (`protocol/native_worker_claim.rs`, `protocol.rs`, `doctor.rs`, `store_gateway.rs`, `store_write_reservation_tests.rs` — newer-clippy lints predating the PR per diffstat); zero mentions of `contract_rejection_gate`.

## Explicit residual: absent production admission callers

No production path calls `ContractAdmissionJournal::admit` or `pre_stage_check` yet — the PR delivers the typed boundary, retry-identity journals, and unit proofs as composable units; live wiring into Governor/Kernel admission is a follow-up slice needing files outside this lane (and #1743-owner coordination). This is reported, not implemented.

No premature closure: this delivery does not close issue #1796 and carries no `Closes` claim. Root owns push, PR update, merge, and closure.
