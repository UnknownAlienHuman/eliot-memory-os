# PR #2253 — 1796: typed, complete, pre-stage contract rejection (verify + harden)

Implements issue #1796 (I6.8): typed `ContractError` / `AdmissionRejection` records with every required field, multi-defect accumulation in one response, `stage_state: none`, `ordering_sequence_assigned: false`, `write_mutation_status: NOT_ATTEMPTED` with no `write_intent_id` consumption, canonical-bytes-first retry identity (same-hash replay, `corrected_from_operation_id` lineage, `IDENTITY_CONFLICT` on key reuse with changed bytes), and a safe Observation-Candidate capture path for semantic ambiguity.

Verify lane hardened both `validate()` mirrors (blank identity fields, hex hash, defect-code hygiene) with no public-shape change.

## Evidence

- `cargo check --offline -p eliot-canonical --lib` → pass (merged tree, final SHA `0ab26c31`, main `52941612` merged cleanly).
- `cargo check --offline -p eliot-kernel-service --lib` → pass; composition re-exports intact post-merge.
- Prior candidate suite evidence: `eliot-canonical` 2/2 pass; `eliot-kernel-service` 209 pass / 0 fail; `eliot-canonical` clippy `--all-targets -- -D warnings` clean; kernel-service clippy failures are known baseline lints in untouched files only (see delivery note).
- Docs: `docs_read.py` PASS, receipt `sha256:1ef904f8…`, bundle `cfbf8f23…`, 40 required items read plus governing I6.8 / I6.6 / I5.5; full attestation in `2253-final-delivery.md`.

## Residuals for follow-up

- No production admission path calls the new journal/gate yet (composable boundary + proofs delivered; live wiring is a separate slice with the #1743 owner).
- Fenced `kernel-service/src/lib.rs` untouched; no hunk required (no new public types).

No closure claimed here — root owns merge and issue disposition.
