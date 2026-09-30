# Report: issue #1730 (MC1 slice) — Governor resume-owner join

Branch `feat/1730-continuity-checkpoint-MC1`, rebased onto `origin/main`
(`0738d7ef`). HEAD `4fc8bd1e8`.

## What changed

New module `crates/governor/eliot-coordination/src/handoff_resume.rs`
(+84) with `resume_from_retained_handoff`, re-exported from `lib.rs`:
the resume-side symmetric join to `capture_handoff_checkpoint`. It
re-checks the complete retained payload with its existing validator,
corroborates the durable capture against the live owner event stream
(`Checkpointed` + owner digest must read back), and runs the
recovery-handoff owners in order. Reference-only resumes, binding
mismatches, and unlanded captures fail closed. No IO, no minted
authority, no worker launch, no store reads; authority observations stay
caller-supplied; rebuild stays with the external Context caller.

## Gates (observed, post-rebase)

- `clippy -p eliot-coordination --lib --no-deps -- -D warnings`: 1 error,
  identical to the `main` baseline (`work_lease_issuance.rs:271`) — 0 new.
- `rustfmt --check` on both touched files: clean.
- `docs_read --changed-from origin/main`: PASS, 24 required items.

## Docs attestation

Route `sha256:c80aadb5…`, read receipt `sha256:c4acd177…`, bundle
`ad21e6a9…`, route generic-source. Manager read the verified bundle
(including `crates/governor/AGENTS.md`) and the issue-mandated shards
I12.17, I7.15, I12.13, I12.16 directly. Conformant: Governor semantic
coordination without IO/authority minting, resume revalidation with
explicit loss handling, continuity through the existing causal-link
machinery, pure compiler untouched. Full receipt in
`docs-read-receipt.json`.

## Open (needs root)

No production runtime caller wires the join yet (verified: definition +
re-export only). The caller was expected via #1742, which is parked —
root decision needed on unparking or reassigning the stitch. Remaining
implementation-order steps (payload, capture boundary, provider gaps,
rebuild caller, recovery finish) are follow-up slices.
