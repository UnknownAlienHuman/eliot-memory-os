# Recovery swarm bootstrap state

This directory is the Git-backed `BootstrapDraft` transport for
`RECOVERY_PROGRAM_v1.md`. It is evidence and coordination state, never runtime
authority.

## Frozen baseline

- Recovery program SHA-256:
  `CAA8E6B02B6D0300F36B3776890E64772F7968C116006DAB01174D2BAF529EA7`.
- Source revision: `d40a0a1e03f8a5afabffb669f4a6acfb6ea848f0` on `main`.
- Architecture: `4.5-draft`, SHA-256
  `58E71A2BDB10925C63D85A708ED768AEE8617BED0FB52EB044478EC20AB439D8`.
- Implementation: `0.29-draft`, SHA-256
  `C216FB7F6FDBC62D108C748BE6F61CA7EF9E5D24E5BB13AF2677C31A58460C0B`.
- Bootstrap contract revision: `recovery-w0-w1-r1-d40a0a1`.

The bootstrap contract remains historical evidence for the original admission
attempt. The current recovery source revision is
`1122e21b081a82a6a335c53f018e9ae60846cdd5`; current W1 generators bind that
HEAD plus explicit dirty-worktree/source digests. W1-06 falsification triggered
the local task-program amendment v1.2 in
`decisions/W1-06-PROGRAM-REVISION-v1.2.md`; it does not rewrite the original
bootstrap evidence.

The canonical normative files remain in
`C:\Development\Rust\docs\ELIOT Arhitecture`. `docs/normative/` is a pinned,
CI-verifiable projection only.

## Current execution boundary

Only W0 and read-only W1 are open. W2 is blocked until the W0 gate passes.
Mutating work uses one writer per declared path scope. External OpenCode lanes
are read-only until an integration owner assigns a worktree and path claim.

The active external audit pool uses five logical OpenCode Go Ox Alpha lanes and
two independent OpenRouter Ox Alpha lanes. Provider/model identities are
`opencode-go/ox-alpha-free` and `openrouter/stealth/ox-alpha`. A logical lane is
not recorded as running until a live OpenCode session returns tool or text
events.

## Admission state

No `AdmittedSwarmPlan` is claimed yet. The current Rust type is intentionally
non-deserializable and cannot be publicly constructed without a verified
admission receipt. Until a real provider can issue and verify that receipt, the
plan remains an inert proposal; see
`challenges/BOOTSTRAP-PLAN-ADMISSION.md`.

Gate evidence lives under `gates/`. Structured external results are admitted
under `results/` only after model/provider identity, source revision, normative
references, and read-only cleanliness are checked.
