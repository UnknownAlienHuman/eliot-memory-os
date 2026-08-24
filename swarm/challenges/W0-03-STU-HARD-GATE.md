# W0-03 ContractChallenge: size-only STU failure

Status: `CONTRACT_CHALLENGE_ACCEPTED`

Authority boundary:

- `docs/tasks/RECOVERY_PROGRAM_v1.md` is the user-supplied recovery program and evidence plan.
- The canonical authority remains the external Architecture/Implementation pair identified by `docs/normative/projection-manifest.tsv`.
- This challenge changes only the conflicting enforcement mechanism; it does not waive workspace CI coverage or dependency-policy verification.

Conflict:

- The recovery program proposes a per-file STU warning at 45,000 and hard failure at 100,000.
- Implementation I2.16 defines `STU = ceil(UTF-8 bytes / 3)` as a conservative planning fallback when an exact route tokenizer is unavailable.
- I2.16 states that crossing a numeric band alone records profile evidence and does not fail or split a crate.
- I17.15 states that I2.16 planning bands alone never create a refusal.
- I18.38 treats the profiles as route/task-family hypotheses, not universal module limits.

Root decision:

1. CI and the local verifier SHALL measure and report per-file STU using the documented fallback formula.
2. The 45,000 and 100,000 recovery-program values MAY be preserved as provisional observation labels so that the requested inventory is reproducible.
3. An STU observation alone SHALL NOT produce a non-zero exit code, refuse admission, require a split, or claim a defect.
4. A future blocking rule requires a separate, evidence-backed contract tied to a qualified route/task profile and a causal defect beyond size.
5. Workspace `check`/`clippy`/tests and pinned `cargo-deny` remain blocking gates because they validate behavior and policy rather than imposing a size-only refusal.

Acceptance evidence:

- Two independent OpenCode Ox Alpha reviews must agree on the I2.16 conflict.
- The measurement implementation must be deterministic, native PowerShell/Rust, and free of Python or Node hot-path dependencies.
- CI and local verification must share the same measurement semantics.
- Generated observations must identify their provisional, non-authoritative status.

This challenge is not a waiver and is not completion authority.
