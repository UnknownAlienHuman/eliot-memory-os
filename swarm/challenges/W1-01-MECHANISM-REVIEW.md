# W1-01 Mechanism Review

Status: `MECHANISM_CHANGED_ONE_SHOT_AUTHORIZED_IN_PROGRESS`

Authorization history: prior `AWAITING_USER_DECISION`; v1.3 authorizes exactly
one mechanism-changed W1-01 attempt (attempt 3), with no admitted terminal
attempt and an evidence-only wrapper.

## Stable findings

The v2 inventory substrate is independently supported:

- Cargo metadata and the inventory contain 125 workspace packages;
- the source universe is the sorted union of Git cached Rust files and
  nonignored untracked Rust files;
- `bins/eliot/src/bootstrap_draft.rs` and
  `bins/eliot/tests/bootstrap_brief.rs` are both included;
- the `eliot` package has 69 tests, matching an independent
  `cargo test -p eliot --all-targets --locked -- --list` census;
- paths are repository-relative and the generated inventory has no
  `HEAD`/worktree-state dependency.

These facts may be reused. They do not accept the W1-01 result envelope.

## Two rejected mechanisms

1. v1 omitted nonignored untracked Rust, double-counted `tokio::test`, carried
   stale bootstrap measurements, and accepted broad metadata tampering.
2. v2 corrected the inventory, but its normal verifier still accepts changes
   to `schema_version`, `implemented`, `executed_evidence`, nested external
   review identity, artifact removal, absolute artifact paths, top-level field
   addition, and removal of the entire external-review block. Its
   `VERIFIED_LOCAL` disposition also does not satisfy the recovery program's
   required `TerminalWorkUpdate` disposition vocabulary and field set.

## Decision options

### A. Authorize a third, mechanism-changed attempt

Keep the accepted v2 inventory algorithm. Replace the result mechanism with a
deterministically generated, content-bound `TerminalWorkUpdate` envelope using
only the permitted disposition vocabulary. The independent verifier must
enforce exact property sets, exact artifact paths/digests, all nested evidence
fields, repository-relative path safety, add/remove/tamper rejection for every
field family, and byte reproduction before and after a future commit.

### B. Stop W1-01 at challenged inventory evidence

Retain the correct inventory as `EVIDENCE_ONLY`, mark the work item
`challenged`, and keep W1 and cutover blocked. No result-envelope acceptance is
claimed.

The one-shot authorization is now in progress. Any new failure requires a new
Mechanism Review and decision.
