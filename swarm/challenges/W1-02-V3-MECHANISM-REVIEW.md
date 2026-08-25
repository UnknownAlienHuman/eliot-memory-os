# W1-02 v3 Mechanism Review

Status: `MECHANISM_CHANGED_ONE_SHOT_AUTHORIZED_IN_PROGRESS`

Authorization history: prior `THIRD_ATTEMPT_REJECTED_AWAITING_USER_DECISION`;
the rejected nested-property finding remains historical and is addressed by
the one-shot exact-family verifier below.

## Stable findings

Independent review supports the current census and content-bound provenance:

- the source universe is 544 Git-cached plus 2 nonignored-untracked Rust
  files, including both bootstrap sources;
- the 546 source paths, per-file digests, aggregate source digest, normative
  pair digest, and content digest independently match;
- the inventory contains 744 rows: 113 `Designed`, 119 `Unimplemented`, and
  512 `Unknown`;
- stable IDs, ordering, source digests, repository-relative path safety, and
  the 737/714 unknown-anchor counts independently match;
- the exact four-field Rust `TerminalWorkUpdate` is kept separate from the
  richer challenged structured evidence, and neither generated artifact binds
  itself to `HEAD`, worktree state, or timestamps.

These facts remain reusable evidence. They do not accept the W1-02 result
envelope.

## Rejected third attempt

The normal oracle does not enforce the exact property set of each
`provenance.source_files[]` element. Adding an extra property such as
`"extra": "tampered"` to one element is accepted with exit code zero because
the verifier checks only the element count, `path`, and `sha256` values. The
48-category self-test mutates source-entry paths and digests but does not test
an added source-entry property.

Therefore a correct CSV and source digest can still be wrapped in a result
whose nested provenance schema was altered without rejection. The claimed
complete result-envelope oracle is false.

## Decision options

Option A authorizes a fourth, mechanism-changed attempt that retains the
independently supported census and adds exact property-set validation plus
add/remove/tamper fixtures for every repeated nested object family. Canonical
byte reproduction must continue to cover both the CSV and result.

Option B preserves the current census as challenged `EVIDENCE_ONLY` material,
accepts no W1-02 result, and keeps W1/W2 blocked.

The one-shot fourth attempt is authorized and in progress. Any new failure
requires a new Mechanism Review and decision.
