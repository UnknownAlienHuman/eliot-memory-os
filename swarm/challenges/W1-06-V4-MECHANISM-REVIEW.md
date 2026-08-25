# W1-06 v4 Mechanism Review

Status: `THIRD_CORRECTION_AUTHORIZED_IN_PROGRESS`

Authorization: exactly one bounded mechanism correction authorized by
`swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md`; evidence remains
`EVIDENCE_ONLY`, C3 remains `UNKNOWN`, and the W2 boundary is unchanged.

## Stable findings

Independent review supports the bounded premise values and the majority of the
v4 mechanism:

- exact filtered source universe currently contains 679 repository-relative
  paths and includes both bootstrap files;
- canonical Cargo metadata digest independently matches;
- A1 is `TRUE` only for the narrow direct-Cargo predicate;
- A2 is `FALSE` with the heuristic current census 331 total, 82 ignored, 249
  unignored;
- A3 is `FALSE`; C1/C2 are statically `TRUE`; C3 remains runtime `UNKNOWN`;
  C4 is statically `TRUE` without a `commit_canonical` runtime claim;
- 23 inventory, 34 result, and 16 nested add/remove independent mutations were
  all rejected;
- authority remains `EVIDENCE_ONLY` and no TerminalWorkUpdate/completion claim
  is made.

These values remain evidence; they do not accept W1-06.

## Two rejected hardening submissions

1. The first v3 submission did not bind every source byte used by the E2E
   parser and validated only selected result fields.
2. The corrected v4 binds its declared 679-path universe and full semantic
   result, but C2 reads
   `scripts/build-eliot-windows-x64-release.ps1` through a witness without
   including that file in the declared input paths/aggregate `inputs_digest`.
   The result is also compared as a semantic object rather than an exact
   canonical raw-byte artifact.

## Decision options

The authorized correction is in progress: bind the release-builder witness in
the declared input universe, persist exact input path-plus-byte bindings, and
enforce canonical raw-byte equality for inventory and result artifacts. Prior
rejection history remains preserved above.

Option A authorizes a third bounded correction: include every witness-read
file in the exact input universe/aggregate digest, make the existing generator
produce/check canonical bytes for both inventory and result, and rerun the same
independent mutation suite without changing premise meanings.

Option B preserves v4 as challenged `EVIDENCE_ONLY` premise material and keeps
W1/W2 blocked.

No additional correction is authorized while this one-shot status remains
`THIRD_CORRECTION_AUTHORIZED_IN_PROGRESS`.
