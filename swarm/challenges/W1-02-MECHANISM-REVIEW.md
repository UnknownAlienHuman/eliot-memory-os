# W1-02 Mechanism Review — complete result-envelope oracle

Status: `MECHANISM_CHANGED_ONE_SHOT_AUTHORIZED_IN_PROGRESS`

Authorization history: prior `MECHANISM_CHANGED_THIRD_ATTEMPT_AUTHORIZED`,
followed by the V3 nested-property rejection; v1.3 authorizes exactly one
mechanism-changed W1-02 attempt (attempt 4), with no admitted terminal attempt.

## Trigger

Two independent gate submissions rejected successive versions of the same
W1-02 mechanism:

1. the first correction leaked nested pattern consumers and mis-scoped
   `src/tests.rs` rows;
2. the second correction fixed the census, classification, scope, anchors,
   evidence, reasons, and source digests, but its independent verifier still
   accepted tampering of result-envelope metadata.

Per recovery-program rule R11, a third patch is not an iteration of the old
hypothesis. The mechanism changes here before further work.

## Rejected hypothesis

Recomputing every CSV row plus its aggregate digest is sufficient independent
verification of W1-02.

This is false. `swarm/results/W1-02.json` is part of the admitted artifact and
contains revision, worktree, normative-pair, schema, output, historical
challenge, uncertainty, and proof-ceiling claims. A verifier that ignores
those fields permits a semantically false envelope around a correct CSV.

## Revised mechanism

The independent verifier must recompute or exact-validate every admitted
result field:

- schema, authority, contract, and work-item identity;
- current Git revision and deterministic worktree-state label;
- census grammar/definition and historical-baseline challenge fields;
- row/classification/anchor/source-file counts and aggregate source digest;
- normative-pair digest and exact pair paths;
- exact CSV schema and output paths;
- proof ceiling.

Its self-test must mutate each metadata category independently and show that
the oracle rejects it. Generator `-Check` remains a byte-reproducibility proof,
not a substitute for this independent semantic oracle.

## Registry boundary

`swarm/inventory/refusals.csv` is a pre-remediation inventory. It does not
launder rows with `UNKNOWN` normative/work anchors into
`docs/UNIMPLEMENTED.md`. The accepted W0-01 honest-empty challenge remains the
owner of that registry boundary until source contains the mandatory structured
marker or a later explicit contract revision replaces it.

## Acceptance

The third attempt is acceptable only if:

1. generator `-Check`, verifier self-test, and normal verifier pass;
2. the previously corrected 744-row census remains unchanged unless a current
   source mutation explains the delta;
3. an independent Luna gate mutates the result-only metadata classes and
   observes rejection;
4. `swarm/results/W1-02.json` links this Mechanism Review and the W0-01
   registry-boundary challenge.
