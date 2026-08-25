# W1-06 falsification disposition

Status: `PROGRAM_REVISION_ACCEPTED_V1_2`; W2 remains blocked by W0 and the
remaining W1 acceptance work.

The fresh, isolated OpenRouter lane B did not falsify the absence of a direct
Cargo dependency edge between the named contour sets. It did falsify the two
other literal premises used by the recovery program:

1. The repository-canonical `--workspace` test gates include 32 unignored
   full-stack UL harness tests. Therefore the literal statement that every
   claimed E2E test is disabled by default is false. A narrower statement may
   still be true for the historical 132-test inventory, but that inventory
   must be regenerated and named explicitly; it cannot be inferred from the
   current source tree.
2. The authoritative Windows release finalizer enumerates seven Authenticode
   PE roles, and the materializer identifies six required executable roles.
   Therefore the literal statement that the signed artifact set contains no
   executable product is false. A narrower Governor-constitutive or
   product-reachability claim remains unresolved and requires its own typed
   definition and verifier.

Program revision for all later work:

- replace assertion 2 with a generated E2E inventory that records each test's
  default gate, ignored/feature/env state, external prerequisites, and actual
  CI inclusion;
- replace assertion 3 with separate, non-interchangeable claims for
  Authenticode membership, materializer membership, launch reachability, and
  Governor-constitutive product authority;
- retain assertion 1 only as a static Cargo-graph fact, not proof that the two
  contours share no foundation or runtime resources;
- do not begin W2 until the generated inventories have independent oracle
  results and the revised assertions are accepted by the integration owner.

The required revision is now recorded in
`swarm/decisions/W1-06-PROGRAM-REVISION-v1.2.md` and projected into the local
task copy. The revised generator retains A1-A3, derives C1-C4 from explicit
predicates, reports C3 as `UNKNOWN`, and has an independent mismatch-tamper
oracle. Acceptance is evidence-only: it does not turn static role membership
into runtime reachability.

Evidence: `swarm/results/W1-06-A.json`,
`swarm/results/W1-06-A-mechanism-review.json`,
`swarm/results/W1-06-B.json`, `swarm/results/W1-06-revised.json`, and the
independent OpenRouter sessions named in the revised result.
