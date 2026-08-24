# W0-06 ContractChallenge: bootstrap brief admission

Status: `CONTRACT_CHALLENGE_OPEN`

## Authority boundary

The recovery program requests an admitted
`eliot bootstrap brief --work-unit <seed>` command. Admission is not
authorized by the request alone. The compiled brief and its
`NormativeCoverageManifest` must remain consistent with the canonical
Architecture/Implementation pair, and I17.2 requires append-only,
content-addressed bootstrap failure and improvement drafts.

## Rejected implementation

The first W0-06 candidate was independently rejected and removed from the
working tree. It:

1. accepted a caller-supplied `RuleCatalogue` and
   `ReasonDirectiveRegistry` without provider-owned provenance;
2. classified hard boundaries, contracts, and guardrails as included in
   `BootstrapCoverage` while excluding every catalogue rule from the
   `NormativeCoverageManifest`;
3. selected an arbitrary lexicographically-minimum exclusion reason;
4. used the process current directory as repository identity;
5. returned generic `anyhow` exit 1 for malformed or unavailable inputs;
6. did not write or read back the append-only drafts required by I17.2;
7. marked a state-changing candidate path as `EffectClass::Read`.

Keeping that candidate would create a second, caller-authored ontology and a
false admission claim.

## Current fail-closed state

- `CommandId::BootstrapBrief` remains `PlanGap` with work item `A-06`.
- The existing pure bootstrap compiler remains available as library code.
- No production CLI route, synthetic zero-entry catalogue, evidence writer, or
  admission receipt is claimed.

## Required owner decisions

Admission is blocked until the contract owners define all of:

1. a provider-owned empty/gap `RuleCatalogue` identity and revision for the
   exact normative pair;
2. the typed `BootstrapFailureDraft` and `BootstrapImprovementDraft` owner,
   canonical schema, and evidence root;
3. an append-only create-new, canonical-JSON, digest/readback contract;
4. an explicit absolute repository/evidence-root CLI contract;
5. the local admitted response contract and typed exit codes;
6. whether evidence-only incomplete coverage is represented as
   `NORMATIVE_COVERAGE_INCOMPLETE` while still returning candidate output.

## Minimum acceptance evidence

- Seed accepts only profile plus canonical `AgentWorkUnitBrief`; caller-owned
  catalogues, rule classes, support states, and evidence outcomes are rejected.
- Brief coverage and `NormativeCoverageManifest` are bijectively consistent.
- Gap mode identifies unsearched provider/runtime/store/integration scopes and
  never invents rule dispositions.
- Draft writes are content-addressed, create-new, idempotent on identical
  reread, and reject tampering.
- CLI requires an absolute root and returns structured, tested exits for
  success, malformed input, and unavailable evidence storage.
- The command remains Kernel/MCP-independent and is classified as a candidate
  write effect with `ProofCeiling::CandidateArtifact`.

Until these conditions are owned and implemented, W0-06 is not admitted and
the W0 gate remains open.
