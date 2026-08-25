# W0-06 ContractChallenge: bootstrap brief admission

Status: `CONTRACT_CHALLENGE_ACCEPTED`

## Root disposition

Root accepts the bounded D0 admission mechanism implemented for W0-06:

1. `eliot-bootstrap` owns an honest empty `Gap` projection for the exact
   frozen normative pair. Callers cannot supply its catalogue, registry,
   provider identity, source revision, or rule dispositions.
2. `compile_provider_gap_brief` consumes a validated
   `CurrentSystemEvidenceSnapshot`, rejects a noncanonical normative pair, and
   derives the snapshot reference itself. A bare caller-provided digest is not
   accepted as evidence.
3. `BootstrapCoverage` is derived only from `NormativeCoverageManifest`; GAP
   scopes remain explicit and no synthetic rule is emitted.
4. `BootstrapFailureDraft` and `BootstrapImprovementDraft` are typed,
   canonical-JSON, content-addressed candidate artifacts. The CLI publishes by
   synced staging plus cross-platform hard-link no-clobber, exact readback, and
   digest verification under the explicit repository root.
5. `eliot bootstrap brief --work-unit <ABSOLUTE> --repo-root <ABSOLUTE>` is a
   one-shot local D0 route with `Candidate` effect and
   `CandidateArtifact` ceiling. It neither calls Kernel nor depends on MCP.
6. The command returns typed JSON and the accepted exits are `0` candidate
   produced, `2` invalid input, `65` digest mismatch, `66` unavailable source,
   `75` publication outcome unknown, and `78` contract challenge.

Focused Clippy passed for `eliot`, `eliot-cli`, and `eliot-bootstrap` after the
NormativePair correction. Focused tests passed: 19 `eliot-bootstrap` library
tests, 3 bootstrap subprocess tests, 20 system-snapshot subprocess tests, and
16 `eliot-cli` tests. The full W0 workspace gate remains a separate required
receipt.

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

## Current bounded state

- `CommandId::BootstrapBrief` is locally admitted as a D0 candidate-producing
  command; it is no longer reported as `PlanGap` by the CLI provider table.
- The provider owns the honest GAP catalogue and its revision. Callers cannot
  inject rule classes, dispositions, support states, or evidence outcomes.
- The command captures the current repository snapshot, emits append-only
  content-addressed drafts, and verifies exact bytes and digests on reread.
- `NormativePair` contains exactly the Architecture and Implementation SHA-256
  identities. Runtime evidence remains a snapshot source with an explicit
  availability state; it is not a third normative document.
- The pair correction is versioned by the v2 provider and artifact schema
  identities, and `canonical_normative_pair_contains_only_architecture_and_implementation`
  prevents reintroducing a runtime digest into the pair.
- Existing v1 candidate drafts remain immutable historical evidence. They are
  not silently rewritten or promoted.

This accepts only the local candidate route. It does not claim a Kernel/MCP
admission receipt, canonical write authority, runtime availability, or product
completion. W0 still depends on the aggregate verifier and independent gate.
