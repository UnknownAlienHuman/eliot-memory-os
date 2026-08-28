# Core and daemon work units

This brief routes issues #13–#24. It is not normative. Current meaning comes
from the canonical pair in `docs/architecture/`, and the exact issue body is the
work-unit contract.

## Scope

Included: Host, Kernel, `eliotd`, Watchdog, Doctor, store bridge, BlobStore,
Host-managed Surreal process boundary, testd, WASM host, native worker, User
Broker, notify, agent bridge, and Researcher provider execution.

Excluded: Dreamer. Do not change Dreamer code, contracts, prompts, process
topology, routes, manifests, or tests from this workstream.

## Start condition

Do not use a shared long-lived core/daemon branch. For the assigned issue:

1. run the root `AGENTS.md` preflight;
2. create a fresh `<kind>/<issue>-<slug>` branch from exact current `main`;
3. record the primary paths and integration owner in the issue/PR;
4. verify that no other writer owns the same path scope.

A branch or brief bound to a different normative-pair digest or missing current
`main` as an ancestor is stale and read-only.

## Operating rules

1. Work on one primary `FunctionalCapabilityCell` and one causal property.
2. Do not infer lifecycle authority from a crate or executable name.
3. Preserve exactly one owner for each mutable state; declare statelessness.
4. Do not create a crate because a concept has a name. A new package requires a
   real consumer, contract/test/context seam, migration/removal path, and a
   justified `CrateExtractionDecision`.
5. Split composition code only at a state/effect/dependency/proof boundary, not
   by line count.
6. Do not change the oracle, acceptance criteria, verifier semantics, or Product
   Pulse in the implementation work unit merely to make a patch pass.
7. Workers return an integration candidate; they do not merge their own work.
8. Source/build/test presence is not runtime or Product Proof. Preserve
   `ContractMaturity`, `ImplementationSupport`, and `EvidenceExecutionStatus`.
9. Preserve the Hard Boundaries: one canonical transition path, no hidden
   authority expansion, no direct storage bypass, no false
   `VERIFIED_COMPLETE`, no provenance laundering, and no secret/privacy
   expansion.
10. Repeating a failed path requires a new discriminator or hypothesis.

## Proof sequence

Every candidate returns:

1. old-path discriminator;
2. independently invocable Module Proof and proof ceiling;
3. affected real Edge Proof;
4. Product Pulse through #11 when the operational spine can change;
5. Failure Capsule for crash, timeout, unknown effect, cleanup failure, or
   regression;
6. promotion, narrowing, rollback, rejection, or blocked disposition.

## Issue routing

| Issue | Primary boundary |
|---|---|
| #13 | generated capability-cell ownership, proof, and current-pair bindings |
| #14 | Host lifecycle and `HostStateJournal` |
| #15 | small Kernel, fencing, ORS, Control Reserve, generation routing |
| #16 | Watchdog deterministic core, protected spool, SCM, containment |
| #17 | bounded one-shot Doctor repair execution |
| #18 | `eliotd` semantic admission, `PreparedTransition`, strict finish |
| #19 | store bridge, BlobStore owner, Surreal process generation |
| #20 | isolated typed Instrument/testd execution |
| #21 | capability-limited WASM component generations |
| #22 | native worker artifact/facet/epoch/process boundary |
| #23 | User Broker SID/session/credential/resource boundary |
| #24 | governed Researcher provider process bridge |

Existing defect issues #7–#9 own their exact storage failures. Issue #11 owns
live Windows operational-spine/Product-Pulse evidence.

## Result schema

```yaml
issue_and_cell:
source_base_and_candidate:
causal_property:
old_path_discriminator:
changed_contract_or_source:
owned_state_and_effects:
module_proof:
edge_proof:
product_pulse_or_not_applicable_reason:
evidence_execution_status:
known_uncovered_behavior:
security_privacy_and_authority_delta:
migration_rollback_and_removal:
integration_candidate:
residual_unknowns:
finish: VERIFIED_COMPLETE | PARTIAL | BLOCKED | FAILED_VERIFICATION |
        DEGRADED_NO_PROOF | UNSAFE_TO_FINISH | CANCELLED | SUPERSEDED
```
