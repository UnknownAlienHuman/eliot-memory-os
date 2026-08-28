# Core and daemon agent work units

This directory routes bounded implementation work for the 2026-08-28
core/daemon inventory. It is not a normative book. The exact issue body is the
work-unit contract; Architecture/Implementation handles remain the source of
meaning.

Current normative identity is
[`docs/normative-pair.toml`](../../../docs/normative-pair.toml). Canonical books
are
[`docs/architecture/ELIOT_ARCHITECTURE.md`](../../../docs/architecture/ELIOT_ARCHITECTURE.md)
and
[`docs/architecture/ELIOT_IMPLEMENTATION.md`](../../../docs/architecture/ELIOT_IMPLEMENTATION.md).
A brief, result, test, or generator bound to the superseded pair must be treated
as `STALE` for current promotion until recompiled; historical evidence is not
rewritten.

## Scope

Included: Host, Kernel, `eliotd`, Watchdog, Doctor, store
bridge/BlobStore/Surreal process boundary, testd, WASM host, native worker, User
Broker, notify, agent bridge, and Researcher provider process.

Excluded: Dreamer. Do not change Dreamer code, contracts, process topology,
prompts, routes, or tests in these work units.

## Required operating rules

1. Work on one issue, one primary `FunctionalCapabilityCell`, and one causal
   property at a time.
2. Start from the exact source identity and issue-linked contract revision.
   Rebase/revalidate before integration.
3. Do not create a crate because a concept has a name. A new package requires a
   completed `CrateExtractionDecision`: actual consumer, public
   contract/test/context seam, owner, migration/re-export, rollback/removal, and
   measured expected benefit.
4. Do not infer runtime or lifecycle authority from a crate/binary name.
   Preserve one owner for every mutable state.
5. Keep composition binaries thin, but do not split code by LOC alone. Extract
   only a coherent state/effect/dependency/proof boundary.
6. A worker does not edit the oracle, acceptance criteria, verifier semantics,
   or Product Pulse in the same work unit to make its patch pass.
7. A worker does not integrate its own result. Return an
   `IntegrationCandidate` with exact source/artifact identity, affected edges,
   evidence, residual unknowns, and rollback/removal notes.
8. Source/build/test presence is not runtime or product proof. Use the exact
   evidence dimensions: `ContractMaturity`, `ImplementationSupport`, and
   `EvidenceExecutionStatus`.
9. Keep Hard Boundaries intact: one canonical transition path; no hidden
   authority expansion; no direct canonical-storage bypass; no false
   `VERIFIED_COMPLETE`; no provenance/history laundering; no
   secret/privacy-boundary expansion.
10. Repeating a failed path requires a new discriminator or hypothesis.
    Otherwise return a Contract Challenge or evidence-backed no-change
    disposition.

## Proof sequence

Every implementation candidate returns:

1. **Discriminator** — exact old path or missing capability that fails before
   the patch.
2. **Module Proof** — independently invocable cell/package proof and declared
   proof ceiling.
3. **Edge Proof** — real provider/consumer, process, protocol, store,
   credential, or lifecycle boundary affected by the change.
4. **Product Pulse** — only when the change can affect the operational spine;
   coordinate with #11 rather than inventing another product test.
5. **Failure Capsule** — for any crash, timeout, unknown effect, cleanup
   failure, or regression.
6. **Promotion disposition** — canary candidate, narrow/rework, blocked,
   rejected, or rollback; never self-declared production support.

## Work-unit routing

| Issue | Primary cell/property | Integration dependency |
|---|---|---|
| #13 | Generated capability-cell ownership and proof bindings | Consumes all module manifests; feeds every later wave; also rebinds active generated projections to `docs/normative-pair.toml` |
| #14 | Host external lifecycle and HostStateJournal boundary | #11, #13, #15 |
| #15 | Small Kernel, fencing, ORS, Control Reserve, generation route | #11, #13, #14, #18, #19 |
| #16 | Independent Watchdog core/spool/SCM/containment boundaries | #11, #13–#15 |
| #17 | One-shot bounded Doctor repair execution | #13–#15 |
| #18 | `eliotd` semantic admission and strict finish boundary | #11, #13, #15, #19 |
| #19 | Store bridge, BlobStore owner, Surreal generation | #7–#9, #11, #13–#15, #18 |
| #20 | Isolated typed Instrument/testd execution | #11, #13, #15, #18 |
| #21 | Capability-limited WASM component generations | #11, #13, #15, #18 |
| #22 | Native worker artifact/facet/epoch/process boundary | #11, #13, #15, #18, #21, #23 |
| #23 | User Broker SID/session/credential/resource/launch boundary | #11, #13, #15, #18, #22 |
| #24 | Governed Researcher provider process bridge | #11, #13, #18, #20/#22 |
| #25 | Normative-pair identity decision | **Closed:** current pair adopted in `docs/normative-pair.toml`; no implementation worker may change it silently |

## Keep-and-bind surfaces

`eliot-notify` and `eliot-agent-bridge` are currently thin by source
inspection. Do not rewrite them without a discriminator. Bind their
statelessness, no-authority/no-durable-state contract, proof entrypoint, runtime
bundle, and replacement boundary through #13.

## Output schema

Return a structured result containing:

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

Only the integration owner may promote a candidate after revalidating the State
Fence, affected edges, and #11 Product Pulse where applicable.
