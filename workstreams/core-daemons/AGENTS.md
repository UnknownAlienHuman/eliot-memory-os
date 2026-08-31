# Core and daemon work units

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_router.py route --path <repository/path> --topic "<causal property>"
```

Read every fragment marked **required**, then record the emitted receipt in the
work unit or pull request. Optional fragments are loaded only when the current
decision crosses their stated boundary. A legacy `ELIOT_*` compatibility map is
never an acceptable reading receipt.

If no non-baseline route matches, stop the mutation and add or obtain a route;
silence is not permission. See [`../../docs/architecture/READING_PROTOCOL.md`](../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


This brief routes issues #13–#24 and their confirmed bounded defect units. It is
not normative. Current meaning comes from the canonical pair in
`docs/architecture/`, and the exact issue body is the work-unit contract.

## Scope

Included: Host, Kernel, `eliotd`, Watchdog, Doctor, store bridge, BlobStore,
Host-managed Surreal process boundary, testd, WASM host, native worker, User
Broker, notify, agent bridge, and Researcher provider execution.

Excluded: Dreamer. Do not change Dreamer code, contracts, prompts, process
topology, routes, manifests, or tests from this workstream.

## Source routing

Current composition roots are under `bins/eliot`, `bins/eliotd`, the Host/
Kernel/Store/Watchdog binaries, and their declared first-party crates.

`crates/eliot-app` and its `eliot-governor` binary are a legacy migration and
regression facade, not another Governor. Read its local `AGENTS.md` before any
change. Work there is allowed only when the owning issue proves the current path
still terminates there and the patch is a bounded regression repair,
compatibility-fixture change, extraction to a current owner, or deletion.
Adding a new feature or state/effect owner to the facade is prohibited.

## Start condition

Do not use a shared long-lived core/daemon branch. For the assigned issue:

1. run the root `AGENTS.md` preflight;
2. create a fresh `<kind>/<issue>-<slug>` branch from exact current `main`;
3. record the primary paths and integration owner in the issue/PR;
4. read every applicable nearest-path `AGENTS.md`;
5. verify that no other writer owns the same path scope.

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

## Primary issue routing

| Issue | Primary boundary |
|---|---|
| #13 | generated capability-cell ownership, proof, and current-pair bindings |
| #14 | Host lifecycle and `HostStateJournal` |
| #15 | small Kernel, fencing, ORS, Control Reserve, generation routing |
| #16 | Watchdog deterministic core, protected spool, SCM, containment |
| #17 | bounded one-shot Doctor repair execution |
| #18 | `eliotd` semantic admission, legacy-facade extraction, `PreparedTransition`, strict finish |
| #19 | store bridge, BlobStore owner, Surreal process generation |
| #20 | isolated typed Instrument/testd execution |
| #21 | capability-limited WASM component generations |
| #22 | native worker artifact/facet/epoch/process boundary |
| #23 | User Broker SID/session/credential/resource boundary |
| #24 | governed Researcher provider process bridge |

Regression probes #7–#10 own Claude Desktop completion, attach/context,
Antigravity terminal reconciliation, and arbitrary JSON payload integrity.
Issue #11 owns live Windows operational-spine/Product-Pulse evidence.

## Confirmed bounded defect units

These issues own one causal contract or local source repair. They do not replace
the primary integration issues above.

| Issue | Causal property |
|---|---|
| #63 | recompute one canonical executable request hash across Governor, Kernel and Store |
| #64 | replace scalar authority epochs with one lineage-aware identity and migration |
| #65 | separate normal admission from protected Control Reserve at every claimed bottleneck |
| #66 | submit one typed semantic activation result instead of silently re-claiming tickets |
| #67 | allow bounded concurrent Store transactions for disjoint Ordering Scopes |
| #74 | give User Broker register/heartbeat/launch/fence distinct operation identities |
| #76 | preserve typed Store errors and recovery directives on EBP |
| #77 | translate host requests before Kernel RequestIdentity binding; no raw Frame passthrough |
| #78 | give notification verification/delivery/ledger steps distinct child operation identities |
| #79 | separate transport connection identity from durable process/session ownership |

Open issues #82, #83 and #84 remain outside active core-daemon defect routing;
their references are retained in the registry as an explicit forbidden set so
they cannot be reintroduced accidentally.

Merged local repairs #59, #61, #68, #70, #72, #73, #75, #76 and #120 close
only their exact source discriminators. #72 now keeps later same-project testd
work behind every earlier nonterminal durable record, but its focused tests were
not executed by Actions and #20/#11 still own daemon integration, crash
recovery and Product Proof. #73 binds provider/config identity to the
workspace-pinned Wasmtime 47.0.4 generation without establishing #21 runtime
conformance. #75 removes the hidden WASM deadline clamp, while #76 preserves
typed Store errors and recovery directives; #120 independently persists and
verifies the effective epoch policy. None establishes runtime or Product
support.

### Required wave ordering

Do not combine the load-bearing migrations into one broad patch:

```text
#13 capability/proof ownership projection
→ #64 lineaged epoch contract
→ #63 executable request digest
→ #65 protected capacity classes
→ process-specific identity/activation/error units (#66, #74, #76–#79)
→ local scheduler/provider units (#67, #75, #120)
→ affected real edges
→ #11 Product Pulse.
```

A different order requires an explicit Contract Challenge showing why the
consumer can migrate safely without a temporary second owner or lossy adapter.

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
