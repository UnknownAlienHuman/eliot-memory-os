## I0.5. Conformance, support and evidence status

Conformance is evidence-derived state, not maintained prose. Three orthogonal dimensions are mandatory:

```text
ContractMaturity
  SKELETON | COMPATIBLE | STABLE | REPLACEABLE | RETIRED;

ImplementationSupport
  CURRENT_VERIFIED | CURRENT_UNVERIFIED | PARTIAL | BLOCKED | TARGET |
  EXPERIMENTAL | DEFERRED | DEGRADED | STALE | NOT_APPLICABLE;

EvidenceExecutionStatus
  NOT_EXECUTED | SIMULATED | EXECUTED | UNKNOWN_OUTCOME.
```

A detailed schema, trait, command or state machine in this book is `TARGET` unless exact current source handles and current Product Identity evidence say otherwise. `TARGET` is a design obligation, not evidence that a capability exists. A source implementation can be `CURRENT_UNVERIFIED`; a generated report cannot promote it.

Canonical evidence binds every support claim to an exact Product Identity and invalidation set. `docs/conformance.toml` is the deterministic, read-only **documentation projection** of M1 Architecture IDs and Appendix H. It proves mapping completeness only; it is not runtime/source support evidence and cannot promote any row above `TARGET` / `NOT_EXECUTED` without separate exact evidence. Each row preserves the exact human Appendix-H owner cell as `owner_projection`; that field is unparsed documentation text, not an executable owner registry or authority grant:

```toml
projection_status = "DOCUMENTATION_TARGET"
runtime_evidence_status = "NOT_EVIDENCE"
normative_pair_receipt = "docs/normative-pair.toml"

[[requirement]]
id = "ARCH-MOD-01"
owner_projection = "I1, I2, I14.14–I14.16"
observable_proof_family = "optional module crash while Kernel remains healthy"
contract_maturity = "SKELETON"
implementation_support = "TARGET"
evidence_execution_status = "NOT_EXECUTED"
source_handles = []
evidence_refs = []
notes = "documentation mapping only; exact runtime/source support remains unproven"
```

Rules:

```text
CURRENT_VERIFIED requires executed, current, scoped evidence on the exact identity;
CURRENT_UNVERIFIED means source exists but product behavior is not proven;
TARGET/EXPERIMENTAL/DEFERRED cannot satisfy current product acceptance;
NOT_EXECUTED or SIMULATED evidence cannot satisfy a real-effect verifier;
any invalidated dependency makes support STALE;
report wording, test count, trait presence or manual status edit cannot promote support;
several ARCH anchors may share one end-to-end proof;
no separate test is required merely because an ID exists.
```

### Current-system evidence snapshot

Current implementation support is never inferred from this prose. A generated `CurrentSystemEvidenceSnapshot` binds the exact repository/runtime/data state used by repair, migration, product and deletion decisions:

```yaml
CurrentSystemEvidenceSnapshot:
  snapshot_id_revision_and_digest:
  normative_pair_identity:
  compiler_and_execution_receipt:
  product_identity_and_source_heads:
  installed_artifact_and_generation_hashes:
  active_store_schema_and_data_revision:
  active_integration_skill_hook_and_surface_manifest_digests:
  domain_coverage:
    source: OBSERVED | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    build: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    runtime: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    store: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
    integrations: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
  capability_support_rows:
    - contract_ref:
      support_claim_ref:
      support_observation_state: OBSERVED | NOT_RUNNING | UNAVAILABLE | UNKNOWN | STALE | CONFLICTED
      contract_maturity:
      implementation_support:
      evidence_execution_status:
      source_handles:
      evidence_refs:
      blind_or_unobserved_boundaries:
      invalidation_set:
  current_product_blockers_and_unresolved_regressions:
  generated_at_expiry_and_invalidation:
```

Each capability row carries the exact three I0.5 dimensions. `support_observation_state` describes observation availability/state only; it is not an `ImplementationSupport` value. `UNKNOWN`, `UNAVAILABLE`, `NOT_RUNNING` or `CONFLICTED` observation cannot be copied into support, maturity or evidence execution. A bound support claim remains at the strongest state actually justified by exact evidence: absent source evidence stays `TARGET` / `NOT_EXECUTED`; present but behavior-unproven source may be `CURRENT_UNVERIFIED`; incomplete behavior may be `PARTIAL` or `DEGRADED`; invalidated evidence is `STALE`. A report may render these values only from `support_claim_ref`; manual report text cannot promote them.

`CurrentSystemEvidenceCompiler` is a D0 FunctionalCapabilityCell with no canonical mutable state. Its source-maintenance owner is the first-party `eliot-bootstrap` crate; its D0 execution owner is the short-lived `eliot.exe` command `eliot system snapshot`. After InstrumentRunner exists, the same pure compiler core executes as a typed Instrument profile and Governor admits the immutable artifact. The crate also contains the bootstrap-only adapters required to read exact repository/worktree identity, build artifacts, service/process manifests, config/policy, optional runtime/store probes and integration manifests; platform/tool adapters remain behind narrow ports. It never infers a running system from prose or a PID alone, and it does not become a daemon, store or status owner.

The compiler has an independent ModuleTestCapsule covering partial source trees, absent runtime/store, stale manifests, conflicting identities, forged support statuses and interrupted probes. A Human-provided fact is preserved as an attributed observation; it cannot directly set `CURRENT_VERIFIED` or `EXECUTED`. Manual YAML editing is not an admitted producer.

The snapshot is regenerated after any source/runtime/data change and before a repair campaign, repository cutover, old-document deletion or product claim. Missing domains remain explicit as `support_observation_state = NOT_RUNNING | UNKNOWN | UNAVAILABLE | STALE | CONFLICTED`; they never create an `ImplementationSupport` value. An absent runtime is `NOT_RUNNING`, not a global compiler failure. Dependent support remains at the strongest state justified by exact current evidence; absence or staleness never promotes a target contract to current support.

