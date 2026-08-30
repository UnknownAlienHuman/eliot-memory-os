## I0.10. User outcome, recovery invariants and anti-proxy development contract

ELIOT distinguishes the reason the product exists from the safety properties required to build it.

```text
UserOutcomeObjective
  observable improvement for a real user/agent on a real task;

ArchitectureSafetyInvariantSet
  authority, integrity, provenance, finish, recovery and privacy properties
  that must hold while pursuing the outcome;

RecoveryAcceptanceProfile
  the bounded set of currently blocking invariant gaps whose closure enables
  the next product experiment.
```

A `RecoveryAcceptanceProfile` is compiled from the current `CurrentSystemEvidenceSnapshot`, active conformance Problems and the accepted objective. Historical failures such as split identity, shadow authority, lossy payload, weak finish, synthetic verification or a broken memory lifecycle are **regression probes**, not assertions about an unseen current tree. A probe becomes a current repair obligation only after it discriminates the exact current Product Identity.

Closing a recovery profile does not establish product value. It may be satisfied in a toy environment without improving real work. Product success additionally requires evidence appropriate to the claim. A deterministic one-scope product property may use the exact pre-change observed behavior or a declared `not_applicable_with_reason` comparison when no separate control can change the conclusion. Stochastic, comparative, population-level, non-inferiority or generalization claims require the applicable baseline/control and `ProductEvaluationPlan`.

Definitions:

| Concept | Meaning |
|---|---|
| **UserOutcomeObjective** | The user-visible or task-visible effect ELIOT is intended to improve |
| **Causal Property** | One observable system property changed by one work unit |
| **Discriminator** | Evidence that separates the proposed mechanism from the old path or a rival explanation |
| **Product Proof** | End-to-end outcome evidence on an exact Product Identity, with a claim-appropriate comparison or exact pre-change behavior, counter-metrics, uncertainty and applicable independent evaluation |
| **Activity Artifact** | Test, receipt, report, diff, type, status or log; evidence, never product success by itself |

```yaml
UserOutcomeObjectiveState:
  objective_id:
  owner:
  task_family_and_population:
  intended_user_outcome:
  primary_outcome_measure:
  comparison_basis: exact_prechange_behavior | matched_control | memory_free_control |
                    historical_reference | not_applicable_with_reason
  counter_metrics:
  disproof_and_stop_conditions:
  evaluation_plan_ref:
  product_identity_ref:
  outcome_evidence_refs:
  status: active | achieved | refuted | superseded | cancelled
  revision:

RecoveryAcceptanceProfile:
  profile_id:
  objective_ref:
  invariant_gaps:
  affected_owners:
  discriminators:
  enablement_condition:
  status: active | satisfied | superseded
  revision:
```

Only the `Requester / Domain Owner`, or a Human explicitly delegated that exact goal/acceptance authority, can revise the `UserOutcomeObjective`. The Task Controller owns the current execution-plan revision and may propose clarification, narrowing or supersession; it cannot silently redefine the user outcome. Dreamer, Watchdog, tests and reports propose or observe; they do not define success. `achieved` requires the predeclared acceptance/outcome on an exact Product Identity and the evaluation depth appropriate to the claim. Formal preregistration and inferential planning are mandatory only for stochastic, comparative or generalizing claims; a deterministic vertical-spine property may close through an exact old-path discriminator, corrected-path proof and applicable fault/restart cases. Closing every invariant gap does not automatically set the product outcome.

Rules:

```text
report/test/receipt/hash/certificate does not close a property it did not measure;
local PASS does not promote product status;
progress requires new evidence, artifact, verified state or lower material uncertainty;
status `ready`, `complete` or `certified` is scoped to exact identity and proof;
test/line/commit/type/tool/phase/token counts are counter-metrics, not goals;
a second repair of one failure class requires a new causal hypothesis or Mechanism Review;
a defect closes by changed product behavior, not by a new report.
```

Documentation changes before code only for public contract, ownership, Hard Boundary, migration or accepted default. Local mechanism choices may be resolved by bounded experiments and documented immediately after the discriminator. Prose that replaces the next discriminative artifact is development failure.

### Current recovery priority and promotion boundary

The normative book does not freeze a historical blocker list. The active `RecoveryAcceptanceProfile` is generated from the current `CurrentSystemEvidenceSnapshot`, accepted Product Objective and unresolved conformance Problems. It names exact source/runtime/data identities, affected owners, discriminators, enablement conditions and expiry. Historical findings such as permissive finish, lossy payloads, shadow writers or synthetic verification remain external regression evidence until the current snapshot confirms or refutes them; they are not silently asserted about an unseen tree.

This is **not a global feature freeze**. A confirmed blocker limits production promotion, authority, release claims and integration paths that depend on it.

Allowed before full impact proof:

```text
read-only investigation;
contract/test/discriminator work;
isolated module or prototype work with no canonical/external effects;
WASM/process shadow generations with zero authority;
research and tool experiments in a declared disposable environment;
work on unrelated owners under explicit dependency assumptions.
```

If dependency on a blocker is unknown, the result remains an isolated candidate and cannot enter the affected production path until the edge is resolved. Unknown dependency does not stop unrelated micro-modular development. Promotion requires affected-edge evidence; exploration does not.

### Rule classes at runtime

Operational rules are resolved through one generated catalogue, not inferred from prose grammar:

```yaml
RuleCatalogueEntry:
  rule_id_and_revision:
  class: HardBoundary | Contract | Guardrail | Default | Experiment | Policy
  architecture_anchor_or_policy_root:
  owning_implementation_section_and_capability:
  scope_and_applicability:
  rationale_and_failure_class:
  observable_property_or_decision_changed:
  enforcement_or_degraded_behavior:
  challenge_deviation_or_change_path:
  invalidation_and_expiry:

RuleBinding:
  rule_ref_and_exact_revision:
  work_unit_task_scope_and_state_fence:
  rendered_instruction_or_directive_ref:
  applied_or_not_applicable_reason:
  authority_and_effect_ceiling:
  delivery_and_acknowledgement_receipt:
```

Classification rules:

```text
HardBoundary
  → requires an Architecture Hard Boundary/authority/privacy/proof anchor;
  → Implementation cannot create it from convenience prose;
  → deviation is impossible without the applicable Architecture/authority change.

Contract
  → observable obligation of one capability;
  → failure returns typed degraded/unsupported state rather than invented success.

Guardrail / Default
  → may be challenged through evidence-backed ImplementationDeviation.

Experiment
  → reversible candidate with discriminator, budget, stop and rollback.

Policy
  → Human-owned privacy/cost/risk/model choice within Architecture.
```

Unregistered prose is explanation, rationale or design context. It may not be the sole source of a blocker, permission, reason code, automatic stop or deviation. One classified block may cover several explanatory sentences; a lint that merely counts modal verbs is explicitly rejected as proxy work. The documentation/evidence build instead verifies that every generated directive, blocking decision, reason code and `ImplementationDeviation` resolves to a current `RuleCatalogueEntry`. If a compiled brief includes modal or imperative prose without such a binding, it is rendered explicitly as `NONBINDING_CONTEXT`; planner, reviewer and deviation logic may not treat it as executable authority.

`NormativeCoverageManifest` accompanies every compiled brief:

```yaml
NormativeCoverageManifest:
  pair_and_catalogue_revision:
  searched_rule_scopes:
  included_rule_bindings:
  excluded_with_reason:
  not_searched_scopes:
  searched_and_absent_questions:
  stale_or_conflicting_rules:
  expansion_handles:
```

For Guardrail and Default an `ImplementationDeviation` is always available. Contract failure uses its declared degraded behavior; it is not silently reclassified. HardBoundary remains fail-closed. A missing or stale rule binding cannot be interpreted as permission.

The D0 `BootstrapRuleCatalogueCompiler` is a third pure FunctionalCapabilityCell in `eliot-bootstrap`. It compiles only explicitly registered Architecture Hard Boundaries, capability contracts, current development guardrails/defaults, active Human policies and admitted experiments into a content-addressed catalogue. It does not classify arbitrary prose by language-model judgment. The initial bootstrap catalogue is a generated evidence artifact with section handles and exact normative-pair identity; after the normal Contract Catalogue exists, the bootstrap projection is generated from that owner and ceases to be an independent input. Catalogue absence yields `NORMATIVE_COVERAGE_INCOMPLETE`, never implicit permission or a global stop unrelated to the missing scope.

