## I14.25. Doctor implementation contract

`eliot-doctor.exe` is a short-lived repair worker, not a permanently reasoning service and not a second Governor. One invocation owns one bounded diagnostic or repair job. Kernel may start it from a Governor request or from a signed Recovery Manifest when `eliotd` is unavailable.

### Inputs

```text
Problem/Incident identity or non-semantic recovery intent;
Diagnostic Brief and exact evidence handles;
Module Catalog snapshot, Capability Registry evidence and Kernel Generation Registry view;
registered RepairRecipe;
current State Fence, Authority Epoch and recovery lease;
last-known-good compatible artifacts/config;
repair budget, deadline, cancellation and escalation target.
```

Doctor does not receive broad database credentials, arbitrary shell authority or a free-form mandate to “fix ELIOT”. Every infrastructure effect is enumerated by the recipe and constrained by the recovery lease.

### Repair classes

```text
automatic_safe
  idempotent restart/reconnect; rebuild derived cache/index; remove stale session/process;
  reconcile a pending operation whose canonical/external outcome is already proven;

guarded
  config or credential transition; integration registration; module generation switch;
  schema/data repair; service/store cutover; restore or forward migration;

diagnose_only
  structural corruption; unknown owner/outcome; repeated repair failure;
  unregistered external effect; unclear privacy/authority impact.
```

`automatic_safe` may run only under pre-authorized policy and remaining budget. `guarded` requires the exact owner/approval named by the recipe. `diagnose_only` produces evidence, a proposed plan and escalation; it performs no repair effect.

### `RepairRecipe`

```yaml
RepairRecipe:
  recipe_id_and_version:
  problem_classes:
  applicable_components_and_generations:
  prerequisites_and_state_fence:
  required_authority_and_approval:
  exact_allowed_effects:
  commands_or_module_operations:
  expected_observables:
  verification_contract:
  rollback_or_compensation:
  attempt_budget_and_cooldown:
  stop_and_quarantine_conditions:
  evidence_and_receipt_requirements:
```

Recipes are versioned policy/config artifacts, reviewed like executable operations and bound to exact component/protocol ranges. A model may propose a recipe candidate; it cannot activate one.

### Execution lifecycle

```text
REQUESTED
→ ADMITTED
→ DIAGNOSING
→ READY_FOR_REPAIR
→ RUNNING
→ VERIFYING
→ SUCCEEDED | FAILED | PARTIAL | CANCELLED | QUARANTINED | ESCALATED.
```

Algorithm:

```text
1. authenticate recovery job and load current evidence/fence;
2. verify recipe applicability, remaining budget and authority;
3. refuse or re-diagnose if the problem changed;
4. execute the smallest allowed effect through Kernel/Module/Store recovery boundary;
5. capture attempt and side-effect receipts;
6. run the independent verification contract;
7. submit repair outcome/reconciliation intent to Governor/Kernel;
8. resolve, keep open, quarantine or escalate the Problem State;
9. emit a candidate lesson/recipe improvement, never automatic doctrine.
```

Doctor never performs a canonical semantic transition itself. When Governor is unavailable, it may write only an opaque reconciliation intent plus evidence locator/digest to ORS through Kernel; it cannot store or reinterpret semantic evidence there. Canonical reconciliation occurs after the governed application path is restored.

### Repair-loop and Doctor failure

```text
repeating the same recipe without new evidence is forbidden after its attempt budget;
failed verification does not count as repair success merely because the process restarted;
unknown external outcome pauses the affected Ordering Scope and requires reconciliation;
repeated failure quarantines the component or recipe and escalates;
Doctor crash is handled by Kernel as a temporary child; the same job resumes only from a durable checkpoint/receipt;
Doctor cannot update its own binary, recipe policy or authority.
```

Doctor artifacts are immutable generations. Replacing Doctor uses the normal stateless/on-demand module staging and contract tests; there is no mutable Doctor state to migrate beyond the Durable Job checkpoint.

