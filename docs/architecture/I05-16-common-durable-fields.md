## I5.16. Common durable fields

Every durable semantic record carries, directly or through an immutable envelope:

```yaml
id:
record_kind:
scope_id:
task_id:
created_by_principal:
created_at:
observed_at:
valid_time:
known_time:
transaction_time:
state_fence:
epistemic_status:
lifecycle_status:
authority_class:
origin_assurance:
instruction_taint:
semantic_screening:
privacy_class:
visibility:
source_refs:
evidence_refs:
verification_refs:
supersedes_refs:
policy_snapshot_id:
config_snapshot_id:
schema_version:
```

Derived/exportable records additionally carry, when applicable:

```text
influence_dependency_closure_ref;
disclosure_dependency_closure_ref;
source_availability;
coverage_and_assurance_ceiling;
coordinate_basis_and_approximation;
```

Absence of a closure or coverage record means `unknown`, not unrestricted/complete.

Fields that do not apply remain explicit `None`; they are not silently omitted from the semantic model.

