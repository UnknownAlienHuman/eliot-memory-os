## I21.5. Inquiry obligations and acceptance certificates

An inquiry item is not a task description but a statement of what must become true and what will show it. Obligations are compiled into the existing work graph by `TaskGraphCompiler` (I10.15); no second graph exists.

```yaml
InquiryObligation:
  obligation_id_and_parent_question:
  goal_and_protocol_ref:
  dependencies_and_assumptions:
  acceptance_certificate_kind:
    kernel_checked_proof | reproducible_build_and_contract_tests |
    immutable_inputs_and_raw_measurements | exact_source_identity_and_passage |
    protocol_compliance_qc_and_raw_data | accepted_evidence_revision_and_authority_signature
  information_boundary:
  responsible_role_and_verifier:
  budget_and_stop_condition:
  status: STUB | READY | RUNNING | BLOCKED | SUBMITTED | VERIFIED |
          REJECTED | INVALIDATED | CANCELLED
  invalidated_by_reason_resources_spent_and_reusable_artifacts:
  reopen_conditions:
```

An obligation is satisfied by its certificate, never by a worker's report that it is done.

Planning is receding-horizon: only obligations that current observations can determine are materialised. Information-dependent futures remain `STUB` and are expanded when the upstream result arrives. Invalidated obligations are not deleted: they retain the invalidating cause, spent resources and any reusable artifacts, so that repeated planning cost becomes visible.

The planner wakes on: depletion of the ready frontier, a new contradiction, a verifier counterexample, a changed contract, a budget phase transition, stale evidence, a new dependency, a repeated local failure, evidence that changes decision ranking, or a Human semantic interrupt. It is not invoked after every tool call.

