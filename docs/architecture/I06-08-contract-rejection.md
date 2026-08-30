## I6.8. Contract rejection

Error returns all defects in one response:

```yaml
ContractError:
  code:
  schema_digest:
  invalid_fields_and_paths:
  missing_fields:
  allowed_enum_values:
  semantic_vs_schema_error:
  evidence_refs:
  safe_fallback:
  minimal_valid_example:
  next_allowed_action:
  retry_policy:
  write_mutation_status: NOT_ATTEMPTED | STAGED | COMMITTED | UNKNOWN
  write_intent_id:
  proposed_operation_id:
  corrected_operation_id:
  corrected_from_operation_id:
```

Semantic ambiguity defaults to safe capture as Observation Candidate, not data loss.

`AdmissionRejection` is a typed pre-stage result, not a canonical receipt:

```yaml
AdmissionRejection:
  request_id:
  proposed_operation_id:
  stage_state: none
  ordering_sequence_assigned: false
  decision: not_accepted | conflict
  all_contract_errors:
  durable_audit_or_problem_ref:   # only when policy/security requires one
  safe_capture_fallback:
  corrected_retry_identity_rule:
  next_allowed_action:
```

A corrected payload normally receives a new operation identity. Exact retry of the same request hash returns the same rejection. The system never reports `ACCEPTED_PENDING` unless the entire immutable payload has actually committed to ORS.

A schema-invalid request with `NOT_ATTEMPTED` does not consume the stable `write_intent_id`. The corrected request receives a new operation ID, canonical request hash and normally a new idempotency key, while `corrected_from_operation_id` preserves lineage. Reusing one idempotency key with different canonical bytes is always `IDENTITY_CONFLICT`. Every release runs the published minimal accepted examples against the current generated schema.

