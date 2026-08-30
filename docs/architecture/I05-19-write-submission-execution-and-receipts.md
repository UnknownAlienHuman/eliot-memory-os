## I5.19. Write submission, execution and receipts

Three different outcomes are not collapsed.

### `WriteSubmission`

Returned by admission/front door before a final canonical receipt:

```yaml
submission_id:
operation_id:
request_hash:
state: not_accepted | staged | resolved_existing
reason_codes:
ors_stage_ref:
canonical_receipt_ref:
retry_identity_rule:
next_allowed_action:
```

`not_accepted` means the requested domain mutation was not staged, no Ordering Scope sequence was reserved and no external effect was issued. Corrected payload uses a new operation identity; exact retry of the same hash returns the same decision. Syntax/shape errors are operational responses. Authority/security/revision denials may create a separate governed audit/Problem transition with its own identity; that control evidence must not be confused with execution of the rejected request.

`staged` means ORS accepted the exact operation identity; caller must not create a duplicate and may poll. `resolved_existing` points to an already final receipt for the idempotency key.

### Canonical execution

For each staged `PreparedTransition`:

```text
1. resolve existing WriteReceipt by idempotency key;
2. verify ordering predecessor and active Authority Epoch;
3. revalidate required revisions/policy;
4. execute one named parameterized transaction;
5. append canonical events;
6. update projections and typed relations;
7. update the exact affected RevisionHeads and OrderingHeads;
8. append audit-chain fields;
9. create final WriteReceipt and outbox rows;
10. commit;
11. reconcile ORS and notify waiters.
```

`WriteReceipt` is terminal:

```yaml
operation_id:
idempotency_key:
scope_and_ordering_sequences:
status: committed | rejected | dead_letter | cancelled
commit_id:
revision_before_after:
applied_command_ids:
emitted_event_ids:
projection_refs:
policy_config_schema_versions:
committed_at:
error_code_and_evidence:
resubmission: none | new_identity_after_condition
```

`retry_wait`, `applying`, `unknown_outcome` and `reconciling` are ORS `OperationState`, never canonical receipt statuses. A final receipt is immutable: retrying the same operation identity returns the same receipt. `new_identity_after_condition` only authorizes a newly admitted operation after the named condition changes; it never replays the terminal operation. `rejected` and `cancelled` assert that the requested domain mutation and external effect did not occur and safely disposition a reserved order. The receipt/audit/sequence disposition itself is a canonical control transition; it is never described as “no canonical write”. `dead_letter` is terminal only when the original mutation is proven not to have been applied; it preserves the unusable operation and opens a `SequenceGap` whose ordering position still requires disposition. If any canonical/external effect is unknown, no final `dead_letter` receipt is fabricated: the ORS operation remains `UNKNOWN_OUTCOME/RECONCILING`, the gap is open and only dependent scopes pause. Recovery resolves the gap through a canonical `SequenceDisposition` preserving original evidence.

Unknown commit is never retried blindly. Kernel queries receipt by identity; proven rollback may retry the same operation; unresolved outcome pauses only dependent scopes and opens Problem State.

### Receipt taxonomy and common envelope

The many domain names ending in `Receipt` do **not** create many receipt stores, writers or unrelated lifecycle roots. Every durable receipt is a typed payload inside one versioned envelope owned by the subsystem that performed the transition:

```yaml
ReceiptEnvelope:
  receipt_id_and_kind:
  schema_and_contract_revision:
  installation_product_workscope_task:
  operation_attempt_and_idempotency_identity:
  principal_owner_and_generation:
  authority_epoch_and_state_fence:
  input_output_and_artifact_digests:
  terminal_or_observed_disposition:
  evidence_and_raw_handle_refs:
  privacy_disclosure_and_retention:
  created_observed_committed_at:
  supersession_invalidation_and_reconciliation_refs:
  typed_payload:
```

Receipt classes are limited to:

```text
canonical transition;
external effect/process execution;
delivery/observation;
evaluation/verification;
recovery/cutover/migration.
```

A new domain-specific name ending in `Receipt` is only a typed payload kind or a derived view unless it proves a distinct owner, lifecycle, idempotency boundary and query need. Common identity, authority, fence, provenance and terminal semantics are never redefined in the payload. A report, candidate, plan, preview or registry view is not renamed into a receipt merely to sound authoritative. Generated contract checks reject duplicate common fields and two payload kinds claiming the same transition.

