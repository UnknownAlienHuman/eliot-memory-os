## I6.10. Authority records

### Capability token

Binds principal to allowed operations, scopes, visibility, data classes, model/tool routes and expiry. It never grants more than its issuing policy.

Kernel performs only a generic authority/fence decision:

```yaml
AuthorityDecision:
  verdict: allow | deny
  reason_codes:
  effective_scope_and_effect_ceiling:
  authority_epoch_and_state_fence:
  granted_or_required_authority_ref:
  next_allowed_action:
```

Semantic action admissibility remains a Governor gate; `AuthorityDecision` cannot promote truth or choose a task plan.

### Kernel authority projection

Before a CapabilityToken, lease, approval or operation-specific permit becomes effective, `eliotd` compiles its mechanically enforceable subset into an immutable `KernelAuthoritySnapshot` and Kernel commits it to ORS:

```text
principal/session/token identity;
allowed named operations and transition classes;
exact scope/effect/data-class ceilings;
State Fence, policy/config/lease revisions and Authority Epoch;
expiry/heartbeat/revocation conditions;
required approval/proof handles;
source canonical receipt and snapshot hash.
```

Kernel validates requests only against this projection and current revocation/epoch state. It may expire, fence, revoke or further narrow authority and record a reconciliation intent, but it cannot create a token, widen scope/effect, reinterpret policy or choose a task action. During `eliotd` outage no new semantic authority is issued; only exact operations already present in a valid snapshot/continuation permit may complete. Kernel restart reconstructs the projection from ORS plus canonical receipts; mismatch or missing lineage closes effect admission until reconciliation. Restore imports snapshots only as historical/suspended evidence and issues new authority explicitly.

Authority activation is an explicit asymmetric saga; no cross-store atomicity is claimed:

```text
grant/widen:
  canonical decision records proposed authority as PENDING_KERNEL_ACTIVATION
  → Kernel validates and commits KernelAuthoritySnapshot in ORS
  → AuthorityActivationReceipt makes the exact grant effective
  → canonical projection records ACTIVE;

revoke/narrow/expire:
  Kernel commits AuthorityRevocation in ORS first and stops matching effects
  → canonical revocation transition reconciles afterward
  → failure to write canonical state leaves a visible stricter revocation intent,
    never an active right without enforcement.
```

A canonical token/approval row without matching activation receipt is not authority. Crash after canonical proposal but before ORS activation leaves it inactive. Crash after ORS revocation but before canonical reconciliation leaves it revoked and opens a scoped recovery item. Exact retries use the same grant/revocation identity. Activation happens when a delegated token/lease/approval boundary changes, not on every request: many Primitive/Standard operations may reuse one current snapshot until its fence, expiry or revocation changes.

### Epoch identity

Every authority-bearing generation uses a typed epoch, not a bare counter:

```yaml
EpochId:
  lineage_id: uuid
  sequence: u64
```

`lineage_id` changes after restore, break-glass reconstitution or loss of the previous trusted epoch source; `sequence` increases within one active lineage. Validity requires an exact match to the currently active lineage and an allowed sequence/operation permit. Epochs from different lineages are never ordered by timestamp or UUID and never become valid because their numeric sequence is larger. HostInstallationEpoch lives in HostStateJournal; Kernel/module/lease epochs live in ORS/canonical receipts as appropriate. Restore and rollback create a new lineage or a newer sequence and never reactivate an old tuple.

### Leases

```text
TaskControllerLease — authority to transition one task's current plan revision;
WorkLease      — ownership of a work item;
SwarmCoordinatorLease — authority to advance one `SwarmExecutionState`, coordinate its current wave and aggregate results under an exact active `SwarmPlanAdmission` and `SwarmPlanDefinition` revision; it cannot revise definition intent or admission ceilings;
WorktreeLease  — exclusive authority over an isolated mutable tree;
ActionLease    — short-lived authority for exact Material/Critical effects;
MigrationLease — installation-wide schema/data transition;
RecoveryLease  — exact bounded repair/cutover action.
```

Each lease carries:

```text
holder;
scope/effect set;
State Fence;
Authority Epoch;
issued/expires/heartbeat;
verifier/receipt obligations;
revocation and reassignment rule.
```

Stale epoch or expired lease can still provide historical evidence, but cannot authorize a new effect.

### Approval

```yaml
ApprovalRequest:
  exact_action_hash:
  impact_and_scope:
  requested_by:
  evidence_and_unknowns:
  expiry:
  allowed_once:

ApprovalRecord:
  request_ref:
  approver_principal:
  verdict:
  conditions:
  decided_at:
```

Approval authorizes the exact action only. It does not prove a fact, verifier competence or successful outcome.

