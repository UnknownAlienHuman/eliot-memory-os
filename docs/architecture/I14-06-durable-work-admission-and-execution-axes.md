## I14.6. Durable work, admission and execution axes

A durable work request exists before an attempt, but admission and execution are separate axes.

### Work admission

```text
BLOCKED_DEPENDENCY
→ READY
→ ADMITTED
| DEFERRED_CAPACITY
| CANCELLED
| STALE

DEFERRED_CAPACITY → READY | CANCELLED | STALE.
```

`DEFERRED_CAPACITY` records unavailable resource/route/quota, `not_before`, source of reset and alternatives. Ready Queue is a projection of `admission_state=READY`; it is not another task store.

### Execution axis

```text
NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED
→ VERIFYING
→ COMPLETED | PARTIAL | FAILED | CANCELLED | STALE | UNKNOWN_OUTCOME.
```

A Job can own several sequential attempts. An external `RunAttempt` is created only after work becomes `ADMITTED` and has its own provisioning/launch/runtime states from I10.15/I14.20. Capacity loss during provisioning closes that attempt with evidence and returns the work through a new admission revision; it does not mutate the running attempt into `DEFERRED_CAPACITY`.

Fields:

```text
job/work item/parent and recipe;
admission_state and execution_state as separate typed fields;
owner and Authority Epoch;
State Fence/dependency receipts;
eligible routes and attempt refs;
input/output/checkpoint handles;
budget/quota/deadline;
worktree/environment leases;
expected artifact/verifier;
coverage, result and receipts.
```

`AdmissionReservation` is Kernel-owned ORS state, not semantic work state:

```yaml
reservation_id:
work_item_and_proposed_attempt_id:
owner_epoch_and_state_fence:
resource_lane_environment_and_effect_claims:
pessimistic_cost_and_quota_view:
status: staged_inactive | active | released | expired | reconciling
canonical_admission_receipt_ref:
activation_receipt_ref:
expires_at_and_release_reason:
```

Only `active` under the matching canonical admission may launch work or hold effect authority. A staged reservation can reduce available capacity but cannot create a process or external effect. Crash/retry reuses the same reservation identity; release/expiry is receipted and cannot cancel a running attempt silently.

At-least-once execution is allowed only for idempotent, fenced or reconciled effects. Internal admission crosses canonical and ORS ownership through the `AdmissionReservation` saga defined in I10.15: ORS first stages inactive claims; canonical state records `ADMITTED` and the launch outbox; Kernel then activates the exact reservation. No process may launch from an ORS reservation alone or from a canonical admission without the matching activation receipt. Provider/environment provisioning remains a later observed idempotent effect. A durable object is never simultaneously “running” and “capacity deferred”.

