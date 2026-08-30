## I1.5. Demand-start, observable use, supervision and idle shutdown

DEFAULT mode is `on_demand`. The word *daemon* describes a supervised service role, not a requirement to consume resources while ELIOT is unused.

### Observable use and activation

Any authenticated, observable use of an ELIOT surface activates the control contour before that use is treated as governed work:

```text
native UI or `eliot` CLI request;
MCP/agent bridge attach or tool call;
ELIOT-launched AgentAttempt or external-agent reconciliation;
approved maintenance, backup, migration or recovery job;
protected external effect that still requires supervision;
Watchdog observation of a registered agent/bridge event requiring reconciliation;
Task Scheduler wake created by an admitted WakeIntent.
```

An unintegrated external agent or editor that never reaches an ELIOT bridge remains outside this claim. Process names and filesystem similarity alone do not prove that ELIOT is being used; the interval is reported as `BLIND` or `UNKNOWN` rather than reconstructed as governed activity.

HostStateJournal owns one non-semantic activation lineage:

```yaml
EliotActivationRecord:
  activation_id_and_idempotency_key:
  trigger_class_and_trigger_evidence:
  requester_principal_session_or_scheduler:
  requested_capabilities_and_candidate_scope:
  state: STOPPED | STARTING | CONTROL_READY | ACTIVE | DRAINING |
         STOPPED_CLEAN | DEGRADED_RECOVERY | FAILED
  activation_generation_and_drain_generation:
  host_kernel_watchdog_and_store_generations:
  supervision_readiness_and_governance_profile:
  runtime_and_supervision_lease_refs:
  wake_intent_refs:
  drain_commit_ref_and_wake_during_drain_disposition:
  boot_session_and_power_transition_evidence:
  started_ready_draining_and_stopped_at:
  failure_and_recovery_directive:
```

Concurrent triggers with the same compatible installation/activation generation coalesce behind one start. A request is not admitted as an active Session/Attempt until it receives an activation result bound to the current Host/Kernel/Watchdog generations. Starting a process, opening a pipe or seeing an old heartbeat is not sufficient.

Activation and drain are serialized by one installation-scoped `activation_generation`. A new observable-use trigger received before the durable drain linearization point cancels drain and returns the same generation to `ACTIVE` after readiness revalidation. A trigger received after `DrainCommitRecord` creates a new activation generation only after the old generation's authority is fenced and its process descendants are terminated or explicitly reconciled. Old and new authority generations never overlap merely to make wake-up appear fast.

```yaml
DrainCommitRecord:
  activation_and_drain_generation:
  last_admission_closed_at:
  lease_and_pending_operation_snapshot:
  authority_epochs_fenced:
  processes_modules_and_store_branches_to_stop:
  wake_during_drain_disposition: cancel_drain | queue_next_generation | reject_stale
  irreversible_stage_and_recovery_owner:
  committed_at:
```

System suspend, hibernate, user logoff and boot-session change close the claimed continuous-observation interval unless the applicable platform sensor proves otherwise. Resume never trusts pre-suspend PID, pipe, UserBrokerEpoch, lease expiry or store lock. Host/Kernel/Watchdog revalidate boot/session identity, generations, cursors, ORS and pending effects before reopening `ACTIVE`; the intervening interval is `replayed`, `partial` or `blind`, never silently continuous.

### Startup

```text
agent bridge / `eliot` CLI / UI / scheduled wake
→ create or join EliotActivationRecord
→ StartService(eliot-host) when required
→ Host starts/reconciles Kernel and requests the independent Watchdog service through SCM as sibling activation branches
→ Kernel reconciles ORS/epochs and starts the canonical-store branch only when needed
→ Host/Kernel verify the current Watchdog supervision epoch and responsiveness
→ derive the actual Governance Profile
→ acquire the applicable RuntimeLease
→ run WorkScope/task/readiness admission
→ start only the remaining capabilities required by the admitted request
→ return the activation/readiness delta to the caller.
```

If Watchdog is unavailable, ELIOT does not claim independent supervision. Read-only or lower-impact work may continue only under the resulting Governance Profile and policy; Material/Critical operations that require independent supervision pause or require the explicit Human risk path. The activation is not reported fully healthy merely because Host and Kernel are alive.

An installed agent shim, hook, plugin or MCP bridge is a demand-start trigger only; it stores no semantic state or authority. If a user runs an unintegrated agent and no observable host event reaches ELIOT, setup/next attach reports the blind interval and no retroactive Watchdog claim is made.

### Runtime, supervision and wake ownership

These three operational objects are distinct and versioned:

```yaml
RuntimeLease:                    # Kernel-owned in ORS
  lease_id_holder_and_reason:
  required_runtime_branches_and_capabilities:
  task_attempt_job_or_effect_refs:
  authority_epoch_and_state_fence:
  issued_at_expires_at_and_renewal_evidence:
  state: ACTIVE | EXPIRING | EXPIRED | REVOKED | RECONCILING | CLOSED
  terminal_disposition:

SupervisionLease:                # Kernel-owned in ORS; signed mirror in Watchdog spool
  lease_id_and_opaque_scope_ref:
  observation_targets_and_sensor_profile:
  claimed_coverage_and_governance_axis:
  issuer_kernel_and_watchdog_epochs:
  issued_at_expires_at_renew_before:
  wake_on_registered_activity_policy:
  state: ACTIVE | EXPIRING | EXPIRED | REVOKED | RECONCILING | CLOSED
  revocation_and_terminal_disposition:

WakeIntent:                      # HostStateJournal; Watchdog may preserve a signed fallback copy
  wake_id_and_idempotency_key:
  reason_and_evidence_refs:
  earliest_start_deadline_and_expiry:
  required_capabilities_and_maintenance_family:
  service_safe_or_user_session_required:
  state_fence_revalidation_and_budget:
  state: PENDING | CLAIMED | STARTED | SATISFIED | CANCELLED | EXPIRED | FAILED
```

A `RuntimeLease` is acquired automatically for an active authenticated UI/CLI/MCP Session, AgentAttempt, Durable Job, upgrade/repair or unresolved external effect. It is renewed only from observable liveness/progress or an admitted wait state; process survival alone does not renew it. Orphaned leases expire and enter reconciliation.

A `SupervisionLease` is issued automatically only for an observable active obligation: an authenticated Session, attached or ELIOT-launched AgentAttempt, Durable Job, protected external effect, active maintenance/recovery/containment operation, or an explicit user `always_on`/between-session supervision policy tied to registered sensors. The mere existence of an installed ELIOT, a registered WorkScope, open Problem, repository on disk or dormant agent configuration does **not** keep Watchdog alive. Human policy selects sensor scope and whether supervision continues between interactive sessions; it does not allow ELIOT to claim coverage without a lease. Watchdog may observe the signed lease but cannot extend it. Before expiry, registered agent/bridge activity or a protected risk causes Watchdog to persist a signed `WakeIntent` and demand-start Host so Kernel can revalidate/renew or close the interval. If renewal cannot be proved, coverage ends at expiry and is reported honestly.

A `WakeIntent` schedules work but never grants semantic authority, keeps the full stack alive by itself or revives an expired lease. On wake, every target, capability, policy, budget and State Fence is revalidated. Stale/resolved intents are cancelled rather than executed because they were once queued.

A lease renewal is a new revision of the same active lease identity and must carry fresh observed evidence; it is not inferred from an alive PID, open pipe or stale heartbeat. `EXPIRED`, `REVOKED` and `CLOSED` are terminal for that lease revision. Resuming work after them requires a new admitted lease/epoch path; no mirror or queued `WakeIntent` can reactivate the old lease. `RECONCILING` permits only exact cleanup/effect/receipt reconciliation named by the lease terminal disposition and cannot admit new semantic work.

### Watchdog wake behaviour while the application stack sleeps

While a valid `SupervisionLease` exists, Watchdog may remain as the only live ELIOT service. It records bounded non-semantic observation envelopes, cursors and coverage gaps in its own spool. It does not write `SystemObservationJournal` or Cognitive Inheritance directly.

```text
authenticated bridge/session/agent heartbeat or protected control event
  → immediate signed WakeIntent + Host demand-start;

critical security/unknown-effect/containment signal
  → immediate Host/Kernel wake or the exact pre-authorized local containment path;

filesystem-only hint under a registered root
  → persist cursor/event and wake only when policy/materiality requires;
  → otherwise reconcile on the next attach/scheduled wake.
```

Demand-start reconciles the Watchdog spool through the Governor-owned journal path before observations can influence memory, policy or task state. Spool pressure narrows claimed coverage; it never turns the spool into a second semantic owner.

When no `SupervisionLease` existed and ELIOT was fully stopped, no live-observation claim is made. The next activation performs `sync-before-think`: it compares exact Workspace/VCS/source/manifests/runtime identities with the last accepted State Fence and, when an admitted OS journal cursor is available, replays its bounded interval. Offline changes become an external world-state delta with `actor/intent = unknown`; they invalidate dependent projections, packets, tasks and leases as required, but are never retroactively attributed to an agent or called governed work.

Open Problem, Incident or Critical Attention do not keep the full stack alive forever merely by existing. Durable state and the persistent inbox survive shutdown. Keep-awake is required only for active containment/repair, imminent escalation, unresolved external effect, observable agent activity or explicit policy. Otherwise a revalidated `WakeIntent` and Human-board item preserve the obligation.

### Idle drain

Idle drain starts only when no `RuntimeLease` remains and no valid `SupervisionLease` requires live sensing/containment:

```text
1. stop new background/model/swarm admission;
2. checkpoint durable jobs and attempts;
3. quiesce optional Modules;
4. flush receipts/outbox and persist/cancel WakeIntents;
5. stop `eliotd` and store bridge;
6. Kernel requests Host to stop the canonical-store process when no data/maintenance lease remains;
7. Watchdog persists observation cursors and stops through SCM when no SupervisionLease remains;
8. Host publishes the clean shutdown manifest, observes child termination and exits.
```

A new observable-use trigger during steps 1–4 normally cancels drain after revalidation; during or after the committed process/authority fence it is queued as the next activation generation. Shutdown never reopens old leases or skips receipt/effect reconciliation. A failed or timed-out drain leaves `DEGRADED_RECOVERY` plus a WakeIntent/manual entrypoint rather than reporting `STOPPED_CLEAN`.

DEFAULT idle grace is five minutes. This is a Config Default, not an invariant.

### Runtime modes

```text
on_demand       — default desktop mode;
always_on       — explicit user policy;
maintenance     — selected curation/backup/meta jobs only;
recovery        — minimal Kernel/Doctor path; normal agents disabled;
offline_export  — store stopped; export/restore only.
```

### Background wake

Windows Task Scheduler invokes a bounded maintenance command only from an admitted `WakeIntent`/policy. The job has budget, deadline and revalidation; ELIOT stops again after completion. Without Human-approved policy ELIOT does not start external models or swarm in the background. When scheduling is disabled or unavailable, the next observable use surfaces one deduplicated manual action instead of silently abandoning maintenance.
