## I10.23. MessagingBridge

`MessagingBridge` is an optional user-channel adapter contract over existing ELIOT principals, Sessions, tasks, Human Control, mailbox/outbox and delivery receipts. It does not own task semantics, memory, schedule, approval authority, route policy or completion. Local UI/CLI operation remains available when every messaging adapter is absent.

```yaml
MessagingBridgeProfile:
  bridge_generation_platform_and_adapter_fingerprint:
  enrolled_principal_binding_and_access_policy:
  chat_thread_session_task_and_workscope_binding:
  negotiated_capability_profile:
  inbound_media_contract:
  outbound_delivery_contract:
  session_command_surface_and_version:
  approval_and_attention_surface:
  scheduled_delivery_target_ref:
  canonical_outbox_and_sink_receipt_projection:
  reconnect_replay_duplicate_and_freshness_policy:
```

A platform account, chat or thread is a transport locator, not an ELIOT principal or Session. Enrollment binds the exact platform identity fingerprint to an existing principal under revocable access policy. Every inbound turn resolves an explicit Session, WorkScope and Task or creates a typed `OperatorIntentCandidate`; transport reconnect does not infer continuity from chat history alone. Platform message/update identity plus adapter generation and principal binding form one replay-safe inbound event identity, so webhook/polling duplicates cannot create a second task or approval.

Commands compile to typed existing operations such as session create/resume/status/stop, approval/denial, route selection, automation inspection and Skill invocation. A command never exposes a generic shell/database path or bypasses its owning contract. Approval binds the exact action/effect digest, scope, State Fence, Authority Epoch, principal and expiry; `/approve` is not session-wide authority and a replay after expiry or revision change is rejected.

The capability profile is negotiated and evidenced per adapter generation: text limits, threads, editing/streaming, reactions, inbound/outbound media, file size/type, idempotency keys, acknowledgement/readback and duplicate behavior are never assumed. Unsupported capability yields an explicit degraded result or another Human surface; it is not silently emulated with weaker guarantees.

Inbound files/media are admitted through `SourceAdmissionPolicy`, privacy scanning and Blob Store as immutable handles before model/tool exposure. Outbound files/media resolve from immutable artifact handles through disclosure closure and recipient policy; a local filesystem path is never sent as if it were the artifact. Revocation stops future delivery where enforceable and preserves the historical delivery receipt.

The “durable delivery ledger” is a read model over the canonical outbox row and sink-owned phases from I5.21, not a second store or lifecycle owner. The logical message binds principal, chat/thread target, task/result/artifact refs, adapter generation, disclosure decision, freshness window and stable sink operation identity.

Crash/reconnect behavior is exact:

```text
result committed and send not started
  → the existing outbox item is claimed and delivered after restart;

send started and acknowledgement/readback lost
  → sink state remains UNKNOWN and is reconciled by platform idempotency/readback;

no reconciliation surface and policy chooses at-least-once resend
  → create a new marked delivery attempt for the same logical message,
    expose possible_duplicate, preserve the old UNKNOWN attempt and freshness limit;

in every case
  → never re-execute the agent turn, model call, tool call or task effect merely to deliver.
```

Scheduled delivery is authored by `UserAutomation` or another existing Durable Job owner and committed through the outbox; the bridge only validates the target and performs delivery. Delivery, recipient acknowledgement, task completion, approval resolution, public use and outcome-helpfulness remain separate observations. A delivered “done” message cannot close a task, and a completed task is not represented as delivered until the sink receipt says so.

Telegram is the first implementation `Experiment`, not a core dependency. Promotion to a Default requires Product Proof of principal/session binding, text plus file delivery, restart between result commit and send, visible unknown/duplicate handling, access revocation and non-reexecution of task effects. A second adapter is admitted only after the same common-contract proof, so adapter count cannot substitute for reliability.

---

