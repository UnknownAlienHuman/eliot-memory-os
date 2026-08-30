## I7.15. Route Continuation and transfer

Continuity is the closed `ContinuityKind` enum for the current protocol line:

```text
NativeResume — same compatible runtime/route continues the same native session;
NativeFork   — runtime creates a child/branch with native history semantics;
Replayed     — ELIOT replays durable public messages/events into a new attempt;
Rehydrated   — a new attempt receives compiled state/artifacts without prior dialogue;
Fresh        — no prior conversational state is transferred.
```

Only `NativeResume` preserves native session identity. Every other kind creates a new ELIOT attempt. `NativeFork` remains a child attempt even when the runtime calls it a continuation.

Route Continuation State may contain opaque provider/harness continuation required for exact resume. It is:

```text
separate from canonical cognitive inheritance;
never evidence, authority or rationale;
not indexed or sent to another route automatically;
protected by privacy/retention;
scoped to exact runtime/adapter/route fingerprint;
deleted on expiry, route invalidation or provider-policy request.
```

Cross-runtime transfer defaults to `Rehydrated` and uses a sealed packet:

```text
task/acceptance and current plan;
Current Epistemic Position and Architecture constraints;
base/diff/environment receipts;
artifacts and exact evidence handles;
failed paths and reopen conditions;
open unknowns, permissions, budgets and output schema.
```

A native transcript, reasoning signature, tool-call ID or compaction summary is not portable. `Replayed` re-emits only public messages/events as inert context; it never re-executes prior tool calls or external effects. UI and reports must not label replay/rehydration as “the same session”.

Every non-fresh transfer is bound by one `HandoffCausalLink`:

```yaml
HandoffCausalLink:
  source_attempt_session_and_revision:
  source_state_fence_and_authority_epoch:
  source_event_and_outbox_cursors:
  in_flight_operations_and_effect_dispositions:
  handoff_checkpoint_and_omission_manifest_digest:
  replay_from_cursor_or_rehydration_bundle_digest:
  target_attempt_and_route_fingerprint:
  post_resume_revalidation_receipt:
  completeness: COMPLETE | PARTIAL | STALE | UNKNOWN
```

Resume/replay is not admitted as causally continuous when the source revision, fence/epoch, cursor, omission manifest or effect disposition is missing or stale. The target may start as a new `Rehydrated` attempt with explicit unknowns, but it cannot inherit completion, authority or proof from an incomplete link.

