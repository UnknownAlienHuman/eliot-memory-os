## I7.10. Reactive delivery

### Event-integrated host

```text
SessionStart      → identity, scope, task, critical attention, brief architecture context;
PromptSubmit      → classify continuation/correction/interruption/new task; update constraints and invalidate dependent packet;
PreToolUse        → prepared context delta + authority decision;
PostToolUse       → observation, changed resources, diagnostic cues;
PreCompact        → public handoff/checkpoint;
PostCompact       → revalidate and emit resume delta;
Stop              → finish/checkpoint requirement.
```

Hot path contains no model call. Semantic work is prepared asynchronously.

Reactive delivery reuses the single `EventEnvelope` / `EventAckReceipt` owner from I7.2; it does not create a second hook database. One Host Event service owns each append-only source cursor and the durable spool drain. Every captured hook/host event binds event and idempotency identity, principal/session, WorkScope/task/plan revision, raw-or-deterministically-redacted source handle, State Fence and source sequence.

```text
RECEIVED → DURABLE → NORMALIZED → APPLIED | REJECTED | UNKNOWN
```

Cursor advancement occurs only at the declared durable/application phase. Crash, duplicate, predecessor gap, reorder, payload mutation, timeout and cross-scope replay are fault-tested. A restart replays the same logical event identity; it never creates a second semantic observation or silently skips an unresolved predecessor. An advisory hook may disappear without becoming a hidden product dependency; its lost coverage remains explicit in `IntegrationCoverageProfile`.

An interruption that changes the active goal or invalidates the current plan creates a durable `InterruptBarrier` task event/projection. It marks old branches `paused`, `killed` or `completed`, records forbidden resumptions, revokes incompatible leases and requires a fresh packet before Material continuation. A later resume must reference the barrier and current State Fence; conversational momentum cannot silently reactivate the old plan.

### Tool-only host

```text
boot/pending context piggybacks on ELIOT responses;
unsupported enforcement is marked advisory;
material actions not seen by ELIOT remain ungoverned;
finish cannot be VERIFIED_COMPLETE when required trace is absent;
Watchdog observes interaction gaps where possible.
```

System never claims it blocked an external action it could not intercept.

