## I1.8. Exact ownership and call paths

### One logical Governor, two internal checks

Kernel + `eliotd` form one logical Governor. Responsibilities are deliberately split:

```text
eliotd
  interprets semantic command, task/scope state and proposes PreparedTransition;

Kernel
  verifies identity, authority, State Fence, idempotency, ordering and runtime generation;

store bridge
  persists only a named, already prepared transition atomically.
```

No component alone can invent semantics, authorize them and commit them. This is a two-check implementation of one authority, not two writers or two policy owners.

`eliotd` and Kernel may not evaluate different semantic snapshots. `eliotd` emits the single canonical `PreparedTransition` defined in I5.6. Across the `eliotd`→Kernel→store boundary its load-bearing identity consists of the operation and canonical-request identities, admission decision digest, semantic source revisions, State Fence, Authority Epoch, Ordering Scopes, transition class, exact mutation-plan digest and required store-contract version.

Kernel rechecks only properties it owns and binds the activation/staging receipt to the same `admission_decision_digest`. Store commit and `WriteReceipt` repeat that digest. A digest, source-revision or mutation-plan mismatch returns `TRANSITION_DIGEST_MISMATCH`/conflict and never retries as the same decision.

### Session attach

```text
agent bridge
→ Kernel authenticates local process/profile and transport generation
→ eliotd resolves principal, WorkScope and task
→ Kernel issues generation-bound Session token
→ agent receives bootstrap/state handles.
```

Session exists only while transport identity and semantic Session refer to the same State Fence/epoch.

### Read path

```text
agent/UI/module
→ Kernel validates principal/session/read capability
→ eliotd selects Q0–Q5 contract and role-filtered projection
→ in-memory snapshot or named store read
→ result with revision/freshness/provenance.
```

For hot reads Kernel may issue a short-lived `NamedReadCapability` directly to `eliotd`. It binds exact named query, principal/role, scope, State Fence, payload cap, expiry, daemon generation and audit identity. Store bridge accepts no generic query and no write under this capability.

### Canonical write path

```text
agent/module/tool observation
→ eliotd semantic admission and PreparedTransition
→ Kernel mechanical authority/fence/idempotency/order validation
→ ORS staging and Ordering Scope reservation
→ named store transaction commits events/projections/relations/WriteReceipt/outbox row atomically
→ ORS reconciliation
→ outbox dispatch
→ caller notification.
```

Doctor, Dreamer, Watchdog, Modules and surfaces submit observations/candidates/intents through this same path. Writes have no direct-read shortcut.

### External effect path

```text
ActionContract + authority
→ bounded tool/module attempt
→ AttemptReceipt
→ observed side effects/artifacts
→ verifier/reconciliation
→ OutcomeReceipt
→ optional semantic transition.
```

Canonical commit and external effect are separate proof objects.

### Recovery path

```text
Watchdog/Kernel/Host detects failure
→ non-semantic intent/fence in Watchdog spool or ORS
→ Host/Kernel starts compatible generation
→ Doctor may execute registered repair effect
→ logical Governor reconciles canonical/external state
→ verifier resolves or escalates Problem State.
```

