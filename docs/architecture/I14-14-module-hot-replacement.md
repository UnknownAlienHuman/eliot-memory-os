## I14.14. Module hot replacement

### Artifact layout

```text
modules/<module_id>/<semver>/<artifact_hash>/
  module.exe
  module.toml
  signatures/
  symbols/
  contracts/
  test-receipts/
```

Running artifacts are immutable. Active generation is registry state.

### Upgrade sequence

Cutover applies to a declared `CapabilityRouteScope` (module + capability + affected WorkScope/effect domain). It does not pretend that every operation in the process changes owner at one instant.

```text
1. package and verify immutable candidate;
2. validate protocol/dependency/license/state-class compatibility;
3. start candidate with no effect authority;
4. restore/checkpoint/rebuild according to ModuleStateClass;
5. run readiness plus shadow or isolated canary;
6. quiesce new admissions to the old route scope;
7. classify every in-flight request and persist a GenerationCutoverRecord in ORS;
8. commit one ORS cutover transition:
     active route for new admissions = candidate;
     new Authority Epoch = issued;
     old general generation authority = fenced;
     exact allowed old-operation dispositions = fixed;
9. atomically swap the in-memory route snapshot from that committed record;
10. drain/reconcile old operations, publish GenerationCutoverReceipt,
    retain rollback artifact and retire the old generation.
```

`GenerationCutoverRecord` and its operational `GenerationCutoverReceipt` are owned by Kernel/ORS. Canonical Memory may later record a referenced observation/audit event, but it never becomes the owner of the active generation or cutover machine.

The ORS commit is the durable linearization point. Crash before it leaves the old route active. Crash after it reconstructs the candidate route and fences from the committed record before accepting work. Rollback is another cutover with a newer epoch; an old epoch is never reactivated. Candidate failure before the linearization point leaves the old generation active. Irreversible state migration requires forward repair or a separately proven rollback path.

### In-flight disposition

Every accepted request records ModuleGeneration, operation identity, impact/effect set and State Fence. At cutover it receives exactly one disposition:

```text
drain_read
  → read/stream may finish while its input fence remains valid;

finish_exact_authorized_operation
  → only the already admitted operation may finish under a committed
     `OperationContinuationPermit`; this is not general old-generation authority;

checkpoint_transfer
  → candidate resumes from a compatible checkpoint under a new attempt/generation receipt;

cancel_proven_no_effect
  → cancellation is accepted only when no external/canonical effect is proven;

block_scope_unknown_outcome
  → outcome is unresolved; conflicting new effects in the affected scope remain blocked
     until receipt/probe/reconciliation resolves it.
```

An unfenced external effect may not silently cross cutover. If the old process has already issued it, the committed cutover may create one non-renewable `OperationContinuationPermit` bound to operation ID, effect hash, old generation/epoch, exact scope, deadline and allowed completion messages. Kernel/store/tool boundaries accept the old epoch only with that permit; it cannot create child effects, widen scope, migrate to another process generation or authorize retry. Final OutcomeReceipt consumes/closes it. Old-process loss before a final outcome becomes `UNKNOWN_OUTCOME`; the permit is not reissued. If the effect has not been issued, the operation is checkpointed or cancelled with no-effect proof. Unrelated scopes may switch and continue.

### Request pinning

```text
shadow/canary
  → evidence only unless isolated effect scope is explicitly granted;

new request after cutover
  → candidate generation and new epoch only;

old request not listed in the committed cutover record
  → rejected as stale;

retry
  → follows operation identity/receipt and its disposition,
     never merely the newest generation.
```

Exactly one generation owns **new** effect admission for a CapabilityRouteScope. A bounded allowlist of pre-cutover operation identities may finish only as declared above. `GenerationCutoverReceipt` records old/new generations and epochs, route-scope hash, state migration, all in-flight dispositions, linearization record, health proof, rollback boundary and unresolved scopes.

