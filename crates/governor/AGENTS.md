# Governor source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_router.py route --path <repository/path> --topic "<causal property>"
```

Read every fragment marked **required**, then record the emitted receipt in the
work unit or pull request. Optional fragments are loaded only when the current
decision crosses their stated boundary. A legacy `ELIOT_*` compatibility map is
never an acceptable reading receipt.

If no non-baseline route matches, stop the mutation and add or obtain a route;
silence is not permission. See [`../../docs/architecture/READING_PROTOCOL.md`](../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


This subtree owns semantic application behavior behind the current `eliotd`
composition root. It does not own Host/Kernel process truth, ORS, database
vendor mechanics, user-session credentials, or model/provider implementation.
Issue #18 is the integration owner; #13 owns executable cell/proof metadata.

## Work discipline

Before mutation, start from current `main`, read the nearest instructions and
owning open issue, create one issue-numbered branch and one PR, and keep one
mutable path writer. Stop when current `main` is not an ancestor or another
writer owns the path.

## Owned semantics

- WorkScopes, tasks, plans and current semantic position;
- semantic admission and immutable `PreparedTransition` construction;
- coordination, Problems/Conflicts/Attention and Module Catalog intent;
- context/evidence admission decisions;
- strict completion derivation from current contracts and executed evidence.

## Hard boundaries

- Emit one canonical, versioned `PreparedTransition` containing exact semantic
  revisions, admission digest, MutationPlan digest, ordering scopes, fence,
  epoch/effect ceiling, transition class, named store-operation manifest and
  proof/approval handles.
- Kernel may mechanically recheck that object; the store bridge may execute it.
  Neither downstream layer may rebuild or reinterpret the semantic decision.
- No SurrealDB SDK, raw query/upsert, Host journal, Job Object/process lifecycle,
  ORS ownership, user credential materialization, or direct provider process
  launch.
- Caches/read models are revision/fence keyed and rebuildable. They cannot make
  state fresh, preserve authority after generation loss, or act as unreceipted
  writes.
- Only current TaskContract + exact artifact/run/verifier evidence + reconciled
  effects can produce `VERIFIED_COMPLETE`. Model/agent self-report, local return
  success or stale proof is insufficient.
- Dreamer/Researcher/model outputs remain candidates until normal admission.
- Do not migrate broad behavior from legacy `eliot-app` unless a current
  consumer and target owner are proved under #18.

## Proof and stop condition

Changes require a deterministic semantic contract fixture and the affected real
Kernel/store/surface edge. Admission/digest/finish changes require shared
negative fixtures across `eliotd`, Kernel and store bridge plus the applicable
#11 Product Pulse.

Stop when requested code needs process generation, vendor-store execution,
credential handling, provider implementation, recovery mechanics, or a second
semantic/state owner.
