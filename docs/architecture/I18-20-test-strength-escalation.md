## I18.20. Test-strength escalation

Test strength is investigated only when risk or evidence justifies it:

```text
1. base/candidate red-green or fault reproduction;
2. changed-line/function coverage on affected scope;
3. selected mutation on critical logic;
4. fuzz/model-check/formal proof on narrow boundary.
```

Coverage proves execution, not correctness. Mutation survivors indicate oracle weakness, not automatically a product bug. Expensive stages are bounded and never default to the entire workspace.


For authority, security, recovery, ordering and prior escaped-regression fixes, the discriminator must also prove that it can fail on the old mechanism (`test-the-test`). At least one applicable method is selected:

```text
merge-base or frozen pre-fix fixture;
mutation/reverted implementation fixture;
feature flag that disables the fix;
modelled bad implementation;
fault injection reproducing the pre-fix boundary.
```

The evidence records the exact old causal branch, the negative mutation and the failure produced. A green test that was never shown to reject the old path has a lower proof ceiling.

Fault points are placed around every irreversible or split-outcome boundary that the changed mechanism owns, including:

```text
before/after authority activation;
after external effect before receipt;
after canonical commit before outbox delivery;
after artifact write before manifest publication;
after old generation fence before new readiness;
after purge before backup/purge-ledger update;
after stage output before stage receipt;
during resource parking/reacquisition;
during partial multi-site transform or generated patch.
```

Multi-site compiler/translation/generated-code transforms declare their expected consumer set, validate every target before mutation, apply into a new immutable generation and post-scan for residual legacy branches. Partial patching fails closed or uses the explicit generic/degraded path.

