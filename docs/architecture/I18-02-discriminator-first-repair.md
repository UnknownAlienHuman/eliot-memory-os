## I18.2. Discriminator-first repair

For a confirmed bug or regression:

```text
1. capture exact failing path, state and identity;
2. state causal hypothesis and at least one rival when material;
3. create the cheapest discriminator that fails on old behavior;
4. implement one Causal Change Unit in one primary FunctionalCapabilityCell and its bounded source packages;
5. run module proof and affected contract-edge proof;
6. run selected live/product proof when the property crosses a real boundary;
7. record outcome and update FailureFingerprint, Skill/Guardrail or Improvement Candidate.
```

A second repair of the same class cannot add another field escape, timeout, wrapper or compatibility branch without Mechanism Review.

No-zero-test rule:

```text
runner records discovered, selected and executed counts;
expected nonzero group with zero execution is failure;
wrong package/feature/target/worktree is harness failure, not product pass;
missing output or parser incompatibility is unknown/failed evidence, not green.
```

