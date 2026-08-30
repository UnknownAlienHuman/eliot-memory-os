## I18.27. Oracle ownership and test-change governance

Every acceptance oracle has an owner and origin:

```text
Architecture/Implementation contract;
external standard or exact source;
accepted Human/domain decision;
registered deterministic evaluator;
previously accepted artifact baseline;
```

A test author may encode the oracle but cannot create its authority by assertion. Changes to implementation and oracle in one candidate are split unless the oracle is mechanically derived from the same unchanged source. When split is impractical, blind reviewer verifies the oracle delta before implementation result is considered.

Tests may be wrong. A false block creates a `TestOracleProblem`, preserves the conflicting observation and permits scoped deviation; it does not encourage hidden bypass or permanent weakening.

