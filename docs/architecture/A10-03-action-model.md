## A10.3. Action Model

A Material or Critical action requires a sufficient external model:

```text
intent and affected scope;
preconditions;
expected effect or observable;
invariants and known failures;
rollback or compensation;
verifier;
stop or revision condition.
```

Existing state may assemble it automatically. The Architecture does not require a ritual essay from the agent. Decision rationale, alternatives, and revisit condition are recorded at the decision boundary; a later explanation is stored as a retrospective hypothesis, not as the original reason.

Contract depth forms a gradient:

```text
Primitive — observation, read, or reversible probe;
Standard — Material action with scope, expected outcome, and verifier;
Deep/Audit — Critical, novel, or highly ambiguous work with rivals, independent challenge, and recovery plan.
```

Depth follows impact and uncertainty, not a habit of writing the maximum contract for every command.

