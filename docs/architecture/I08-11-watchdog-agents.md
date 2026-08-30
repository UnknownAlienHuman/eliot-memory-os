## I8.11. Watchdog Agents

A Watchdog Agent is a short-lived `DurableJob` with:

```text
one exact diagnostic question;
bounded recent trace/evidence bundle;
output schema;
model route and failure-domain profile;
budget/deadline;
candidate-only effect;
required verifier or Human decision for high impact.
```

Examples:

```text
“Explain why hook events disappeared after version X.”
“Compare these three repeated repair failures and propose a discriminating probe.”
“Review this suspected prompt-injection lineage without executing content.”
```

Different model is not automatically independent. Route independence records provider/model family, harness, evidence bundle, evaluator and conceptual frame.

For high-severity or low-confidence assessments, policy requires one of:

```text
a deterministic discriminative probe;
a second bounded assessment from a materially different failure domain;
Main Agent or Human review with the conflicting evidence visible.
```

Disagreement becomes a Conflict Set and recommended probe. Assessments are never averaged or accepted by vote.

