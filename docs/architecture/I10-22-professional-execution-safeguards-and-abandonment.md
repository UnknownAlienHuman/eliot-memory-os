## I10.22. Professional execution safeguards and abandonment

Professional work has three independent owners:

```text
Task/Domain owner — method, goal, acceptable substitutions and deliverable;
bridge/environment owner — software/process capability and observed effects;
evaluator owner — measurement contract and reference isolation.
```

The same agent may perform several roles only when the Evaluation Contract permits it; shared reference or self-judging limitations remain visible.

`PrematureAbandonmentSignal` is raised when an attempt stops, reports success or changes approach while a required deliverable, verifier or declared workflow boundary remains unresolved. It does not force continuation: the Task Controller may reframe, supersede, accept partial work or ask the Human, but the missing artifact cannot disappear from state.

Approach changes are recorded as a new revision with rationale, preserved partial artifacts and impact on acceptance. A bridge may suggest a fallback application or file format; it cannot silently substitute one.

