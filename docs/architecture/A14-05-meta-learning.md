## A14.5. Meta-Learning

Learning begins inside the execution loop. Meta does not create learning from nothing; it decides which already observed local learning deserves broader and more durable influence. There are therefore two loops.

### Inner Loop — Learning During Work

Runs inside an active task: fast, local, and reversible.

```text
attempt
→ trace, outcome, and applicable verifier
→ attribution: which mechanism explains the result and with what ceiling
→ task-local delta to strategy, context, procedure, or route
→ delta admitted to the current overlay
→ next compatible attempt compiled with that delta
→ activation, adherence, decision delta, and outcome become observable.
```

This loop changes only task-local state with a bounded blast radius and explicit rollback. It does not change the goal, acceptance criteria, authority, privacy, cost ceiling, evaluator, sealed holdout, production generation, or its own promotion decision.

After material new evidence appears, another materially equivalent attempt is inadmissible without an explicit reason. Valid reasons include stochastic replication, noise estimation, exact defect reproduction, controlled comparison, recovery proof, and verifier calibration. "Try again" is not a reason. When no strategy change is justified, the system records an evidence-backed no-change or exhaustion disposition rather than repeating the path.

### Outer Loop — Consolidation and Promotion

Runs across tasks, more slowly and on stronger evidence:

```text
recurring or high-value local delta
→ scoped Improvement Candidate
→ isolated candidate, fixed replay, shadow, or canary
→ held-out, retention, claimed transfer, and Product Pulse
→ promote, narrow, reject, or roll back.
```

A problem is not the only trigger. Learning must also follow an unexpected success, a cheaper alternative route, correct abstention, useful environment discovery, effective decomposition, correct verifier selection, successful transfer, or discovery that a procedure is unnecessary.

An Improvement Candidate contains evidence, validity scope, owner, expected delta, risk, rollout, rollback, and stop condition. Advice may be immediate, task-level, system-level, or architecture-level.

By default, Meta advises the Main Agent or Human. A change is prepared as a separate candidate in an isolated Experimental Contour, tested on fixed replay and affected proofs, and then, when needed, passed through shadow or canary and reversible cutover. The active generation remains immutable until governed promotion. Only preauthorized, local, reversible tuning changes with canary and rollback may apply automatically.

The Meta loop itself is evaluated by verified delta, activation, adherence, adoption, regressions, false positives, noise, cost, and Product Pulse impact; useless advice is demoted or archived. Code, schema, authority, verifier definitions, privacy, Architecture, and destructive forgetting never change automatically.

**ARCH-META-01 — Self-improvement is advisory, isolated, and falsifiable.** ELIOT improves from evidence of real work through candidates, replay, shadow or canary, and rollback—not by confidently rewriting the active system.

