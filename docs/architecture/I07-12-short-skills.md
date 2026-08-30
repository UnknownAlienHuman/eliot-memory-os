## I7.12. Short Skills

### Core Skill

```text
Solve the task; use the current ELIOT task view as state.
Refresh before a Material effect when the view is stale or the goal, scope or load-bearing state changed.
Record material observations, decisions, failures and outcomes unless ELIOT already acknowledged them; follow its retry identity.
Report missing, stale, wrong-scope, irrelevant or excessive context through the supplied feedback handle; do not manufacture positive feedback.
Separate observation from inference.
Follow typed directives; challenge a false block with evidence or escalate.
In degraded mode do only work the directive explicitly permits.
Use `eliot.finish`; only `VERIFIED_COMPLETE` means done.
```

### Memory Skill

```text
Record meaning the bridge cannot infer while context is fresh.
State what happened, why it matters and when it may matter again.
Unknown type never blocks safe capture.
```

### Conflict Skill

```text
Do not vote or overwrite.
Preserve rival claims and shared lineage.
Run the cheapest safe test that distinguishes them.
Name the decision owner and residual uncertainty.
```

### Failure Skill

```text
Do not repeat an exact failed path without new evidence.
Change the hypothesis, route or precondition.
Record the new outcome and reopen condition.
```

### Development Skill

```text
Optimize the Product Objective, not reports, test counts or forms.
Work in one primary micro-module and one causal property.
Before code, run or define the discriminator that can refute the hypothesis.
Run the module proof and affected edge proof; do not run the full suite without impact evidence.
Do not repair unrelated paths or change the oracle to fit the patch.
A second repair of the same failure class requires a new hypothesis or Mechanism Review.
Treat tests, receipts and reports as evidence only.
Challenge a harmful guardrail openly; never bypass a Hard Boundary.
Claim only the exact scope actually proven.
```

Host-specific skill adds only host limitations and exact tool names. Skills do not restate Architecture.

Skill context is paid at three separate points and each has its own budget:

```text
index     name and one-line trigger description of every route/profile/policy-eligible Skill;
          paid every session for that eligible catalogue;
body      the Skill instruction itself; paid on activation; kept intent-dense;
runtime   references, scripts and assets; paid only when actually read or executed.
```

The trigger description states **when to load**, not what the Skill can do; it is evaluated by activation precision, activation recall and forbidden activation. A verbose body is not a local cost: several Skills may be active at once, so one oversized Skill degrades unrelated capabilities. Adding a Skill can regress another Skill without modifying it, which is why the catalogue is evaluated as shared behavioral surface rather than as isolated documentation (I7.25).

