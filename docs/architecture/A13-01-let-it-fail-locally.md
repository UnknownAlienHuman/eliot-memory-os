## A13.1. Let It Fail Locally

ELIOT follows **let it crash**, but never treats it as indifference to data.

```text
a process or agent may die;
an operation may finish partially;
a Module may be quarantined;
a model result may be wrong;
a queue may reject work.
```

The following must survive failure:

```text
canonical history;
confirmed artifacts and evidence;
ownership and State Fences;
independent work;
Problem State;
recovery entrypoint;
the ability to continue or stop honestly.
```

Resilience has three distinct goals: operational resilience preserves processes, state, and effects; epistemic resilience does not turn missing data into false certainty; cognitive resilience preserves goals, alternatives, commitments, and the ability to continue inquiry.

**ARCH-RES-01 — Fail locally, recover globally.** Failure of an optional capability reduces capability rather than destroying all of ELIOT.

