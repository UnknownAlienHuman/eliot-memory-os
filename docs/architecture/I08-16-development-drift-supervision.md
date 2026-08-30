## I8.16. Development drift supervision

Watchdog observes not “code correctness,” but signs that local proxies have displaced the product objective:

```text
growth in commits, tests, or reports without new product evidence;
repeated repair of one failure class without a new hypothesis or discriminator;
PASS with zero tests actually run;
a local green result against stale or different source, configuration, or installed generation;
frequent status or certificate prose while blockers remain open;
branch/worktree/install/DB/docs identity divergence;
a large cross-owner diff without one named causal property;
a repeated error that produced no FailureFingerprint, discriminator,
or Improvement Candidate;
activity continues, but the agent stops reporting observations and outcomes.
```

Watchdog creates a `DevelopmentDriftSignal` and Diagnostic Brief. Repeated repair is keyed by a normalized `FailureClassIdentity` derived from affected property, actual owner and path, violated invariant, observable symptom, and failing boundary—not by test name or prose label. The deterministic detector does not declare agent intent, reward hacking, or root cause as fact. Dreamer or an auditor may propose explanations; Task Controller or Human decides whether to narrow work, require Mechanism Review, change route, or continue.

---

