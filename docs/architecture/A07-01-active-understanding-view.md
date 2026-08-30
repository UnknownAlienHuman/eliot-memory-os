## A7.1. Active Understanding View

A view is compiled for a specific `model × task × harness × tools × inference regime`.

Semantic order:

```text
goal, acceptance, and commitments;
blocking attention;
current epistemic position and rivals;
semantic and causal model;
done, open, deferred, and killed work;
invariants and negative memory;
unknowns and inquiries;
exact load-bearing evidence;
available and authorized affordances;
next action, expected observable, verifier, and stop condition.
```

A view uses one applicable State Fence or explicitly marks stale or incompatible sections.

At an action boundary, the system creates a concise **decision-local tail**: current goal, load-bearing position, exact atoms, do-not-use items, next action, expected observable, verifier, and stop or revision condition. Its layout is validated against the Effective Context Profile rather than frozen as permanent prompt magic.

**ARCH-CTX-01 — Decision sufficiency before size optimization.** Context must preserve distinctions that could change the decision, risk, verifier, or unknowns.

