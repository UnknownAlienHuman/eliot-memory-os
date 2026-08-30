## A0.6. Changing the Architecture

```text
recurring problem or new fact
→ concise statement of the violated Intent
→ evidence and alternatives
→ Implementation and migration consequences
→ Architecture Owner decision
→ change to the main text.
```

The Implementation may refine concrete contracts and defaults while preserving Intent, Hard Boundaries, and observable behavior.

A **Recoverable Deviation** is permitted: a temporary, scoped departure from a Guardrail or Contract when useful progress requires it and no Hard Boundary is crossed. It has an owner, reason, affected scope, review condition, rollback, and outcome. A successful deviation becomes evidence for correcting the rule; a failed one becomes negative memory.

Append-only addenda with implicit precedence and permanent exceptions without an owner or review are prohibited.

