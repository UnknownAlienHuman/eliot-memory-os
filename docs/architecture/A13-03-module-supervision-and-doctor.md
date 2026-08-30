## A13.3. Module Supervision and Doctor

A Module lifecycle supports:

```text
start;
health and readiness check;
quiesce or drain;
checkpoint;
restart or rebuild;
replace or roll back;
quarantine;
retire.
```

Replacement:

```text
stop new work
→ checkpoint or drain
→ fence the old Authority Epoch
→ replace
→ health and evaluation
→ resume or roll back.
```

Normal promotion path for an experimental capability:

```text
contract and conformance
→ recorded replay
→ effect-free shadow
→ bounded canary
→ active generation
→ drain and retire or forward rollback.
```

A shadow performs no external effect and changes no canonical state, scheduling, policy, or memory influence; it produces divergence evidence. Promotion into a more integrated or hot-path contour requires not only correctness, but measurable benefit, a compatible failure envelope, and demonstrated rollback. Last-known-good means compatible with durable formats, policy, and recovery state—not merely a generation that once started successfully.

Doctor operates from the Module Registry, Problem State, Diagnostic Brief, and registered repair recipes. Doctor itself is an ordinary supervised Module: the Host Supervisor may restore its last-known-good build, and repeated failure escalates without asking Doctor to "heal itself."

Repair classes:

```text
automatic-safe — idempotent restart or reconnect, cache or index rebuild, stale-session cleanup;
guarded — configuration, credential, integration, schema or data repair, and cutover through approved recovery intent and canonical transition;
diagnose-only — corruption, unknown ownership, unclear external effect, or repeated failure.
```

Doctor never writes canonical state directly. It forms a repair intent, performs only the authorized infrastructure effect, and returns evidence; the applicable semantic transition is performed by the Governor or Kernel recovery boundary.

A repair has an attempt budget, cooldown, verification, and receipt. Once the budget is exhausted, automation stops, the Module is quarantined, and the problem escalates.

**ARCH-RES-02 — Self-repair is bounded and verified.** Doctor neither guesses indefinitely nor becomes a second writer.

