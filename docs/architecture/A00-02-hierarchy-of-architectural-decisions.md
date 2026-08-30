## A0.2. Hierarchy of Architectural Decisions

| Class | Meaning |
|---|---|
| **Architectural Intent** | The ultimate goal and rationale; the primary guide under conflict |
| **Theory** | An explanation of cognition, memory, resilience, and learning; it does not impose one mechanism |
| **Invariant** | A property a healthy system preserves or restores over its trajectory |
| **Hard Boundary** | A narrow boundary around authority, secrets, irreversible effects, proof, or canonical integrity; enforced fail-closed |
| **Contract** | An observable capability obligation; degradation under failure must be explicit |
| **Guardrail** | A preferred defense against a known error class; challenge and scoped deviation remain possible |
| **Default** | The currently preferred mechanism; replaceable without changing Intent |
| **Policy** | A governed human decision about privacy, risk, cost, models, or operations |
| **Experiment** | A reversible hypothesis test with an evaluator, stop condition, and rollback |
| **Empirical Profile** | Versioned knowledge about a specific model, harness, toolset, and workload combination |
| **Metric** | A measure of a property that must not become the system's objective |
| **Example** | An illustration with no independent normative force |

`ARCH-*` entries are durable **decision anchors**. They restore meaning and support the conformance map, but must not turn every working boundary into ceremony. Normative force does not follow from words such as "must" alone; it follows from the decision class, rationale, and observable property. A listed mechanism is not permanent unless it is a Hard Boundary.

An Invariant is evaluated over a trajectory. A temporary error is tolerable when it is:

```text
detected;
localized;
not granted hidden authority;
recorded as evidence;
covered by recovery or honest escalation.
```

