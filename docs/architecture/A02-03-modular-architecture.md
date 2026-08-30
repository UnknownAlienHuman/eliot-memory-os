## A2.3. Modular Architecture

```text
0. Kernel
   identity, authority, fencing, canonical transition boundary,
   control scheduling, health, and recovery entrypoint.

1. Canonical state
   Memory OS, tasks, evidence, relations, history, receipts, and durable jobs.

2. Instrumental intelligence
   truth adapters, verifiers, code and dependency graphs, logs, and artifact inspection.

3. Cognitive intelligence
   Understanding State, Context Compiler, Dreamer, semantic curation, and calibration.

4. Harness and orchestration
   agent and tool gateway, swarm, work graph, leases, and result aggregation.

5. Surfaces
   agent protocols, Skills, ControlBoardView, Human interface, and reports.

External supervision
   Watchdog in a separate failure domain.
```

Functional layer, source boundary, runtime process, and deployment unit are separate dimensions. Many independently developed Modules do not require the same number of processes, services, or state owners. The Kernel supports all four functional planes without containing their depth. Canonical state primarily serves Memory OS and Harness; the instrumental and cognitive layers serve Smart; Watchdog, Doctor, and learning loops serve Meta. The Kernel owns the logical lifecycle and fencing of Modules; the external Host Supervisor performs the physical lifecycle of approved generations and remains available when the main process fails.

**Micro-modularity** means a material capability can be isolated as a bounded cell with:

```text
one causal responsibility and one lifecycle owner;
an explicit public contract, inputs, outputs, and owned mutable state;
allowed effects and an authority boundary;
typed dependency ports and one-way dependency direction;
an independent proof surface;
failure, replacement, migration, and removal boundaries.
```

A Micro-module may be a source module, package, sandboxed component, process, service, or remote worker. The Architecture does not prescribe its physical form. Internal dependencies of a material capability follow these layers:

```text
contract
→ domain or pure core
→ ports
→ adapters
→ service or lifecycle
→ agent or human surface.
```

This is a direction of responsibility, not a required directory layout. The core does not depend on a specific vendor, transport, store, sandbox, or UI; adapters gain no right to decide task truth, policy, or finish.

The Architecture sets no maximum size, line count, token count, file count, package count, or Module count. The current need for smaller causal worksets follows from model-context limits, parallel agent development, and failure localization. Split or merge decisions depend on the Effective Context Profile, dependency fan-out, build and test cost, failure isolation, replacement cost, and Product Pulse. Better models may permit larger units; observed drift may require further separation without changing the Architecture.

A new or materially changed capability first runs in the least-privileged **Experimental Contour** sufficient for its function:

```text
bounded sandboxed component — pure, capability-limited logic;
isolated worker — OS, tool, credential, or resource-heavy work;
integrated runtime generation — only after demonstrated benefit with equivalent conformance and recovery guarantees.
```

The Implementation selects concrete technologies. No contour is a mandatory maturity ladder: a capability may remain isolated permanently when that is simpler and sufficiently efficient. Promotion proceeds through contract and conformance, replay, effect-free shadow, bounded canary, active generation, drain and retire, or forward rollback. A published generation is immutable; an active Module does not rewrite itself in place.

The hot path contains only bounded, observable, and sufficiently stable operations over compatible state. Model reasoning, research, compilation, broad indexing, heavy verification, and curation run outside the synchronous decision boundary and publish versioned projections or receipts. Added depth must not silently increase hot-path latency or failure domain.

Dependencies are required, optional, or advisory. Failure of an optional Module reduces only the associated capability. The hard-dependency graph from the Kernel outward is acyclic. Isolation follows failure semantics: pure cancellable computation may share a runtime; untrusted, blocking, credential-bearing, resource-heavy, or crash-prone capability receives a stronger boundary.

**ARCH-MOD-01 — Small living Kernel.** Failure of an agent, model route, graph, Dreamer, UI, or adapter must not destroy canonical state or independent work.

**ARCH-MOD-02 — Depth is additive and micro-modular.** New depth is added through independently understandable, testable, and replaceable capability cells; their size and physical form remain empirical Implementation decisions.

**ARCH-MOD-03 — One causal responsibility, one owner, one proof, one replacement boundary.** A material capability has one causal and lifecycle owner; each mutable state it owns has exactly one owner; the capability has an independently invocable proof surface and a declared replacement boundary. A stateless capability declares the absence of mutable state explicitly. Physical packaging remains empirical; ownership does not.

**Why:** `ARCH-MOD-02` prevents premature size constraints but does not by itself expose blurred ownership. Loss of causal responsibility—not size—destroys independent verification, replacement, and failure localization.

**Violated when:** one mutable state has two owners; a stateful capability has no owner; a capability lacks independently invocable proof; changing one causal responsibility requires simultaneous edits across several owners without a declared contract wave; or the replacement boundary is unnamed.

**ARCH-PORT-01 — Organs and execution contours are replaceable.** Models, agents, harnesses, tools, storage, protocols, and isolation technologies are replaced through capability, conformance, migration, and failure contracts; public inheritance transfers, while tacit strategy is reevaluated.

---
