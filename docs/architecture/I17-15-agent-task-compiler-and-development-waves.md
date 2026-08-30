## I17.15. Agent Task Compiler and development waves

`AgentDevelopmentPlanner` is a deterministic Agent Coordinator and Governor capability. It does not create a second task graph.

Inputs:

```text
CrateRegistry and CrateFleetReport;
ModuleGraph and ModuleContractKits;
BuildTestGraph and historical escapes;
current Product/WorkScope identity;
Problem/FailureFingerprint evidence;
public-contract and resource overlap;
available agents/routes/budget/context profiles;
integration and Product Pulse dependencies.
```

Output is canonical WorkItems in four bounded waves:

```text
Contract/Evidence wave
  owner, public contract, old path, fixtures, oracle and discriminator;

Module-cell wave
  disjoint FunctionalCapabilityCells implemented and tested in parallel inside bounded source packages;

Edge wave
  actual provider/consumer/process/store boundaries;

Product Pulse
  shortest end-to-end route capable of exposing local-proxy drift.
```

Rules:

```text
contract revision frozen inside a wave;
one mutating writer per declared mutable scope/path claim/contract edge; disjoint cells in one crate may run in parallel only when their source/effect claims do not overlap and one Integration owner reconciles the shared crate;
read-only audits may fan out independently;
workers receive brief/kit/capsule, not the whole Implementation;
Module/Cell Proof creates IntegrationCandidate, not merge or product status;
contract drift invalidates only dependent work;
second failure of one mechanism class triggers Mechanism Review;
Product Pulse occurs before a long chain of local green crates accumulates;
model may propose decomposition, but Governor admits the work graph;
planner opens `ContextScaleReview` when no qualified envelope fits the unit; it prefers decomposition or a tighter projection, but may retain a cohesive unit when exact measurement proves a complete workset and the Task Controller records the scoped decision. I2.16 planning bands alone never create a refusal.
```

