# Assignment reservation

Owning issue: #698
Branch: `feat/698-durable-swarm-state-machine`
Base revision: `d89d3e7b9d012993aa22a8d00db75f6a6740a2de`
Required predecessors: B-MOD #694 and B-PEER #696
Semantic owner: durable Swarm execution state, checkpoint/restart and no-lost-child proof
Required matrix: 40 cases

This branch must not define model registry, peer transport, process execution, Governor admission or task finish. It blocks B-AGENT-WIRE-CONTROL #872. Remove this marker when implementation begins and before ready-for-review.
