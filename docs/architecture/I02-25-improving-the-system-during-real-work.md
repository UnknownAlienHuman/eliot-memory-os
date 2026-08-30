## I2.25. Improving the system during real work

The running stable generation is neither edited nor rebuilt in place.

```text
real workload creates Problem/Improvement Candidate
→ AgentDevelopmentPlanner selects one FunctionalCapabilityCell and its bounded source packages
→ isolated worktree and build lane
→ package proof
→ affected real edge
→ shadow/canary generation on bounded workload
→ comparison with stable generation
→ authorized Module promotion owner or pre-authorized System policy decision; Main Agent supplies the recommendation and evidence
→ forward cutover or rejection
→ outcome updates memory, tests, Skills and crate profile.
```

Rules:

```text
background compilation has a lower resource class;
real project state is not used as an unprotected test fixture;
canary effects are read-only or separately authorized;
self-learning does not mean self-writing source without an owner;
agent and model-route policy and budget are Human-defined;
a failed experiment does not damage the stable generation;
new evidence may change a crate split or merge decision.
```

ELIOT can therefore improve during operation, while the production hot path remains on a known generation until the candidate passes its proof.

