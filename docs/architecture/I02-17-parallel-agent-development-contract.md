## I2.17. Parallel agent development contract

An agent swarm develops FunctionalCapabilityCells in parallel only after freezing the applicable contract revision; crates are source and build containers.

```text
Contract/Evidence wave
  owner, public API, old failure, discriminator, fixtures;

Module-cell wave
  disjoint FunctionalCapabilityCells are implemented in parallel within bounded source packages;

Edge wave
  independent integrators verify real boundaries;

Product Pulse
  the shortest actual front-door path catches architectural drift.
```

### Assignment rule

One `AgentWorkUnitBrief` contains by default:

```text
one primary FunctionalCapabilityCell;
bounded support closure, justified by one-hop contracts/effects and measured context;
one causal property;
one discriminator;
one contract revision;
one integration owner;
an Agent Workset within I2.16.
```

A cross-crate defect is decomposed into:

```text
contract change unit;
provider/consumer crate units;
edge integration unit;
product pulse.
```

An agent receives neither a giant task such as “fix the entire subsystem” nor a meaningless atomized task such as “change one line” without product context.

### ContractChallenge

An agent must return a challenge instead of proxy optimization when:

```text
the primary owner is wrong;
the discriminator does not fail on the old production path;
the contract is contradictory;
the oracle would need a hidden change;
a decision-sufficient workset fits no applicable qualified Context Envelope;
a local edit would break a product invariant;
several tasks conflict over a public contract or state owner.
```

### Write isolation

Every mutating lane has a worktree, write and path claims, BuildFingerprint, test-resource namespace, and IntegrationCandidate. A worker does not integrate its own result.

