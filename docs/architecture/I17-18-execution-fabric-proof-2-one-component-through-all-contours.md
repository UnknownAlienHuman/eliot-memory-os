## I17.18. Execution Fabric Proof 2 — one component through all contours

This proof is required before ELIOT permits agent-generated runtime components to receive live traffic. It is not a prerequisite for Operational Spine Proof 1 or unrelated D1 work.

```text
1. Main Agent receives one small pure component cell and frozen contract.
2. Agent changes core in a leased worktree.
3. `eliot-testd` runs crate-local discriminator, unit/property and contract tests.
4. Component builder compiles `wasm32-wasip2` and records WIT/artifact provenance.
5. WASM and native-core outputs pass one differential conformance corpus.
6. Deterministic replay executes recorded cases and fault seeds.
7. `eliot-wasm-host` runs candidate in effect-free shadow mode.
8. Comparator records semantic/resource divergence.
9. A bounded canary receives explicitly eligible traffic.
10. Kernel commits generation cutover and raises Authority Epoch.
11. A forced regression demonstrates automatic routing rollback without loss of task/effect state.
12. Restart Host/Kernel/testd and reproduce the same receipts and active generation.
```

Exit evidence:

```text
no direct shell or DB authority for the agent/component;
no orphan process or unreceipted effect;
byte-addressable artifacts and Failure Capsules;
component can remain WASM or be replaced by an equivalent isolated native generation;
full control-plane release is not required for a component-only iteration.
```

Failure at any stage returns the component to a non-active state and preserves the candidate for diagnosis; it does not trigger broad feature work or a full workspace certification campaign.


