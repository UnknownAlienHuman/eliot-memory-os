## I18.7. Independently testable capability cell contract

Owner of this contract is the `FunctionalCapabilityCell`, not the crate; a crate may host several cells and remains only the normal Cargo compilation/publication container.

Every production crate or independently scheduled capability cell has an executable `ModuleTestCapsule`; the package-selective profile is the normal Cargo entrypoint. Private micro-modules inside the crate may have narrower selectors, but the crate is the normal unit of Cargo compilation, contract publication and agent delivery. Mutable-state/lifecycle ownership remains attached to FunctionalCapabilityCell/service contracts rather than inferred from package membership.

Canonical entrypoints are generated through Instrument Plane:

```text
cargo check -p <crate>;
cargo nextest run -p <crate> <selector>;
crate-specific property/model/golden profile;
consumer contract profile;
real-edge profile where applicable.
```

Independence means:

```text
unrelated runtime services are not started;
fixtures and resources are declared;
selected tests have nonzero discovery/execution receipts;
result is attributable to one crate/contract edge;
proof ceiling is explicit;
Cargo may still compile exact dependencies required by that crate.
```

Minimum proof by class:

| Crate/micro-module class | Required local proof |
|---|---|
| `foundation_contract` | schema/serialization/compatibility/property; no runtime |
| `pure_core` | unit, property and adversarial boundary cases |
| `state_machine` | transition model, replay, stale revision/epoch and cancellation |
| `parser_normalizer` | golden corpus, unknown fields, truncation, non-UTF-8 and fuzz |
| `profile_recipe` | fake-executor stage graph plus exact real-tool fixture |
| `stateful_service` | service contract, restart/replay and no hidden state owner |
| `process_adapter` | handshake, identity, streams, cancel, cleanup and fault |
| `projection_renderer` | semantic invariants plus snapshot/accessibility where applicable |
| `thin_binary` | composition/startup/config/health; domain behavior belongs to libraries |

A fake implements the same public contract and exposes unsupported behavior rather than returning success. Fake proof never becomes Edge/ProductProof.

Each fixture corpus is a versioned `ContractFixtureSet` with source lineage, oracle owner, covered property/failure and invalidation dependencies. Provider and consumer crates use the same contract revision. Updating implementation and expected oracle in one work item requires separate oracle review.

Crate tests are sharded with nextest when independent. Cross-crate edge tests live in dedicated edge/scenario crates owned by the relation, not copied into every participant.

