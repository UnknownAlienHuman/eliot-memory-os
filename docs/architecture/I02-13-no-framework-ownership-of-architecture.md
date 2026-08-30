## I2.13. No framework ownership of architecture

Tokio, ractor, axum, rmcp, SurrealDB, nextest, sccache, and future frameworks implement local mechanics. None defines:

```text
authority;
canonical record semantics;
task lifecycle;
epistemic status;
module ownership;
finish outcome;
Architecture conformance;
supervision policy ELIOT;
swarm decision authority.
```

A framework always remains behind an ELIOT-owned crate contract and removal boundary.

