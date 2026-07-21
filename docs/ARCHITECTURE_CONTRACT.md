# Architecture contract

The normative architecture set is:

- `docs/architecture/ELIOT_Canonical_Master.md`
- `docs/architecture/ELIOT_Rust_Governor_Production_Architecture_v1_0.md`
- `docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md`

Current source, Cargo manifests, migrations, generated metadata, diagnostics, and
tests take precedence when implementation and prose diverge. Runtime databases,
reports, agent memory, and generated code graphs are evidence layers and are not
repository truth.

## Product boundaries

- `eliot-app` owns the CLI, daemon, MCP facade, host integration, and operator
  command surface.
- `eliot-engine` owns governance, task, verification, delegation, and memory
  policy transitions.
- `eliot-store` owns canonical persistence, SurrealDB supervision, migrations,
  blobs, backups, and store receipts.
- `eliot-types` owns shared configuration, contracts, schemas, and wire types.
- `eliot-windows-ipc` owns authenticated Windows process and named-pipe
  boundaries.
- `apps/Eliot.Operator` is a replaceable operator UI over governed protocols.

## Authority invariants

Host identity is transport metadata, not a task role. Memory recall is evidence,
not current source truth. Model output is candidate evidence until governed
disposition. Completion requires current verifier evidence and FinishGate; no
plugin, hook, provider, or UI may manufacture it.

## External-provider invocation lifecycle

Every real provider invocation is bounded by current scope, role and work leases,
typed arguments, an idempotency key, explicit budgets, and a terminal or
reconcilable outcome. An unknown outcome must be reconciled before redispatch.
Provider credentials remain owned by the provider host and never enter canonical
memory or repository configuration.
