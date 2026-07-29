# Architecture contract

The architecture documents have three deliberately different authorities:

| Category | Document | Meaning |
|---|---|---|
| Canonical vision | `docs/architecture/ELIOT_Canonical_Master.md` | Governing product theory and long-term architecture; it does not claim that every mechanism exists today. |
| Current implementation | `docs/architecture/ELIOT_Rust_Governor_Production_Architecture_v1_0.md` | The maintained description of the code and runtime that exist now. |
| Future design | `docs/architecture/ELIOT_Understanding_Layer_Engineering_Task_v1_4.md` | A bounded design specification for deeper project understanding; it is not a progress report or evidence of implementation. |

Current source, Cargo manifests, migrations, generated metadata, diagnostics, and
tests take precedence when implementation and prose diverge. Runtime databases,
reports, agent memory, and generated code graphs are evidence layers and are not
repository truth.

Development milestone names are not product architecture. Historical ADR names
may retain the milestone that motivated a decision, but active CLI, protocol,
schema, tests, and current documentation use semantic capability names.

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

## Metacognition coverage policy

The current implementation uses the versioned policy
`metacognition-coverage-v2` for every `covered`, `thin`, and `blind` decision.
The policy is deliberately conservative:

- `blind`: the subsystem has no capsule, its capsule is stale, or it has no
  module card anchoring the concept to a current path;
- `thin`: the capsule and module-card anchors are current, but fewer than three
  distinct knowledge records, fewer than two evidence classes, or no behavioral
  evidence are available;
- `covered`: the capsule is fresh, at least one module card exists, at least
  three distinct records span at least two evidence classes, and at least one
  decision, failure fingerprint, episode, experience case, or experience
  pattern supplies behavioral evidence.

Claims, decisions, failure fingerprints, episodes, experience cases, and
experience patterns are counted by distinct canonical record reference. Missing
or stale structural anchors never become `thin` or `covered` merely because
writer-provided prose is abundant. `UlMetacognitionView.policy_version` exposes
the applied policy to packets, tests, and external readers.
