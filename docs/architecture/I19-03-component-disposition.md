## I19.3. Component disposition

Current source-preservation rule:

| Existing source owner | First change | Forbidden duplication |
|---|---|---|
| `eliot-types` | additive host/route/capability/continuity/usage contracts | new parallel agent-domain crate |
| `eliot-engine` | extend Host Broker, admission, route selection and Agent Coordinator | second task DAG, scheduler or budget authority |
| `eliot-store` | store route evidence, raw/native events and receipts | agent/runtime database as canonical state |
| `eliot-windows-ipc` | carry additive typed commands/events | second unauthenticated local control channel |
| `eliot-app` | add `host_runtime` adapters/sidecars and migrate provider-specific launch paths | independent provider launch journals/recovery loops |

```text
KEEP       — conforms and can remain;
WRAP       — useful third-party/current component behind new bridge;
EXTRACT    — move from monolith to module with same behavior;
REWORK     — concept valid, contract wrong;
REPLACE    — incompatible or too costly;
RETIRE     — no value/duplicate;
UNKNOWN    — requires experiment.
```

No deletion before data/behavior owner and replacement proof.

