## I20.2. Replacement matrix

| Component | Current default | Boundary | Replacement proof |
|---|---|---|---|
| Canonical DB | SurrealDB bridge | Store EBP + ECXF | dual-read/write, migration, restore |
| Host state journal | redb | HostStateStore + installation-state export | activation/dependency lineage and torn-write recovery equivalence |
| Operational WAL | redb | ORS repository trait + export | crash/idempotency/recovery equivalence |
| Actor runtime | plain Tokio through `eliot-runtime`; `ractor` is experimental | runtime facade | supervision/fairness/perf scenarios and zero domain-type leakage |
| MCP SDK/spec | rmcp / MCP 2026-07-28 | eliot-mcp | host profile compatibility |
| Main model/provider | user-selected routes | ModelBridge | task/quality/privacy/cost profile |
| Dreamer model | user policy | Agent Coordinator job | curation/research evaluation |
| Code graph | bridge modules | eliot-graph-api | exact query/impact/health equivalence |
| LSP/IDE | bridge modules | diagnostic/symbol contract | project scenarios |
| Human UI | WinUI 3 / Windows App SDK desktop client | ControlBoard/Operator API | ordinary-user onboarding, Dreamer chat, launcher, accessibility and recovery |
| Windows services | SCM/Job Objects | platform facade | future Linux service tests |
| Notifications | Windows adapter | NotificationBridge | delivery/dedup/ack behavior |
| Blob compression/hash | zstd/BLAKE3 | Blob format version | export/import/content integrity |

