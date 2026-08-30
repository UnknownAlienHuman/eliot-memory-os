# Appendix I. Dependency selection and containment

| Need | Current candidate | Where contained | Adoption status |
|---|---|---|---|
| async/process I/O | Tokio | runtime/platform facades | required baseline |
| CPU-bound pool | Rayon behind `eliot-cpu` | runtime facade only | candidate DEFAULT after bounded cancellation/memory tests |
| supervised actor tree | plain Tokio baseline; ractor candidate | daemon-only runtime facade | Research Gate RGF-RUNTIME-RESILIENCE |
| MCP | official Rust SDK (`rmcp`) | `eliot-mcp` | primary bridge |
| optional binary EBP encoding | prost | `eliot-protocol` | RGF-PROTOCOL-TRANSPORT candidate; JSON-first remains D0/D1 default |
| host state journal | redb | `eliot-platform` / HostStateStore | primary installation/process lineage store |
| operational recovery DB | redb | `eliot-ors` | primary ORS |
| canonical DB | SurrealDB SDK | separate store bridge process | provisional primary |
| Windows-native UI | WinUI 3 on Windows App SDK stable line; thin C# client | `eliot-ui` user-session adapter | primary Human surface; Rust control plane unchanged |
| filesystem watch | notify | platform/scope bridge | hint source, not truth |
| serialization/schema | serde, serde_json, schemars | foundation contracts and EBP JSON codec | internal/wire schemas; public types remain ELIOT-owned |
| sortable identities | uuid v7 | `eliot-types` ID facade | default; wire format is ELIOT newtype, not crate type |
| path/write-set policy | globset | policy/path facade | default for compiled path sets; canonicalization remains ELIOT-owned |
| HTTP middleware | tower | HTTP/MCP/UI transport facade | default for timeout, concurrency and load-shed layers |
| config hot snapshots | arc-swap | config service | default |
| hashes/content IDs | BLAKE3 | artifact/blob/audit facades | default |
| compression | zstd | blob/export facade | default |
| tracing | tracing + tracing-subscriber; tracing-appender candidate | observability facade | default spans; async file appender contained and replaceable |
| short synchronous locks | std locks first; parking_lot candidate | runtime facade only | adopt only after profiling; never across await/external calls |
| Windows service/API | official windows-rs service/platform crates | platform-windows | primary Windows layer |
| Cargo graph parsing | `cargo_metadata` | Instrument Plane Cargo profile | default structured package/resolve graph |
| test inventory metadata | `nextest-metadata` | Instrument Plane test profile | candidate parser for discovered test inventory |
| test runner | cargo-nextest | dev tooling / Instrument Plane | default affected runner |
| property tests | proptest | dev dependency in contract crates | default for normalization/state/idempotency |
| concurrency model checks | loom | Kernel/write/lease test backend only | targeted load-bearing tests |
| fuzzing | cargo-fuzz/libFuzzer | protocol/parser/import targets | release/security jobs |
| Rust semantic index | pinned rust-analyzer + SCIP Rust bindings | Instrument Plane architecture profile | one-shot candidate profile after RGF-CODE-RESEARCH |
| compiler JSON | Cargo/rustc/Clippy JSON streams | Instrument Plane compiler profile | authoritative parser path |
| code text search | ripgrep JSON | Instrument Plane exact-search profile | exact lexical evidence only |
| snapshots | insta | UI/rendered packets/reports only | scoped, reviewed snapshots |
| benchmarks | criterion | hot-path/store/module benches | empirical profile input |
| fault points | ELIOT `FaultPoint` facade; `fail` crate candidate | dev/fault builds only | experiment behind facade |
| metrics facade | `metrics` + bounded exporter | observability facade | candidate; no domain dependency |
| process inventory hints | `sysinfo` behind Watchdog sensor facade | Watchdog only | advisory; Windows APIs remain authority source |
| Windows service helper | `windows-service` plus `windows-rs` | platform-windows | candidate behind facade |
| optional web compatibility view | axum + Askama | separate UI adapter only | non-primary fallback/experiment; no additional authority |
| terminal dashboard | Ratatui + Crossterm | optional `eliot dashboard` | lightweight projection only; no second state owner |
| WASM components | Wasmtime Component Model | optional module runtime | experiment RGF-COMPONENT-SANDBOX |

Rules:

```text
exact versions pinned in lock/compatibility registry;
license policy or an explicit contained exception is verified before promotion;
third-party public types do not cross ELIOT facade;
removal/replacement test exists for load-bearing dependency;
Kernel dependency set remains minimal.
```

---

