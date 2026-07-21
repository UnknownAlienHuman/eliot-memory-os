# ADR 0001: Phase A dependency boundaries

Known facts:
- The architecture contract requires four crates: `eliot-types`, `eliot-store`, `eliot-engine`, and `eliot-app`.
- Phase A requires a real SurrealDB remote-server path, redb ControlWal, BlobStore, startup doctor, logging, and a Windows service entry.
- Local stable Rust is `1.96.0`; `redb 4.1.0` requires Rust `1.89`.
- The v1.1 transport contract makes a Governor-managed local SurrealDB server plus thin WebSocket JSON-RPC client the default path.
- The default Cargo graph must not include the SurrealDB Rust SDK or its transitive `rsa` audit blocker.

Causal mechanism:
- `eliot-types` must remain pure schema code, so it cannot depend on Tokio, SurrealDB, redb, rmcp, filesystem, or Windows APIs.
- `eliot-store` owns persistence adapters and may depend on redb, hashing, a WebSocket client, and process supervision.
- `eliot-engine` owns lifecycle/readiness abstractions and does not depend on `eliot-store`.
- `eliot-app` composes the crates, owns CLI/service entry, and is the only crate allowed to use `anyhow`.
- The SurrealDB SDK currently pulls a graph that conflicts with release gates; a thin JSON-RPC client keeps the server boundary while avoiding SDK transitive risk.

Conclusion:
- Set project MSRV to `1.89` to allow current redb without raising the whole parent Rust root.
- Keep SurrealDB storage behind a local server process started by the Governor, not as an embedded SDK dependency.
- Treat `cargo audit`, `cargo deny`, `cargo tree -i surrealdb`, and `cargo tree --target all -i rsa` as release blockers for dependency boundary drift.
