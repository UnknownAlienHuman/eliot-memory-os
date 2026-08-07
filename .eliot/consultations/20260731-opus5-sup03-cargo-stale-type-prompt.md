# ELIOT SUP-03 bounded diagnostic request

You are reviewing a native Windows Rust workspace at:
`C:\Users\kleym\OneDrive\Documents\Rust\projects\eliot-memory-os`.

Read-only diagnosis only. Do not edit files and do not run provider adapters.

Current staged SUP-03 change adds these fields to the single definition of `eliot_types::ServiceRestartPolicy` in `crates/eliot-types/src/service.rs`:

```rust
#[serde(default)]
pub restart_delays_seconds: Vec<u64>,
#[serde(default)]
pub reset_period_seconds: u64,
```

Exact observations:

1. `rg` and the code graph find only one `ServiceRestartPolicy` definition, and current source contains both fields.
2. `cargo tree -p eliot-engine -e all` shows one local path `eliot-types v0.1.0`.
3. `cargo check -p eliot-engine --all-targets` passes.
4. `cargo check -p eliot-types --all-targets` passes and recompiles `eliot-types`.
5. Immediately afterward, `cargo check --workspace --all-targets` fails compiling `eliot-engine (lib test)` at `crates/eliot-engine/src/service.rs:844-845`, claiming `ServiceRestartPolicy` has only the old five fields and no `restart_delays_seconds` or `reset_period_seconds`.
6. No source edits occur between commands.

We already tried two non-destructive rebuild routes. Determine the most likely root cause and prescribe the smallest safe next diagnostic/fix. Specifically decide whether a package-scoped Cargo artifact clean is justified, and give exact PowerShell/Cargo commands. Do not recommend weakening the service validation or removing the new fields. Keep the response concise and evidence-driven.
