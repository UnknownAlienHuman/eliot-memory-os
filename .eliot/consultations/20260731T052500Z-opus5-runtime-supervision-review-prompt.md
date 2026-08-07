# Read-only RUNTIME-SUP-01 engineering consultation

You are the senior reviewer for a Windows-native Rust supervision repair. Work read-only: do not edit files, do not run tests or provider calls, and do not use MCP. Inspect the current uncommitted diff and exact source anchors with Read/Grep/Glob only.

Repository:
`C:\Users\kleym\OneDrive\Documents\Rust\projects\eliot-memory-os`

Binding contract:
`C:\Users\kleym\Downloads\ELIOT_RUNTIME_SUPERVISION_01_PROCESS_LEASE_SEAL_RECOVERY_v1_0.md`

Current baseline commit:
`8d2db4ad55052040dd46c31e29fe559f47c87a44`

Current phase:
Only RUNTIME-SUP-01 is being implemented. SUP-02 and SUP-03 must remain separate later commits. No certification/provider execution is allowed now.

What was implemented:

- New typed runtime supervision/checkpoint/restart/reap records in `eliot-types`.
- New operation-runtime/redb tables and sole-writer actor API.
- New engine cancellation token, durable operation supervisor, watchdog, restart/circuit state.
- Adapter API migrated to an execution context; timeouts now cancel, await cleanup, and require a reap receipt.
- Windows Job Object wrapper now supports unique named jobs, reopen/count/terminate/wait-empty, kill-on-close, secured descriptor, and retained stdin.
- New shared app primitive in `crates/eliot-app/src/host_runtime/supervised_process.rs`: named Job, concurrent stdin/stdout/stderr drain, absolute timeout/cancel, TerminateJobObject, wait for zero active processes, join pipe tasks, durable progress/reap receipt, startup named-job recovery.
- Claude/Antigravity/OpenCode/MCP helper paths were migrated to this primitive; startup watchdog is connected.

Observed verification:

- `cargo check -p eliot-engine -p eliot-app --all-targets` passed.
- `cargo test -p eliot-windows-ipc supervised_process -- --nocapture` passed 2/2 in 2.312s.
- Each exact native self-spawn app fixture test passed individually in about 0.03s and 0.28s.
- One aggregate `RUST_TEST_THREADS=1 cargo test -p eliot-app supervised_process -- --nocapture` passed 6 tests in 5.161s.
- Later the same aggregate invocation appeared to hang twice until the outer tool timeout (one >124s and one >34s). One earlier surviving exact test process was identified and terminated; the latest bounded process inspection currently shows no Cargo or test process. The failure is intermittent and target aggregation-specific.

Please inspect the actual diff and answer these questions:

1. Identify the most likely source-level cause of the intermittent aggregate `supervised_process` test hang. Trace the exact wait/channel/job/process path and explain why individual tests pass. Give the smallest deterministic fix and a focused regression command.
2. Audit the SUP-01 implementation against the binding contract. List only concrete missing or incorrectly implemented requirements that block a truthful SUP-01 PASS. Keep SUP-02 lease/seal/recovery work out unless a boundary error leaked into SUP-01.
3. Specifically assess:
   - spawn/setup failure cleanup and whether every owned child reaches a complete reap receipt;
   - separate absolute/first-output/idle deadlines;
   - global and per-adapter concurrency ceilings;
   - actual bounded restart dispatch versus merely persisting restart metadata;
   - startup watchdog behavior for durable checkpoints and named Job recovery;
   - any remaining provider/MCP child lifecycle that bypasses the shared primitive;
   - whether `ProcessReapReceipt::proves_complete_reap` is sound.
4. Provide an ordered minimal patch plan with exact files/functions and tests. Flag any change that belongs to SUP-02 or SUP-03 instead of SUP-01.

Be decisive. Cite source paths and functions/line regions. Do not propose broad redesigns, new dependencies, Python/Node hot-path services, weakened timeouts, sleeps, or PID-based broad termination.
