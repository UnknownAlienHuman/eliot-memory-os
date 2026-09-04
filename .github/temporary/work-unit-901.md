# Assignment reservation

Owning issue: #901
Implementation branch: `feat/901-kernel-process-supervision-diagnostics`
Required predecessor: F-LOG-KERNEL-0 #895

Status: **blocked marker-only** until #895 integrates and this branch is rebased onto current `main`.

Exclusive production scope after activation:

- `bins/eliot-kernel/src/process_execution.rs`
- `bins/eliot-kernel/src/daemon_process_launch.rs`
- `bins/eliot-kernel/src/daemon_live_receipt.rs`
- `bins/eliot-kernel/src/daemon_supervision.rs`
- `bins/eliot-kernel/src/supervision_lease_authority.rs`
- focused test/fixtures named by #901

Diagnostic calls only. No Kernel manifest/main/lib, front-door, Store/composition, generation/control/health, shared crate, root Cargo/lock, workflow or documentation change.

Issue #901 is the complete 30-case execution contract. Remove this marker when implementation begins and before ready-for-review.
