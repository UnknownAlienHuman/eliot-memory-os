# Assignment reservation

Owning issue: #903
Implementation branch: `feat/903-kernel-generation-control-diagnostics`
Required predecessor: F-LOG-KERNEL-0 #895

Status: **blocked marker-only** until #895 integrates and this branch is rebased onto current `main`.

Exclusive production scope after activation:

- `bins/eliot-kernel/src/control_plane.rs`
- `bins/eliot-kernel/src/daemon_runtime.rs`
- `bins/eliot-kernel/src/generation_control.rs`
- `bins/eliot-kernel/src/generation_recovery.rs`
- `bins/eliot-kernel/src/health_view.rs`
- `bins/eliot-kernel/src/runtime_identity.rs`
- focused test/fixtures named by #903

Diagnostic calls only. No Kernel manifest/main/lib, front-door, Store/composition, process/supervision, shared crate, root Cargo/lock, workflow or documentation change.

Issue #903 is the complete 30-case execution contract. Remove this marker when implementation begins and before ready-for-review.
