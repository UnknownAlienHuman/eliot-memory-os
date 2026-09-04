# Assignment reservation

Owning issue: #899
Implementation branch: `feat/899-kernel-store-composition-diagnostics`
Required predecessor: F-LOG-KERNEL-0 #895

Status: **blocked marker-only** until #895 integrates and this branch is rebased onto current `main`.

Exclusive production scope after activation:

- `bins/eliot-kernel/src/canonical_store_runtime.rs`
- `bins/eliot-kernel/src/composition_bootstrap.rs`
- `bins/eliot-kernel/src/kernel_build_contract.rs`
- `bins/eliot-kernel/src/kernel_config.rs`
- `bins/eliot-kernel/src/store_receipt_dispatch.rs`
- focused test/fixtures named by #899

Diagnostic calls only. No Kernel manifest/main/lib, front-door, process/supervision, generation/control/health, shared crate, root Cargo/lock, workflow or documentation change.

Issue #899 is the complete 26-case execution contract. Remove this marker when implementation begins and before ready-for-review.
