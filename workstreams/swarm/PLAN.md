# Initial source-work assignments

Two independent issue assignments are selected in PLAN.tsv. READY means source work
can proceed after live controller preflight, not that tests passed or the entire
backlog has been checked. The reserved subtrees are conservative exclusion ceilings;
edit only files causally required by the assigned issue. They may be narrowed after
a manager records the concrete diff, never silently widened.

## M-KERNEL — #1943

Reuse eliot-ipc's role_lease.rs and ApplicationSession admission/transition methods.
Connect them to the real authenticated server admission and role-transition paths;
compile the current owner's role/WorkScope/delegation limits, do not trust a role label
or a caller-created permissive policy. Preserve exact task/route/profile/fence/epoch/
expiry binding, revoke the old context, and update independence on transitions.
Do not implement a second capability engine. The two existing acceptance scenarios
remain the behavioral discriminators; test execution follows product assembly.

Read issue #1943 and all five pre-continuation comments, I7.21, the relevant IPC and
Kernel instructions, and the complete routed bundle. The source recheck on the baseline
found admit_role_capability in session_lifecycle.rs only; PR #4880's title is not proof
that a live caller exists. Resolve the actual production boundary before mutation.
The Kernel/protocol subtrees stay with this manager; #1678/#1701 and other Kernel
issues are not simultaneous writers. #1678 first receives a residual recheck: its
async admission_reservation_saga.rs coordinator already exists on current main.

## M-STORE — #2691

Complete W5 and W7 in the existing snapshot owner. The current hook is pub(crate) in
backup_snapshot.rs and the source search found no caller outside that module; Charge
retains dimension/limit/charged, not a high-water observation. Expose a narrow owner
method and drive it from StoreComposition's supervised lifetime even with no clients;
stop/join that work with the owner. Reuse the existing bounded expiry transitions,
clock domain and diagnostics. No detached task, second database, reset-to-zero
accounting or silent evidence eviction. Preserve #2688/#2689 identity/retirement work.

The actual S-03 composition is bins/eliot-store-surreal/src/lib.rs, which owns
SurrealStoreAdapter and CanonicalSnapshotPort; main.rs owns its process lifecycle and
existing diagnostics installation. Both are included in this assignment. Do not
expand Store API/protocol or change another process without an explicit scope amendment.
Read issue #2691, all six pre-continuation comments, A13.5/I14.3/I5.16/I5.27 and the
mandatory bundle. The latest correction is comment 5931062575; earlier saturation
and duplicate-begin findings must be checked against their already-merged fixes.

## Controller-only shared changes and external work

Cargo.toml/Cargo.lock, routing/workflow inputs and active planning files remain root-owned.
No new dependency is pre-authorised. #5021 remains an external writer on:

- bins/eliot-watchdog/src/health_projection.rs
- config/doc-code-conformance.toml
- crates/foundation/eliot-bootstrap/src/capture.rs
- crates/kernel/eliot-ors/src/status.rs
- crates/smart/cognitive-rev12-contract-schema-freeze.toml
- scripts/README.md

Refresh the PR before dispatch; a terminated writer does not reserve paths forever.
Its last observed head was 0a64bbfb31b87dfa0c87e50a825f906ed76dda14. Do not copy its
changes or declare them accepted merely because its body says checks pass.

Read-only reviewers may examine RECHECK issues concurrently. They return one bounded
finding to root with issue/item, source SHA, exact owner/output, paths and release
condition; they do not edit the shared map or create duplicate implementation branches.
Root integrates planning updates one at a time. Full stop inventory remains available
for subsequent candidates, without requiring every worker to ingest it.
