# Selected source assignments

PLAN.tsv selects three independent issue deliveries, not a complete sprint schedule.
Subtrees are conservative exclusion ceilings: edit only causally necessary files.
READY remains conditional on a current controller scope claim and the required read.

## M-KERNEL — #1943

Reuse eliot-ipc role_lease.rs and ApplicationSession's admission/transition methods.
Connect real authenticated admission and explicit role transitions, using actual
WorkScope/delegation policy rather than caller-selected authority. Bind task, route,
profile, fence, epoch and expiry; revoke the old context and update independence.
Do not build a second capability engine. Keep both existing acceptance scenarios.
Issue comment 5963617714 records the source boundary; read the current full thread,
I7.21 and routed bundle. #1678/#1701 cannot mutate the same Kernel/IPC scope in parallel.

## M-STORE — #2691

Finish W5/W7 and A6's source obligation: the supervised S-03 owner must drive bounded
snapshot expiry when clients disappear and publish bounded high-water/remaining-budget
diagnostics. Own the start/stop lifecycle, clock and error reporting. No detached
maintenance service, silent eviction, reset-to-zero accounting or new database.
Preserve #2688/#2689 handle/incarnation, interruption and terminal-receipt semantics.
The existing producer is in backup_snapshot.rs; StoreComposition and main.rs own the
composition and lifetime. Recheck those actual boundaries before editing. Earlier
cleanup-charge and duplicate-begin defects have already changed; do not replay old
patches. Read comments 5931062575/5963619581, the full issue and routed bundle.

## M-TOOLS — #2701

The stop-map claim that only audit items 3 and 6 remain is false on the checked SHA.
_validate_checked_result still accepts Boolean counts, conflicting candidate_id/id,
invalid digest shapes, blank base_sha and foreign proof_ceiling. An extracted-function
reproduction confirms acceptance; it is not execution of the repository CLI/scanner.
Read audit 5908785311 and recheck 5963910318 plus the complete issue discussion.
Implement all its existing items 1-7 and preserve item 9, not a fresh alternative spec.

Primary file: scripts/audit-serde-boundary-closure.py. The second reserved file,
scripts/serde_boundary_inventory.py, is only for a genuinely needed change to its
accepted #929 API; discovery is not reimplemented. Keep exactly one check(Path) call,
no sync/fallback during ordinary checking, distinct inventory/closure digests, and
valid unknown/needs-repair findings. Reject malformed identity/count/vocabulary/shape
before constructing CheckedInventory. Existing item-8 regressions remain acceptance.
Do not edit Rust, workflows or the global generated TOML from this manager.

## Integration and external paths

Root owns Cargo.toml/Cargo.lock, shared planning and generated whole-tree refreshes.
New paths require a scope amendment before writing. Child tests/fixtures must also
be explicitly claimed; unexecuted tests are never reported as passing.

#5021 is still open at the last read, head 0a64bbfb31b87dfa0c87e50a825f906ed76dda14:
  bins/eliot-watchdog/src/health_projection.rs
  config/doc-code-conformance.toml
  crates/foundation/eliot-bootstrap/src/capture.rs
  crates/kernel/eliot-ors/src/status.rs
  crates/smart/cognitive-rev12-contract-schema-freeze.toml
  scripts/README.md
These exact paths are excluded from all selected assignments. Refresh the PR delta
before claiming; neither a stale PR nor a historical wave is a permanent lock.
