# W1 report — issue #1108, session 20261001-064347: claim-row read arm (NO-CHANGE)

## Verdict: nothing to port — prior delivery already on origin/main; specified edit cannot land single-file

The remaining CHECK (`handle_provider_capability_claim_row_read` not found in
`bins/eliot-kernel/src/native_worker_lifecycle_route.rs`) is true file-locally
but stale tree-wide: the exact arm it asks for already serves production on
current `origin/main` from its documented owner file, with the daemon caller
and factory consumer wired to it. Adding it again in the lifecycle file within
my exclusive paths is either a build break or a silent route shadow (details
below), both requiring files I must not touch. No code changed.

## Heads examined (port sources)

- `d32fe661` (`fix/1108-claim-row-restore-W1d` — the brief's named prior
  delivery): adds the claim-row read arm to
  `bins/eliot-kernel/src/provider_capability_route.rs` (+124/-10:
  `PROVIDER_CAPABILITY_CLAIM_ROW_READ_OPERATION`,
  `ProviderCapabilityContext::read_claim_row`,
  `KernelComposition::handle_provider_capability_claim_row_read`, dispatch
  branch). Base `fe7ef391`.
- `60d9cd6a6` + fmt `9e6b2bce6` (sibling lane worktree `W1-1108b-014755`,
  branch `fix/1108-claim-row-arm-W1b`): the same arm re-shaped for
  `bins/eliot-kernel/src/native_worker_lifecycle_route.rs` (+111/-5) against an
  older base (`5d95c2fb8`) that predates the re-landing below.
- `6125b5917` (PR #4913, on current `origin/main` `4537751bf`): re-lands the
  `d32fe661` arm into `provider_capability_route.rs` after regression #4892
  (`a3a6e1608`) had removed it. `git log -S
  handle_provider_capability_claim_row_read` confirms the remove/re-land pair.

## Current-main evidence (all read, not modified)

- `bins/eliot-kernel/src/provider_capability_route.rs`: const line 80,
  `is_provider_capability_operation` lines 84–87, `read_claim_row` lines
  396–426 (row verbatim from `ors.load_native_worker_claim`, no presented
  echo), dispatch branch lines 551–560,
  `handle_provider_capability_claim_row_read` lines 680–700.
- `bins/eliot-kernel/src/frame_dispatch.rs`: `is_native_worker_operation`
  routes first (line 971 → `dispatch_native_worker_frame`);
  `is_provider_capability_operation` routes after (line 1005 →
  `dispatch_provider_capability_frame`).
- `bins/eliotd/src/daemon_kernel_client.rs`: `load_provider_claim_row_async`
  lines 1932–1988 sends the op, checks the seal digest, enforces claim-echo
  binding, builds `OwnerLoadedClaimRow::new`; header line 96 names the provider
  route handler as its Kernel counterpart.
- `bins/eliotd/src/provider_capability.rs:105`,
  `crates/agent/eliot-agent-coordinator/src/admitted_provider.rs:59`
  (`OwnerLoadedClaimRow`), drive seams per client docs lines 1926–1931.

## Why the specified single-file edit does not apply anymore (superseded)

1. E0592: `provider_capability_route.rs:680` already defines inherent method
   `KernelComposition::handle_provider_capability_claim_row_read`. Adding a
   same-named method in `native_worker_lifecycle_route.rs` (same crate, same
   type) is error E0592 duplicate definitions; renaming either side needs a
   file outside my exclusive paths.
2. Route shadow: putting the same op string into `is_native_worker_operation`
   would divert claim-row frames at `frame_dispatch.rs:971` into
   `dispatch_native_worker_frame`, silently displacing the landed provider
   branch (`:1005`) owned by another lane — a behavior change to a production
   path I do not own, and a duplicate owner surface for one row.
3. A differently-named or differently-stringed arm in my file alone would be
   unreachable dead code (no caller sends it) or a second wire op for the same
   row — a third design, which the routing rules forbid inventing.

Per RESCUE.md §4 this head is therefore superseded *for the lifecycle file*:
the needed producer exists at its documented owner and the agreed composition
boundary (`production_fabric_ports`, `agent_fabric_new_verified_async`, solo
consumer via the daemon client above) already consumes it.

## What would unblock a lifecycle-file arm (needs another path — NOT done)

Either (a) relocate the owner: remove/rename the provider-route method and
re-point the daemon client + `frame_dispatch` order (touches
`provider_capability_route.rs`, `frame_dispatch.rs`, `bins/eliotd/*` — all
forbidden here); or (b) manager re-scopes the CHECK to the provider file where
the symbol already lives. Awaiting manager decision; no code written, no tests
added, no cargo run (per brief, manager builds).

## Docs bundle

Read once, as supplied:
`control-20260923-impl/v2/workers/W1/docs-read-bundle-1108-064347.md`
(route `sha256:675e…`, pair `sha256:ab2011…`). No self-routing performed.
TASK.md / REMAINING.md (single CHECK) / BATCH.md / STITCH.md / RESCUE.md table
read. `d32fe661` applies content-wise (fully present via #4913) but not as a
fresh port; archive heads not consulted per brief condition.
