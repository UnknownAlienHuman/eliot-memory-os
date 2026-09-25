# Independent review — Windows #1751 drain path `6a7cb3f` (0607)

- Target: `C:/Development/Rust/projects/eliot-swarm/finish-windows1751-20260922`, branch `codex/finish-windows1751-20260922`, exact `6a7cb3fd04fe2b2e7485650cc5833d80421cf281`, parent `552ee79ae7a13adef8362f629589d13ed004db2c`. Worktree clean; tracked source untouched by this review (this report is the only file written, untracked under `CONTROL/`).
- Increment: 7 files, +1596/−407 — `bins/eliot-host/src/lease_drain.rs`, `bins/eliot-host/src/lib.rs`, `bins/eliot-host/src/main.rs`, `bins/eliot-kernel/src/control_plane.rs`, `crates/kernel/eliot-host-state/src/model.rs` (1 line), `crates/kernel/eliot-kernel-service/src/lifecycle.rs`, `crates/kernel/eliot-kernel-service/src/protocol.rs`. Plus necessary parent context (barrier/census groundwork, demand-cancel path, `drain_transition` matrix).
- Verdict for the bounded source: **ACCEPT**, with two P2 corrections and the listed remaining obligations. No P1 defects found.

## Reading scope (genuine)

- `control-20260922/windows1751-resume-author.md` (full, incl. 6a7cb3fd continuation), `windows1751-lane-progress.md` (full), live-issue #1751 body via cached `live-issue-1751.json` (contract + acceptance restated; consistent with lane-progress restatement).
- Full unified diff `552ee79a..6a7cb3f` read end-to-end for all 7 files; parent-context reads: `HostComposition::stop` (lib.rs:7924-8177), demand-cancel path (lib.rs:5400-5512), `drain_transition` (model.rs:2316-2349), SCM loop + post-loop (main.rs:866-979), idle supervisor (main.rs:1211-1310).
- Docs route for the 7 source paths, topic "windows service idle shutdown drain lease terminalization": PASS, read `sha256:dede5cfd…739c9c`, route `sha256:e8aaf2e2…981d0`, 39 required items, bundle `sha256:b7d33fb9…74bdb`, matched `generic-source, host-kernel` (bundle/receipt kept in `$env:TEMP`, author copy untouched). All 39 items hash-match the author's prior `.eliot` receipts (full reuse valid, zero new). I01-05 demand-start/idle-shutdown read in full this round as the acceptance anchor; remaining required items rest on verified prior reads.

## What the increment establishes (verified in source)

1. Real owner state throughout: pre-commit census goes Host journal → authenticated Kernel front-door → canonical ORS `load_runtime_lease_census_by_state_fence` (control_plane:925-971 read path; reconcile/terminalize paths re-read). Journal refs are never treated as census (lease_drain.rs:133-136 comment is enforced by construction).
2. Active obligations preserved: `terminalize_generation_leases_for_drain` retires only owner-inactive rows (control_plane:1507-1600, snapshot pass + per-row re-read/re-resolve + revision-guarded transition); any active owner fails closed and Kernel stays Ready; `Requested` fails closed everywhere (see P2-2).
3. Fence/process identity authenticated: request boundary binds resource_generation + authority epoch + supervision incarnation (protocol.rs:1398-1432); transport peer validated by pid + start_time_100ns + expected image on every call (lease_drain.rs:218-234, 506-520, 612-626); response message_id/digest/state/shape binding exact; supervision revoke checks 11 incarnation bindings + revision + post-commit verification (control_plane:1603-1680).
4. Recoverable pre-commit: `begin_precommit_drain` (lease_drain.rs:62-121) never writes DrainCommit; `Cancelled→Requested` re-entry (model.rs:2342); demand cancel with readiness revalidation incl. `control_ready && supervision_ready` (lib.rs:5464-5512) so post-revoke resume re-proves supervision rather than resurrecting terminal leases; 5-minute idle grace (main.rs:1236) with probe-failure-fails-safe (`note_probe_failure`, main.rs:1297-1306).
5. Commit/termination order: DrainCommit only after census proves no active owner (lib.rs:7956-7980); barrier invoked and cross-checked field-by-field incl. process identity (lib.rs:8066-8103); Kernel re-reads census and requires `is_fully_retired` + Draining state before `request_shutdown` (control_plane:940-978); observed exit requires exact process + complete/empty Job history + `Exited` before forgetting (lib.rs:3620-3658, 20s bound); Store terminates after Kernel (lib.rs:8115-8132); journal finalizes `StoppedClean` + clean marker (lib.rs:8134-8158); any failure records `DurableShutdownFailed` capsule + service-specific SCM code, never clean (lib.rs:8047-8052, 8068-8072, 8120-8132, main.rs:964-977).

## Defects

### P1 — none found

No path was found that fabricates owner state, skips fence/process authentication, commits before the owner census, terminates Store before Kernel, forgets the Kernel branch without observed exit, or publishes clean on failure. Compilation alone was not relied upon; every claim above traces to a read line.

### P2-1 — graceful-shutdown refusal is indistinguishable from transport failure (lib.rs:8104-8126)

`request_kernel_shutdown_after_retirement(&barrier).is_ok()` discards the error; any failure (including an active Kernel refusal because its re-read census is not terminal) falls into `terminate_kernel()` with only a lifecycle-observe line. A Kernel-side refusal means reality diverged from the barrier census; killing the Job then abandons a possibly-live obligation with no divergence record.
Correction required: distinguish refusal (`SessionFenced`/not-terminal) from transport/timeout. On refusal, re-run the pre-commit owner census: active → abort shutdown, resume the cancellable drain on the same generation (no commit has been bypassed); on transport/timeout → record the divergence evidence, then take the bounded fallback.

### P2-2 — `Requested`-state leases block stop/drain with no recovery owner and no deadline

`LeaseState::Requested => return Err(SessionFenced)` in `reconcile_runtime_lease_census` (control_plane.rs:1539), `terminalize_generation_leases_for_drain` (control_plane.rs:1672), hence in every Host census/barrier path. Safety direction is correct (never abandon an admitted obligation), but: the SCM loop (main.rs:884-905) retries forever on census error (30s `wait_hint` exceeded, service unresponsive); idle supervision resets grace forever via `note_probe_failure`. A stuck `Requested` lease (admitted, never activated) permanently wedges clean stop and idle drain.
Correction required: bound stop-loop retries with a deadline that degrades to `DEGRADED_RECOVERY` + WakeIntent/manual entrypoint per I1.5, and/or define `Requested`-state recovery (owner-readback-gated resolution) in a later hunk. Do not "fix" by ignoring `Requested`.

### P2-3 — scope note, not a code change here

The `#[cfg(not(windows))]` stop path (lib.rs:8022-8030) still commits `DrainCommit` with no owner census. Acceptable only because #1751 is Windows-scoped; it must never be presented as cross-platform acceptance.

## Recorded limitations (not defects of this source; assigned later)

- Stopped-installation bootstrap caller into SCM and the real #419 authenticated registration/renewal producer (peer-bound principal/session/connection/fence, handle-observed process identity) are absent — later code per brief.
- I1.5 steps 2–5 (durable-job checkpoint, module quiesce, receipt/outbox flush + WakeIntent persist/cancel, eliotd/store-bridge service stops) are not established in this increment; no `eliotd` handling appears in the diff.
- No E2E/runtime proof; full Windows/WinUI build gate and the acceptance campaign own verification (author's focused `cargo check` is compile evidence only).
- `DrainState::Failed` has no producer in this lane and no exit transition — unreachable today; any future writer must pair it with a recovery path.
- M2 seam stable at parent `552ee79a`; M2/A2/1137 copies untouched and unevaluated here.

## Remaining obligations before main delivery

1. Correct P2-1 (refusal vs transport distinction + re-census-or-record).
2. Correct P2-2 (deadline → degraded recovery for wedged census; Requested-state recovery defined).
3. Later phase: stopped-installation producer + #419 identity, I1.5 steps 2–5, E2E acceptance incl. same-generation cancel/resume proof.
4. Root owns push/merge/Issue closure; donor branches untouched by this review.
