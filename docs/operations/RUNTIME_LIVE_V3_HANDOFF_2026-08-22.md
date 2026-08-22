# ELIOT Runtime Live V3 — integration handoff (2026-08-22)

## Canonical integration point

- Repository: `UnknownAlienHuman/eliot-memory-os`
- Branch: `codex/runtime-live-v3-integration-staging`
- Source task: `C:\Users\kleym\Downloads\ELIOT_CODEX_RUNTIME_LIVE_V3_2026-08-18.md`
- This branch is an integration staging branch. It is not a `RUNTIME_LIVE_CANARY` completion claim.
- Longstanding untracked `.eliot/inbox/*.surql` files are preserved and are not part of the Git tree.

## Project map

| Contour | Canonical implementation | Current state |
|---|---|---|
| Installer transaction and registry | `crates/kernel/eliot-installation` | Durable plan/apply/recover, strict wire migrations, Phase-A/Phase-B, approved generation and SCM receipts are integrated. |
| Windows installation effects | `crates/kernel/eliot-platform-windows` | Protected roots, service registration/readback, EliotHost-to-Watchdog service-control DACL, supervision authority and exact process/Job observations are integrated. |
| Host operational authority | `bins/eliot-host`, `crates/kernel/eliot-host-state`, `crates/surfaces/eliot-host-service` | HostStateJournal is the operational owner; Kernel/Store recovery and authenticated runtime-control are integrated. |
| Kernel and eliotd | `bins/eliot-kernel`, `bins/eliotd`, `crates/kernel/eliot-kernel-service` | Durable activation, physical process authority, supervision signing/reconciliation and authenticated ProbeReady are integrated. |
| Store | `bins/eliot-store-surreal`, `crates/storage/eliot-store-surreal-adapter` | Canonical runtime roots, provider process/socket identity and recovery contour are integrated. |
| Watchdog and runtime status | `bins/eliot-watchdog`, `workspace/tools/eliot-runtime-status` | Installer-owned registration, verified ORS/publication consumption and fail-closed status projection are integrated. |
| Live canary | `workspace/tools/eliot-live-canary` | Source paths for Pulses 1–5 are integrated. Pulse 5 requires a fresh Store/Host/Kernel/readiness/supervision contour and owns bounded post-Stop cleanup. No live machine evidence exists yet. |

## Integrated milestone lineage

- `4004564` — provisioned supervision authority.
- `07f1b65` — supervision consumers bound to current ORS authority.
- `5a3e26e` — supervision/readiness lifecycle composition.
- `99677cd` — honest source paths for live canary Pulses 1–4.
- `075fadd` — installer-owned Watchdog service-control grant.
- `334bf60` — bounded SCM Host stop/start Pulse 5 candidate.
- `7dcdf43` — first-install profiled root hierarchy, exact staging root and protected `canary-evidence` root.
- `facc3c0` — Pulse 5 fresh Store proof and stop-owned single-start reconciliation correction.
- `7faacee` — Pulse 5 installer-approved Store executable/materialized-config attestation with production-reachable static authority generation.
- `7cc1730` — read-only runtime leases for Store attestation; canary never repairs or rewrites ACLs.

## Verified in focused source gates

- Pulse 5 foundation: all-target check; canary 14/14; Host-state 104/104; focused Windows enabled-Administrators read-only test; formatting/diff; touched-crate no-deps Clippy.
- Final Pulse 5 correction: canary all-target check; 21/21 tests; strict no-deps Clippy; formatting and diff checks. Independent source audits accepted static-generation reachability, same-path binary/config substitution rejection, read-only ACL behavior and single-start cleanup.
- First-install roots: focused all-target checks; 12 Windows installer-root primitive tests; SystemService planner test; v18-to-v19 migration test; formatting/diff.
- Earlier integrated milestones carry their own focused test and strict lint evidence in Git history.

These checks prove source behavior only. They do not prove live service installation or `RUNTIME_LIVE_CANARY`.

## Mandatory remaining work

### Production canary invocation and evidence

`eliot-live-canary` is currently a workspace binary. Publish one canonical operator invocation, preferably through the already shipped `eliot.exe` CLI, without adding a tenth runtime role to the exact nine-role generation bundle.

Bind evidence output to `RuntimeStateRoots::canary_evidence_root()` from the active manifest and retain/verify the protected root. Do not accept an arbitrary caller-provided directory as production authority.

### Signed runtime bundle

The release pipeline intentionally emits unsigned binaries, while the source-bundle materializer correctly requires `AuthenticodeVerdict::Valid` for runtime executables. No usable code-signing certificate with private key was observed in the machine certificate stores during this run. Do not weaken Authenticode. A signed and timestamped exact bundle, or an explicitly approved development-signing trust setup, is required before Pulse 1.

### Live Windows evidence

No real SCM/service mutation was executed in these source lanes. Required next live sequence is:

1. Build/sign the exact bundle and materialize the nine-role Phase-A source bundle.
2. Run elevated installation plan/apply for a disposable SystemService installation.
3. Run and persist Pulses 1–5 against the same installation identity.
4. Verify remote/result digests, journal/registry readback, Store filesystem placement, SCM identities and absence of the legacy writer.

Pulses 6–8 remain post-canary recovery/removal work. They may report exact blockers, but may not be silently marked complete.

## Repository cleanup state

The 2026-08-22 exact inventory found 269 registered worktrees and 253 local `codex/*` refs before cleanup: 44 local tips were ancestors of staging, two were tree-equivalent, 209 were unique non-ancestors and the remainder were dirty, live-process-bound or otherwise unknown. Eight clean, non-live, staging-contained superseded worktrees and their local branches were removed without force; 183,023,726 bytes (174.55 MiB) were reclaimed. Current readback is 262 worktrees and 246 local `codex/*` refs because one new active Pulse 5 correction worktree appeared during cleanup.

The remaining unique non-ancestor tips are not classified as garbage. Recompute reachability and liveness before every later deletion; archive or integrate unique commits first. Cargo target directories account for about 17.11 GiB but were not removed while agents were compiling. Preserve all `.eliot/inbox` evidence until its owning ingestion/disposition is explicit.

## Exact restart point

Resume from `origin/codex/runtime-live-v3-integration-staging`. Wire the canonical manifest-bound canary invocation/evidence root through `eliot.exe`, then complete the signed-bundle decision. Only after those source gates pass should live Pulses 1–5 begin.
