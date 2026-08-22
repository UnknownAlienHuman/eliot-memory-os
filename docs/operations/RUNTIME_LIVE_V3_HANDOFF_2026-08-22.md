# ELIOT Runtime Live V3 — integration handoff (2026-08-22)

## Canonical integration point

- Repository: `UnknownAlienHuman/eliot-memory-os`
- Branch: `codex/runtime-live-v3-integration-staging`
- Accepted local release-handoff candidate: `4bf70d9fd0454923c7fbd4da3661b76dbb1e1707` before the documentation merge.
- Current pushed staging ref: `origin/codex/runtime-live-v3-integration-staging` at `1e2d2cfdcf3592a4910eb82206b434e4985645ca`; it must not be called current until the accepted candidate is fast-forwarded and the remote SHA is read back.
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
| Live canary | `bins/eliot`, `workspace/tools/eliot-live-canary` | Source paths for Pulses 1–5 and the canonical manifest-bound `eliot runtime canary` entrypoint are integrated. Production evidence is marker-last and bound to the retained active registry, manifest, fence, Phase-B receipt and protected evidence-root identity. No live machine evidence exists yet. |

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
- `4c2b7c7` — production `eliot runtime canary`, exact active-manifest evidence root, retained Host/evidence object identity and marker-last authoritative completion.
- `2117967` — fail-closed six-PE Authenticode/RFC3161 release finalizer with typed `COMMITTED_UNKNOWN` reconciliation.
- `c28757f` — materializer publication receipt bound to the generation plan.
- `80174b8` — retained-handle Authenticode verification and certificate evidence hardening.
- `9c9c426`, `a63ea6c`, `ac7cc63` — unbound Generate/Auth paths removed; generation planning requires published source authority.
- `f7135aa` — durable `StagePackage` source observations and strict transaction wire v21.
- `1a80462`, `18745e7`, `78d56e6` — retained publication identity, Redb recovery and handle-relative no-replace publication.
- `59a07ac`, `80346fe` — durable source-publication journal v3 with exact old-temp restart authority and store admission gates.
- `4bf70d9f` — atomic same-parent Redb journal publication; monotonic single-write-transaction journal CAS; and independent sealed WinTrust revalidation of all six executable roles, including existing/response-loss fast paths, before privileged installation effects.

## Verified in focused source gates

- Pulse 5 foundation: all-target check; canary 14/14; Host-state 104/104; focused Windows enabled-Administrators read-only test; formatting/diff; touched-crate no-deps Clippy.
- Final Pulse 5 correction: canary all-target check; 21/21 tests; strict no-deps Clippy; formatting and diff checks. Independent source audits accepted static-generation reachability, same-path binary/config substitution rejection, read-only ACL behavior and single-start cleanup.
- Production canary invocation: `eliot` bin 23/23; `eliot-live-canary` 23/23; all-target `eliot` check; strict no-deps Clippy; formatting/diff. Independent audit rejected the first publication ordering, then accepted the corrected marker-last and exact snapshot-to-retained-handle identity chain.
- First-install roots: focused all-target checks; 12 Windows installer-root primitive tests; SystemService planner test; v18-to-v19 migration test; formatting/diff.
- Earlier integrated milestones carry their own focused test and strict lint evidence in Git history.
- Signed finalizer: both PowerShell 7 and Windows PowerShell 5.1 provider-free suites pass; the release-security smoke passes. The tests cover exact six-role signing, RFC3161 evidence, retained identity/hash contours, no-replace publication, partial-output quarantine and exit 75 for `COMMITTED_UNKNOWN`.
- Source authority candidate `4bf70d9f`: metadata/fmt/diff pass; all-target check for `eliot-installation`, `eliot-platform-windows` and `eliot`; Redb publication tests 18/18; `eliot` bin 38/38; package-staging tests 32/32; strict no-deps Clippy passes with the repository's established baseline lint waivers. The production dependency graph does not enable `eliot-installation/test-support`.
- The unfiltered installation suite remains 202/209 on this host: four Windows Credential/provider tests fail with the pre-existing `ProviderError::Unavailable`, and three following shared-mutex failures pass independently. They are machine-provider gaps, not live acceptance evidence.

These checks prove source behavior only. They do not prove live service installation or `RUNTIME_LIVE_CANARY`.

## Mandatory remaining work

### Signed runtime bundle

The unsigned builder remains intentionally separate from the implemented fail-closed finalizer. The finalizer selects an explicit certificate with a private key and Code Signing EKU, invokes `signtool.exe` for exactly six runtime PE roles with an explicit RFC3161 endpoint, independently rereads signer/timestamp/hash evidence, and never promotes a mutable published directory to installation authority. The Rust materializer then performs the first authoritative nine-role handoff and independently reruns sealed WinTrust checks.

No real certificate has yet been installed/selected and no release binary has yet been signed in this handoff. The next external step is to provision the user-approved development signing certificate, choose the RFC3161 endpoint, sign the exact built candidate, run public-certificate `-VerifyBundle`, and feed that verified snapshot to `eliot installation materialize-source-bundle`. A source-only green finalizer is not a signed release.

### Live Windows evidence

No real SCM/service mutation was executed in these source lanes. Required next live sequence is:

1. Build the exact unsigned release and finalize/sign its six PE roles with the selected certificate and RFC3161 timestamp.
2. Run public-certificate `-VerifyBundle`; reconcile `COMMITTED_UNKNOWN` read-only and materialize the exact nine-role Phase-A source bundle until `SOURCE_BUNDLE_MATERIALIZED` is durably read back.
3. Run elevated installation plan/apply for a disposable SystemService installation.
4. Run and persist Pulses 1–5 against the same installation identity.
5. Verify remote/result digests, journal/registry readback, Store filesystem placement, SCM identities and absence of the legacy writer.

Pulses 6–8 remain post-canary recovery/removal work. They may report exact blockers, but may not be silently marked complete.

## Repository cleanup state

The historical 2026-08-22 cleanup note reported eight clean staging-contained worktrees removed and 183,023,726 bytes reclaimed, but no independent cleanup report is currently available; treat those numbers as historical, not acceptance evidence. The fresh pre-push readback is 273 registered worktrees and 257 local `codex/*` refs; only 39 local refs are ancestors of accepted base `80346fe`. Counts may change while agents are active.

The remaining unique non-ancestor tips are not classified as garbage. Recompute reachability, patch equivalence, dirty state and process liveness before every deletion; archive or integrate unique commits first. Do not repeat the old Cargo-target size estimate without a fresh scan. Preserve all `.eliot/inbox` evidence until its owning ingestion/disposition is explicit.

## Exact restart point

Accept `4bf70d9fd0454923c7fbd4da3661b76dbb1e1707` plus this handoff update only after independent authority/recovery re-audits, then fast-forward and read back `origin/codex/runtime-live-v3-integration-staging`. The canonical canary, finalizer and durable source-publication seams are source-complete. Next: provision the approved development signing identity, produce and verify the exact signed bundle, materialize it, perform the elevated disposable installation, and obtain live Pulses 1–5 evidence. Do not claim `RUNTIME_LIVE_CANARY` before that sequence succeeds.
