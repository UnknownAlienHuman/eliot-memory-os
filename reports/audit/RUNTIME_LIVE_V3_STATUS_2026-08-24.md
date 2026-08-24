# Runtime Live V3 status — 2026-08-24

## Executive status

`NOT RUNTIME LIVE`. The audited product-source baseline is
`f63675ba0539aca21e813fe9ba2c0076e1badb1f`. The package-manifest digest defect
that blocked the previous e51 installation plan was fixed and verified in
source. A fresh f636 Windows x64 bundle was built, signed and independently
publicly verified. No successful f636 Phase-A materialization, elevated Apply,
SCM registration, service start, runtime-status pass or Canary Pulses 1–5 has
been established. Subsequent graph/docs-only commits do not change the product
bytes described by this report.

This distinction is required by the Runtime Live V3 task: tests, a signed
bundle, a plan, a process that stays alive, or an agent verdict do not count as
live completion without fresh machine evidence.

## What is closed on f636

### Source correction

`crates/kernel/eliot-installation/src/lib.rs` and
`crates/kernel/eliot-installation/src/package_planner.rs` now validate the
package manifest digest in the package-digest domain. Candidate-manifest and
package-manifest digests remain distinct and are checked independently by
package inspection, reconciliation, execution, package binding and the sealed
planner. A deterministic regression test rejects candidate/package/generation
mutations without relying on the protected machine state.

The previous e51 failure was a real product defect: valid plans carried a
candidate manifest digest and a different package manifest digest, while three
package paths compared the package digest to the candidate digest. It failed
before source observation. The old e51 transaction remains terminal and is not
reused or retried.

### External source corroboration

The exact-f636 source-audit pool produced 25+ valid external `ACCEPT` results,
with zero valid `REJECT`, P0 or P1 findings for this source revision. This is
corroborating review evidence only; it does not replace Cargo diagnostics,
installer receipts, SCM readback or live canary evidence.

### Rust gates

- Focused digest-binding tests: pass.
- Full `eliot-installation` suite: 239/239 pass on f636.
- Relevant all-target check: pass.
- Formatting and `git diff --check`: pass.
- Cargo.lock was not changed by the source fix.
- Clippy has eight pre-existing warnings in untouched
  `eliot-platform-windows`; no touched-file failure was observed. This is a
  lint baseline, not a reason to claim runtime acceptance.

### Release artifact

Fresh artifact root:

```text
C:\Users\kleym\AppData\Local\Eliot\release-work\run-f63675b-20260824-01
```

The build, finalizer and public verification logs report:

- source commit: `f63675ba0539aca21e813fe9ba2c0076e1badb1f`;
- release version: `0.1.0-rc1`;
- release verifier inventory: 421 manifest entries; an independent physical
  directory readback counted 422 files, including the self-excluded
  `SHA256SUMS.json` manifest;
- signed scope: six runtime materializer PE roles plus the install-authoritative `runtime/eliot.exe` CLI role;
- Authenticode/WinTrust: 7/7 valid;
- signer thumbprint: `FA2E37C6BF28E31154E7047552A22EB020AD9467`;
- code-signing EKU: present;
- RFC3161 timestamp: `http://timestamp.digicert.com`;
- timestamp CMS/message-imprint evidence: independently read back;
- public `VerifyBundle`: `VERIFIED_SIGNED` and read-only; it is not installation authority.

The signed bundle is therefore an input to Phase-A, not proof that Phase-A or
Apply happened.

## What remains open

| Gate | Status | Evidence ceiling |
|---|---|---|
| Correct SystemService Phase-A | **OPEN** | No fresh exact nine-role materialization and no accepted Phase-A plan/store readback |
| Elevated `installation apply` | **OPEN** | No f636 Apply result; no active installation transaction |
| Protected roots/ACLs and ApprovedGenerationRegistry | **OPEN** | No fresh f636 registry/receipt evidence |
| `EliotHost` SCM registration/start | **OPEN** | Current SCM readback: service absent |
| `EliotWatchdog` SCM registration/start | **OPEN** | Current SCM readback: service absent |
| Host/Kernel/Store/`eliotd` processes and Job Objects | **OPEN** | Current process readback: `eliot-host`, `eliot-watchdog`, `eliot-kernel`, `eliot-store-surreal` and `eliotd` absent; no live Job/endpoint evidence |
| `eliot runtime status --json` | **OPEN** | No `ACTIVE_VERIFIED` status from a real installation |
| Canary Pulses 1–5 | **OPEN** | No production canary evidence or PASS marker |
| `RUNTIME_LIVE_CANARY` acceptance | **BLOCKED** | All preceding live gates are prerequisites |

The next legal run is one fresh, elevated `system_service` Phase-A using
`%ProgramData%` profile roots, a new transaction identity and
`apply_run=false`, followed by the normal installation Apply and independent
SCM/process/runtime/canary readback. The abandoned e51 transaction and any
PortableDev attempt are not valid substitutes.

## Execution blockers observed during this run

These are operational execution failures, not additional product acceptance:

1. A non-elevated Phase-A preflight could not inspect the existing protected
   `C:\ProgramData\Eliot\packages` ACL. This correctly stopped before output
   creation; weakening the ACL is not an acceptable workaround.
2. One helper used an unavailable PowerShell
   `[RandomNumberGenerator]::Fill()` API. It failed before product effects and
   was replaced in the helper design with a compatible RNG call.
3. One later helper was caught with the wrong `portable_dev` profile and old
   e51-shaped IDs. Its exact process was stopped before materialization; it
   created no accepted output bundle, plan, transaction store, service or SCM
   effect. That root is quarantined/rejected, not evidence of success.

Current HKLM readback reports `EnableLUA=0`: normal UAC is disabled, so the
required SystemService Phase-A cannot proceed through the normal elevation
boundary. The policy was not changed by this run. Restore the intended UAC
policy explicitly, then perform the required Windows activation/reboot before
attempting the fresh elevated Phase-A. No installer retry, ACL weakening,
service registration, SCM mutation or forced recovery is implied by this
report.

## Cleanup readback

The final cleanup pass removed 3,582 exact roots containing 31,082 files, for
21,565,769,975 bytes total. The final delta removed eight additional exact
roots (+15,761 files and 10,209,615,746 bytes), covering residual builds, old
packages, production-run outputs, stale releases, canary outputs and temporary
roots. The earlier deletion of `external-c95-audit` followed a live=0 readback;
its sandbox is gone, while the sibling external launch guard was retained.
The current f636 release root, the Claude audit report, active instances and
the external launch guard are retained; the f636 root remains a verified build
input, not disposable cleanup. Repository source, Git state,
`C:\ProgramData`, and certificates were read back as untouched by that cleanup.

## Historical/source-only limitations

- Existing provider/credential tests have machine-dependent failures in the
  Windows Credential Manager contour (`ProviderError::Unavailable`); they are
  not live-runtime proof.
- Existing Surreal store fixture failures involving invalid supervision
  authority remain source/test-environment evidence, not a successful live
  store proof.
- The source handoff documents describe integrated Host, Kernel, Store,
  Watchdog, runtime-status and canary paths, but explicitly state that no live
  machine evidence exists. They must not be promoted to `DONE_VERIFIED` by
  prose alone.
- External source audits are corroborating review evidence only. They do not
  replace Cargo, installer receipts, SCM readback or the production canary.

## Required acceptance evidence

The project may be called Runtime Live only after all of the following are
freshly read back for the same installation/generation/manifest:

1. Phase-A exact nine-role materializer receipt and immutable plan/store.
2. Elevated Apply reaches `ACTIVE_VERIFIED` with registry, root, ACL and
   transaction evidence.
3. `EliotHost` and `EliotWatchdog` SCM configuration, service account and
   process identities match the approved manifest.
4. Host, Kernel, Store, `eliotd`, endpoint and Job Object observations pass;
   Store files are confined to the declared Store data root.
5. `eliot runtime status --json` independently reports the bound healthy
   state, including fresh readiness evidence rather than process liveness.
6. `eliot runtime canary` executes Pulses 1–5 against that same identity,
   with the required fault pulses, and produces the protected marker-last PASS
   evidence.

Until then the honest disposition is `NOT RUNTIME LIVE`, not `DONE`.
