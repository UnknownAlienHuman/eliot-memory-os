## I14.16. Kernel and Host update

Kernel is replaced only by Host Supervisor through an exclusive installation lineage.

### Kernel side-by-side cutover

Host owns `KernelActivationRecord` inside the separate crash-safe HostStateJournal, outside Kernel ORS and Canonical Memory. It contains only installation epoch, approved artifact hash, active/candidate pipe identity, one-time activation nonce and activation state; it cannot answer semantic questions or issue project authority.

```text
1. quiesce application, reconcile canonical writes and checkpoint ORS;
2. start candidate Kernel on a candidate pipe in `shadow_no_authority` mode;
3. candidate may inspect immutable/read-only snapshots and run compatibility checks;
4. candidate cannot write ORS/store, issue Session/lease/epoch or accept normal work;
5. old Kernel writes a KernelHandoffReceipt, closes admission/front door,
   releases KernelOwner/ORS locks and exits;
6. Host verifies process termination and lock release, advances HostInstallationEpoch
   and writes a one-time activation nonce to KernelActivationRecord;
7. candidate presents the nonce, acquires the exclusive ORS/KernelOwner locks,
   reconciles the handoff, creates a strictly newer/global-distinct authority lineage
   and opens the stable front-door pipe;
8. Host marks the candidate active only after KernelReadyReceipt;
9. rollback repeats the process with another activation nonce and newer lineage.
```

The activation-record transition plus exclusive OS locks is the linearization boundary; no claim is made about impossible atomicity across independent OS resources. Agent bridges retry during the short front-door gap. Two Kernels may coexist only while the candidate has zero authority. If old-process termination, lock exclusivity, handoff integrity or activation nonce ownership cannot be proven, cutover stops and manual recovery is required. Kernel change runs T3/T4 tests.

### Host Supervisor replacement

Host cannot hot-load itself. Installer/SCM performs side-by-side replacement:

```text
confirm independent Watchdog/fallback and rollback artifact;
cleanly stop Kernel and preserve recovery manifest;
install candidate Host at immutable path;
update SCM binary/config through one explicit installer operation and read back the observed SCM configuration;
start candidate and verify HostStateJournal, build registry, Kernel Job Object ownership and rollback control;
restore the prior observed service configuration if startup proof fails.
```

A short visible control-plane gap is preferable to a recursive supervisor chain.

