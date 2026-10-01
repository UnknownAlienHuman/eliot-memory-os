# eliot-live-canary

This tool exercises only retained production authority contours. It has five
bounded pulses:

1. read-only installation, retained-root, journal and Host/Watchdog SCM
   inspection;
2. read-only readiness and dynamic-supervision inspection;
3. Kernel restart through authenticated Host `RestartKernel`/
   `ReconcileKernelRestart` only;
4. Store recovery through authenticated Host `RecoverStore`/
   `ReconcileStoreRecovery` only;
5. elevated EliotHost service stop/clean/start through the exact active
   installer-owned SCM approval. Pulse 5 never registers, updates, deletes, or
   directly opens a raw SCM service handle. It issues one identity-bound stop,
   waits by read-only inspection for `Stopped`, proves the final `CleanMarker`
   and released Host owner lease, issues one start, then requires a direct-child
   Host epoch, fresh Host/Kernel nonces and readiness/ORS/eliotd evidence while
   the exact Watchdog PID/start/image remains unchanged.

## #1750 Windows SCM-alive / heartbeat-unresponsive discriminator

The discriminator is **not implemented by the current canary pulses**. Pulse 1
and Pulse 2 are read-only prerequisites only: they can show the currently
approved Host/Watchdog SCM registration, PID/start/image, retained Host
journal, readiness projection, and current supervision receipt. They do not
pause a Watchdog heartbeat responder, read the Kernel's original supervision
proof/fence revocation consumer, invoke the provisioned Operator Material
frontdoor, or observe a refusal-before-effect response. A Pulse 1 or 2 `PASS`
is never evidence for this discriminator.

The production Material callers are Kernel-owned request routes; this canary
does not have their provisioned Operator grant or original Operator client. Do
not replace that path with a canary pipe request, caller-supplied JSON,
`HostRuntimeControl`, a fabricated `OriginControlPresentation`, a test signer,
or a synthetic receipt. The current Runtime Status contract also does not
expose the Kernel consumer's exact revoked proof/fence. The live procedure
therefore remains `NOT_EXECUTED` until both original-owner evidence surfaces
are available.

For a later authorized live run, an operator must use the already provisioned
Windows installation and the original Operator frontdoor/capability. Preserve
one original admitted heartbeat proof and its original receive/deadline and
Kernel State Fence. Before the deadline expires, an independently approved,
signed, reversible Windows observer must suspend only the exact Watchdog
process incarnation after recording its SCM service name, PID, creation time,
and image. The observer must verify that the same PID/start/image remains
`Running`; service STOP, process termination, restart, or a replacement PID
does not satisfy the discriminator. While that responder is unresponsive and
before the original proof deadline, the operator must submit the selected
approved Material request through the original Operator client. Capture the
original Kernel consumer response proving refusal before any Material write,
bound to that request and the original proof/fence, plus the Kernel revocation
readback. Resume the same process immediately through the same reversible
observer and verify the same SCM incarnation and heartbeat recovery. Never
extend or refresh the original heartbeat deadline by re-reading SCM.

The operation is `INCOMPLETE`/`NOT_EXECUTED` if the installed services, signed
reversible observer, provisioned Operator client/grant, original Kernel proof
and deadline, Kernel revocation readback, or refusal-before-effect response is
missing. This repository does not provide an automatic pause/resume command or
an effect-free Material admission probe; select a safe, approved canary-target
Material operation with the installation owner before running. Preserve the
SCM snapshots, original heartbeat identity/deadline, exact Kernel fence and
revocation response, original Operator response, and before/after effect
readback together as one evidence set. Source inspection, a fixture, or a
Pulse 1/2 status snapshot cannot be reported as runtime acceptance.

Pulse 2 passes only when the runtime-status verifier projects the exact current
Active ORS head, fresh signature context and immutable Watchdog publication,
and the canary independently reconstructs the same dynamic incarnation from
the retained Host journal. Missing, stale or substituted evidence fails closed.

Fault pulses require `--execute-faults` and an actually elevated Windows token
with enabled built-in Administrators membership; an arbitrary CLI string is
not authority. The canary authenticates the pipe server as the exact
SCM-observed EliotHost LocalService process (PID, creation time and image).
A response-loss path for Pulses 3 and 4 reconciles the exact request identity
once; it never retries a fresh mutation. Pulse 5 treats an unknown SCM effect as
fail-closed and never resends it. Evidence directories are retained across all
non-reparse ancestors, and files use create-new/no-follow creation plus pinned
readback. Nonces and raw request payloads are excluded from evidence.

Example (read-only Pulse 1):

```text
eliot-live-canary --host-state-root <active-manifest.runtime_launch.runtime_state_roots.host_state_root> --evidence-dir <protected-canary-evidence-dir> --pulse 1
```

Fault execution is intentionally explicit:

```text
eliot-live-canary --host-state-root ... --evidence-dir ... --pulse 3 --execute-faults
```

Pulse 5 uses the same explicit mutation gate:

```text
eliot-live-canary --host-state-root ... --evidence-dir ... --pulse 5 --execute-faults
```

The supplied Host root is only a selector for retained readback. Before any
Pulse 5 SCM effect, the canary requires it to equal the exact `host_state_root`
in the active committed installation manifest and derives both service requests
from that generation's durable installer approvals.
