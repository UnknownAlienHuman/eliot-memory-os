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
