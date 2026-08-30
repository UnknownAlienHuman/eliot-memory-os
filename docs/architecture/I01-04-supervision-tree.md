## I1.4. Supervision tree

```text
Windows SCM
├─ Eliot Host service
│  ├─ Host-owned Kernel Job Object (`KILL_ON_JOB_CLOSE`)
│  │  └─ eliot-kernel
│  │     ├─ eliot-store-surreal
│  │     ├─ BlobStore capability (co-located or optional process generation)
│  │     ├─ eliotd
│  │     ├─ eliot-testd
│  │     │  └─ governed Cargo/rustc/test/sim process trees
│  │     ├─ eliot-wasm-host
│  │     ├─ eliot-native-worker-*
│  │     ├─ eliot-dreamer
│  │     ├─ eliot-doctor
│  │     ├─ eliot-mod-*
│  │     └─ service-safe agent/model jobs
│  └─ Host-owned canonical-store Job Object (`KILL_ON_JOB_CLOSE`)
│     └─ surreal.exe
└─ Eliot Watchdog service

Authorized interactive Windows user session
├─ eliot CLI (one-shot)
├─ eliot-user-broker
│  ├─ eliot-ui in the broker-owned Job Object
│  └─ subscription/desktop-bound runtimes in the broker-owned Job Object
└─ eliot-notify (one-shot via broker or signed scheduled fallback)
```

The User Broker branch is deliberately outside SCM and Host Job Objects. It is supervised in the interactive user's security context, while Kernel owns only registration, route admission, scoped launch leases and reconciliation. Exactly one active broker registration is allowed per installation + Windows SID + interactive session; a new `UserBrokerEpoch` fences the previous registration, and processes from an old broker epoch cannot receive new effect authority.

Watchdog is an SCM-owned sibling service. Kernel and the canonical-store process reside in separate Host-owned Job Objects: restarting Kernel or daemon need not stop the database process, while Host failure terminates both Host lineages, after which SCM and Watchdog initiate recovery. Kernel always belongs to exactly one `HostInstallationEpoch` and dedicated Job Object. Unexpected Kernel exit causes Host to close or terminate the entire Kernel Job Object lineage before any replacement Kernel can activate; surviving child PIDs are never adopted as the new lineage. The separate canonical-store branch may remain running, but no bridge, daemon, or Module from the failed Kernel branch retains authority. Loss of the Host process closes Job Objects and terminates managed process lineages; a detached Kernel or store process is not treated as continuing active supervision or authority. If the OS cannot prove termination, Watchdog marks the lineage suspect, closes normal admission, and requires the new Host to perform containment, fencing, and a store-integrity probe first.

`eliotd` makes semantic lifecycle decisions; Kernel physically performs start, stop, switch, and fence. Service-safe Process Modules, Dreamer, Doctor, and service-safe agent jobs are Kernel-supervised siblings of the current `eliotd`, so daemon restart neither destroys them automatically nor leaves them with old authority. Native UI and subscription or desktop-bound agent jobs belong to the authenticated User Broker lineage; Kernel owns only their registration, admission, leases, and reconciliation.

On loss of the active daemon generation, Kernel immediately revokes daemon-issued effect leases. Read-only or rebuildable Modules may remain warm, but new results are held as unbound observations until a new compatible daemon and fence exist. Effect-capable Modules and agent jobs checkpoint, pause, or terminate according to manifest.

Restart semantics are ELIOT contracts, not a requirement to use an Erlang runtime or framework:

```text
restart_self
  — local restart of one independent generation;

restart_dependents
  — restart only downstream capabilities whose state or fence depends on the failed upstream;

restart_branch
  — restart a small tightly coupled branch when partial state is more dangerous than a brief outage;

quarantine
  — after restart-budget exhaustion, disable the capability while Problem State remains open.
```

The hard-dependency graph defines startup, drain, and restart order and remains acyclic. Siblings without an invalidated dependency are not restarted.

### Modern `let it crash`

`Let it crash` applies to an isolated executor—not to data, authority, or an irreversible effect.

```text
expected error
→ typed result and Recovery Directive;

unexpected internal defect
→ task or process generation terminates;
→ supervisor records evidence;
→ stale Authority Epoch is rejected;
→ replacement starts from canonical or checkpointed state;
→ an unknown external outcome is reconciled by receipt;
→ repeated crash leads to quarantine and escalation.
```

It is prohibited to catch a panic and continue with unknown mutable state, restart a child indefinitely, repeat an effect without idempotency and reconciliation, treat restart as resolution of Problem State, or terminate independent branches because an optional Module failed.

