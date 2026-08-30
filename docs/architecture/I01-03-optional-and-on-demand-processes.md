## I1.3. Optional and on-demand processes

### `eliot-dreamer.exe`

Separate AI service or server. Starts with the first Dreamer job or in a maintenance window, then stops after an idle period.

### `eliot-doctor.exe`

Short-lived diagnostic and repair worker. `eliotd` usually requests its start, but Kernel may cause it to start through Recovery Manifest when the application daemon is unavailable. A persistent Doctor agent is prohibited. Any canonical Doctor result applies only through the Kernel or Governor recovery gateway.

### `eliot-mod-<id>.exe`

Process Modules: code graph, LSP bridge, Researcher provider, external tool, cloud laboratory, model provider, report renderer, and other optional capabilities.

### `eliot-ui.exe`

Windows-native desktop client. The first implementation uses WinUI 3 on the stable Windows App SDK line as a thin C# user-session adapter; Rust remains the control plane and owner of all domain state. The Start Menu/desktop entry invokes the one-shot `eliot ui` bootstrap, which starts or reuses the authenticated User Broker and asks it to launch the UI as a broker-owned user-session child. The UI speaks only the role-filtered ControlBoard/Operator contract over authenticated local IPC and has no database, storage-bridge, package-manager or agent-runtime credentials of its own.

It hosts the Dreamer chat, project/onboarding views, agent and swarm launch controls, maintenance/configuration workflows, notifications and recovery guidance. Closing or crashing the UI does not stop active tasks, Dreamer jobs or the agent path. A browser surface may exist later as an optional compatibility/remote-view adapter, but it is not the primary Windows desktop surface.

### `eliot-user-broker.exe`

On-demand process inside an authenticated interactive Windows user session. It is required for routes whose subscription entitlement, credentials, desktop profile or host configuration belongs to that user rather than to the service account.

```text
Kernel / eliotd
→ issue scoped UserExecutionRequest
→ authenticate broker by installation ID + Windows SID + session ID + launch nonce
→ broker launches the exact approved runtime/adapter bundle in the user session
→ raw/normalized events, usage and effects return through EBP
→ Governor retains task, budget, authority, recovery and finish ownership.
```

The broker owns no canonical state, scheduler, route policy or durable attempt journal. It may materialize only explicitly delegated user-scoped credential/config handles, open the approved local Human surface, deliver user-session notifications and launch approved interactive routes or workspace adapters. User-owned filesystem, Git, LSP and professional-tool operations run through this branch when the service identity lacks the WorkScope ACL; every request carries exact roots, effect set and lease. The broker cannot widen paths, privacy class, budget, tools or child-agent envelope and does not expose a generic shell to the service.

The service does not manufacture an interactive logon token. The broker is started in user context by an approved per-user bootstrap — normally an agent bridge, the one-shot `eliot ui` launcher or a signed Task Scheduler entry created during installation — and then registers with Kernel. The native UI itself is never the bootstrap authority for the broker that owns it. The broker owns a scoped Job Object for the UI and launched runtimes, publishes process lineage and heartbeats, and exits after its user-session leases drain. Kernel and Watchdog verify the registered SID/session/process lineage; a broker surviving logoff or registration expiry loses launch/effect authority.

The active broker registration carries a short monotonic Kernel heartbeat/lease. Loss of Kernel heartbeat, registration expiry or epoch mismatch immediately stops new launches and new effects; already issued exact effects follow their operation permit and then the broker drains or terminates its Job Object. A broker never treats mere process survival as continuing authority.

If no matching interactive user session exists, subscription- or desktop-bound work becomes `DEFERRED_CAPACITY` or `ROUTE_UNAVAILABLE`. Background work may use only service-safe API/local routes approved for the service identity. ELIOT never copies a user's session secrets into a machine service merely to keep a route available.

### Canonical CLI and agent stdio shims

#### `eliot.exe`

One canonical user/agent/operator CLI. It is a short-lived surface over the same Kernel/Governor contracts and owns no semantic state, scheduler, policy or recovery journal. Command families are:

```text
eliot system ...
eliot bootstrap ...
eliot dev ...
eliot module ...
eliot instrument ...
eliot doctor ...
eliot recovery ...
eliot backup ...
eliot maintenance ...
eliot ui
eliot dashboard
```

`eliotctl` and `eliot-dev` are not canonical command names. Temporary migration shims, if shipped, only forward to `eliot` and are excluded from generated help/contracts after their declared expiry. The current Appendix J artifact is a bootstrap retained candidate catalogue; only a future admitted command catalogue plus compiled `eliot --help`, exact source handles and execution receipts can establish support. Prose cannot define a second CLI.

### `eliot-notify.exe`

Per-user, one-shot notification adapter. Normal launch is through the authorized User Broker. For control-plane loss, installation may register a signed Task Scheduler fallback that launches it in an existing authorized user session to read only the signed Watchdog notification envelope. It owns no canonical state and cannot execute repair or authority transitions. Its processes belong to the User Broker Job Object or the installer-owned one-shot scheduled-task boundary and terminate after delivery.


Thin processes `eliot-agent-bridge.exe --profile <id>`. They:

```text
start ELIOT through SCM when needed;
connect to the Kernel pipe;
translate the host protocol into EBP or MCP;
contain no durable state;
receive no database credentials.
```

### `eliot-testd.exe`

On-demand isolated build/test/simulation service. It is the execution plane for `InstrumentRunner`, not a second scheduler or task database.

```text
eliotd / InstrumentRunner
→ Durable TestdJob + exact InstrumentProfile + State Fence
→ Kernel starts/adopts an approved `eliot-testd` generation
→ testd provisions worktree/build sandbox and tool processes
→ raw artifacts + normalized evidence + VerificationReceipt
→ Governor admission and task verifier binding.
```

`eliot-testd` owns only active build/test process trees, temporary build roots, local dependency caches and parser checkpoints. It has no SurrealDB credentials, cannot finish tasks, cannot change agent budgets and cannot turn a tool exit code into canonical truth. It uses the same `eliot-process-windows` execution semantics as every other governed native tool. A compile storm consumes a dedicated execution pool and cannot consume Kernel Control Reserve.

During D0 the contract may be hosted by a thin separate process with only `fmt/check/test` profiles. Before agent-generated Rust, fuzzing, mutation, simulation or component promotion is admitted, the separate process boundary is mandatory.

### `eliot-wasm-host.exe`

On-demand Wasmtime Component Model host. It runs immutable component generations under explicit WIT worlds and capability grants. It has no canonical DB credentials, raw process capability, user secrets or general filesystem/network access unless a specific imported capability is present in the admitted world.

The host owns compiled component caches, instance pools, Store limits and shadow/canary execution. Governor owns component admission, policy, routing, effects and promotion decisions. A trap terminates the affected Store/instance or generation; it does not mutate Kernel state.

### `eliot-native-worker-<class>.exe`

Generic isolated native process generation for OS-heavy or promoted component code. It uses versioned EBP/native protocol and is pinned to one artifact manifest, capability envelope and Authority Epoch. Typical classes are compiler/test worker, LSP/code-intelligence worker, browser/professional-tool worker and measured native policy worker.

The native worker never shares Rust references or allocator ownership with Kernel/`eliotd`. Direct `.dll`/`.so` loading into those processes is not an admitted replacement mechanism.

