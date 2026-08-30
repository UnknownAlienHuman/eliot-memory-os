# Concise decision

ELIOT is implemented neither as one large executable nor as a scatter of DLLs. It consists of a small resilient control Kernel, a replaceable application daemon, and replaceable process Modules. The target production topology appears below; early delivery depths may temporarily co-locate a capability behind the same public contract when its layer explicitly permits this and no second owner is created.

Source topology intentionally contains many narrow Cargo crates. A crate is an ordinary boundary for compilation, package-selective testing, dependency containment, and agent delivery. Causal and lifecycle ownership belongs to the `FunctionalCapabilityCell` or service contract and is mapped explicitly in the manifest; several tightly coupled cells may share one crate. A process generation is a broader boundary for failure, authority, and hot replacement. ELIOT does not turn every crate into a microservice.

```text
Windows Service Control Manager
├─ Eliot Host service (`eliot-host.exe`)
│  ├─ Host-owned Kernel Job Object
│  │  └─ `eliot-kernel.exe`       identity, fencing, ORS, control reserve,
│  │     │                        canonical transition gateway, recovery
│  │     ├─ `eliot-store-surreal.exe` ── client of the canonical-store process
│  │     ├─ BlobStore capability   co-located initially; optional `eliot-blob.exe` after isolation proof
│  │     ├─ `eliotd.exe`          primary Governor application daemon
│  │     ├─ `eliot-testd.exe`     isolated build/test/simulation plane, on demand
│  │     ├─ `eliot-wasm-host.exe` capability-limited Component Model generations, on demand
│  │     ├─ `eliot-native-worker-*.exe` OS-heavy or promoted native generations
│  │     ├─ `eliot-dreamer.exe`   on demand
│  │     ├─ `eliot-doctor.exe`    on demand
│  │     ├─ `eliot-mod-*.exe`     adapters, graphs, research, tools
│  │     └─ service-safe agent/model jobs
│  └─ Host-owned canonical-store Job Object
│     └─ `surreal.exe`             sole process owner of canonical DB files
└─ Eliot Watchdog service (`eliot-watchdog.exe`)
   └─ independent observation and protected minimal spool

Authorized interactive user session
├─ `eliot.exe`                    one canonical CLI; one-shot, no state ownership
├─ `eliot-user-broker.exe`        on demand
│  ├─ `eliot-ui.exe`              native WinUI client; no canonical authority
│  └─ subscription/desktop-bound runtimes; no canonical authority
└─ `eliot-notify.exe`             on demand via User Broker or signed Task Scheduler fallback; notification only
```

SCM owns only the stable Host and Watchdog services. Host owns OS process lifecycle for two isolated branches: Kernel and the canonical-store dependency. It starts `surreal.exe` as a supervised console/server process from an approved immutable manifest; ELIOT does not assume that the upstream binary implements the Windows service-control protocol. The SurrealDB process owns database files, while Host owns only start/stop/restart and Job Object containment. Kernel requests dependency lifecycle through Host and physically supervises `eliotd` and replaceable child generations. `eliotd` owns desired module state and semantic scheduling; Kernel performs generation routing, switch and fencing. Subscription- or desktop-bound runtimes are launched through a per-user `eliot-user-broker.exe`; the service identity never impersonates user-owned credentials or interactive desktop state.

Logical Governor consists of Kernel and `eliotd`, but canonical application authority remains singular. Kernel is the failure-surviving part of Governor, not a second Governor.

Primary update path:

```text
immutable artifact
→ staged generation
→ protocol/contract check
→ candidate process
→ warm-up or shadow traffic
→ health and canary
→ quiesce old admissions
→ persist one disposition for every effect-capable in-flight operation
→ commit the ORS cutover record as the durable linearization point
→ publish the candidate route, raise Authority Epoch and fence old general authority
→ drain permitted reads/exact old operations and reconcile unknown outcomes
→ retire or perform a new forward/rollback cutover.
```

Primary development path:

```text
small working vertical spine
→ real observations and performance
→ separate Modules
→ affected tests
→ canary in current work
→ Improvement Candidate
→ controlled promotion
→ full release gate only for a release or load-bearing change.
```

A full workspace rebuild and full test suite are not the normal response to a local change. They run only for a matching blast radius or release.

Runtime extensions and agent-generated components use three execution contours:

```text
WASM Component
  pure, portable, capability-limited and rapidly replaceable logic;

isolated native process generation
  Cargo/Git/LSP/browser/native libraries, credentials or OS-heavy work;

static native bundle
  trusted Kernel/control-plane or a measured hot path promoted through a new binary generation.
```

A Cargo crate is not automatically a process, and a process is not automatically a Windows service. In-process Rust dynamic libraries are not a normal promotion route: Rust ABI, shared heap, callbacks, threads and unload semantics do not provide the failure isolation required by ELIOT.

Agent Execution Fabric is not a new control plane. It is an execution projection of the existing Governor, Host Broker, and Agent Coordinator:

```text
Human / Main Agent
→ goal, constraints, assurance and budget policy
→ ELIOT chooses the simplest admissible recipe, routes, staffing and isolation
→ external runtimes execute bounded attempts
→ ELIOT reconciles evidence, audits disagreement and owns durable task state.
```

Task intent, lifecycle, evidence, authority, recovery, and decision gates are unified. The internals of Codex, OpenCode, ACP, Claude, Antigravity, and future agents remain distinct and are preserved in route and provenance records.

Instrument Plane is the deterministic foundation for development and grounding, not another agent system:

```text
ELIOT task / memory / authority
→ typed InstrumentProfile
→ one InstrumentRunner control path
→ isolated `eliot-testd` execution plane
→ one Windows ProcessExecutor semantics
→ compiler, test, simulation, component, semantic, runtime and performance instruments
→ EvidenceEnvelope + VerificationReceipt with authority, freshness, coverage and provenance
→ CodeCortex / verifier / Diagnostic Brief / Active View.
```

An agent receives neither dozens of raw tools nor permission to invent shell verifier commands. It requests the intent `verify`, `inspect`, `assist`, or `evidence`; ELIOT selects a profile, runs exact instruments, preserves raw evidence, and returns a compact verifiable result. Instrument Plane owns neither tasks, memory, Architecture, nor completion.

---

