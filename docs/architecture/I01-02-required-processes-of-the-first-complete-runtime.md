## I1.2. Required processes of the first complete runtime

### 1. `eliot-host.exe`

Minimal Windows service and external Host Supervisor.

**Owns:**

```text
installation root;
approved build registry;
HostStateJournal and HostInstallationEpoch;
start/stop/restart Kernel;
start/stop isolated managed dependency branches, including the canonical store process;
request start/stop of the independent Watchdog service through SCM;
last-known-good selection for managed Kernel/dependency artifacts;
minimal recovery and rollback command channel.

Host does not select or replace its own service binary while running; Host-service replacement belongs to the installer/SCM procedure of I14.
```

**Does not own:** project semantics, canonical memory, Sessions, tasks, model routing, repairs, or Architecture decisions.

The code must remain small, dependency-light, and rarely changed. It loads no SurrealDB SDK, MCP, HTTP UI, or model clients.

### 2. `eliot-kernel.exe`

Resilient part of Governor.

**Owns:**

```text
local front-door IPC;
principal/session binding;
Authority Epochs and fencing;
Operational Recovery State;
Control Reserve;
Module/daemon generation routing;
canonical transition gateway;
minimal health and Recovery View;
startup/drain orchestration;
connection to store bridge.
```

**Does not perform:** semantic curation, Dreamer jobs, code graphs, UI, full task planning, or broad retrieval.

### 3. `eliotd.exe`

Primary Governor application daemon.

**Owns:**

```text
WorkScopes;
tasks and current plan revisions;
write admission;
read models;
Context Compiler;
Agent Coordinator;
Durable Jobs;
problem/conflict/attention application state;
module orchestration;
reports and normal API behavior.
```

Kernel can hot-replace it. Its restart changes neither canonical owner nor the validity of stale leases.

### 4. `eliot-watchdog.exe`

Independent supervision daemon installed as a separate SCM-managed service or process. Host requests start and stop through SCM, but owns neither its Job Object nor a kill-on-close handle. A Host, Kernel, or `eliotd` crash therefore does not automatically terminate Watchdog. Watchdog preserves a minimal independent signal spool and audit anchor.

### 5. `eliot-store-surreal.exe`

Storage bridge. The only ELIOT process with SurrealDB credentials and SDK.

```text
Kernel / eliotd
→ EBP Store service
→ eliot-store-surreal.exe
→ SurrealDB RPC
→ SurrealDB server.
```

Bridge accepts only closed semantic store operations and named queries. Raw SurrealQL over the runtime protocol is prohibited.

### 6. BlobStore capability; optional `eliot-blob.exe` generation

Vendor-neutral immutable payload service. It owns the Blob Store root, temporary staging, hashing, compression, local encryption envelope, reachability/GC metadata and `BlobReadyReceipt`. It has no SurrealDB credentials, no semantic query surface and no right to create canonical references by itself.

```text
agent/module/tool stream
→ governed BlobStageRequest
→ eliot-blob writes immutable CAS object
→ BlobReadyReceipt
→ canonical transition may reference BlobRef
→ failed canonical commit leaves a harmless orphan for bounded GC.
```

The target process boundary isolates untrusted large payloads, compression/native libraries, disk pressure and retention work from Kernel and the canonical DB bridge. During D1 the same `BlobStore` contract may run as an internal capability of `eliot-store-surreal` or `eliotd` as a declared Delivery Default, provided that it has one data-root owner, separate bounded resources, no SurrealDB credential leakage and an independently extractable state format. Separate `eliot-blob.exe` becomes admissible when untrusted/large-payload pressure, native codec risk, independent GC/restart, credential isolation or measured contention justifies a process boundary. Delivery depth alone does not mandate the executable. This staged co-location is not an Architecture deviation; changing the public contract or creating two blob-root owners is.

### 7. `surreal.exe`

Separate Host-managed dependency process in its own Job Object, owning the database files. It may start on demand and survives restart of `eliot-kernel` or `eliotd` because it is not in the Kernel Job Object. Host starts it from an immutable process manifest and observes process exit; Kernel and store bridge check database readiness and semantic compatibility. ELIOT does not require upstream `surreal.exe` to implement the Windows SCM service protocol and does not make a third-party service wrapper mandatory.

