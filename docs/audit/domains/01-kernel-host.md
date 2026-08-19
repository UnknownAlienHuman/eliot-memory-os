# Domain: Kernel / Host / runtime topology / installation / IPC

**STATUS: PARTIAL — Q1 done, Q2/Q3/Q4 pending.**

## Scope covered (so far)
- `bins/eliot-host/src/lib.rs`, `bins/eliot-host/src/main.rs`
- `bins/eliot-kernel/src/lib.rs`
- `crates/kernel/eliot-installation/src/lib.rs`
- `crates/kernel/eliot-kernel-service/src/lifecycle.rs`
- `crates/kernel/eliot-ipc/src/lib.rs`
- `crates/kernel/eliot-platform-windows/src/lib.rs`
- `crates/foundation/eliot-contracts/src/lib.rs`
- Arch: A2.2, A2.3, A13.2, A13.3. Impl: I1.2, I1.4, I1.8.

## Carried findings (from prior run)
1. Host launches exactly TWO Job-Object branches: Kernel + canonical store engine
   (`surreal.exe`). `bins/eliot-host/src/lib.rs:271` `HostJobBranches { kernel, store }`.
2. `eliot-store-surreal.exe` (the bridge) is deliberately NOT a Host-owned process:
   `crates/kernel/eliot-installation/src/lib.rs:751-753` doc comment "The bridge is
   route evidence only and is not a Host-owned process".
   `runtime_paths()` at `crates/kernel/eliot-installation/src/lib.rs:1255` returns
   (kernel, canonical_store, config) — the bridge path is not handed to Host.
3. Launch binding IS real: `HostJobBranches::launch` at `bins/eliot-host/src/lib.rs:764`
   spawns suspended (`SuspendedJobChild::spawn_named`, line 843), validates image path +
   SHA-256 artifact digest + config digest under a retained file lease, then resumes.
4. `HostComposition::open` at `bins/eliot-host/src/lib.rs:1724` is the only production
   caller of `start_approved_contour` (line 1784) and it takes the two executable paths
   from env vars `ELIOT_KERNEL_BINARY` / `ELIOT_STORE_BINARY` (`configured_image`, line 2639).
5. The SCM `service_main` (`bins/eliot-host/src/main.rs:196`) NEVER starts a contour;
   it only loops on `has_durable_branch_fence()` / `reconcile_approved_contour()`.
   Startup happens as a side effect of `open_host()`.

## Q1 — Authority epoch / lease / fence: ENFORCED, not just typed

Enforcement is real and concentrated in four independent gates.

### 1a. Kernel control-wire gate (the strongest one)
`KernelRuntime::apply_control_request` at `bins/eliot-kernel/src/lib.rs:2937`. Every Host
control request is rejected with `TransportError::SessionFenced` when any of these fail
(`:2950-2975`):
- `request.sequence != expected_sequence` (replay / reorder)
- `request.peer_process_id != observed_peer.process_id()` — `observed_peer` comes from the
  transport's handle-proven `PeerIdentity`, not from the payload
- `request.handshake.pipe_identity != self.ipc.name()`
- handle-proven peer PID / `start_time_100ns` / `image_path` != `handshake.host_process.*`
  (this is the new `HostProcessBinding` — PID reuse and image substitution are both observable)
- `request.generation != policy.module_generation.generation`
- **`request.handshake.kernel_epoch != policy.module_generation.state_fence.authority_epoch`** (`:2966`)
- `handshake.artifact_hash != policy.module_generation.artifact_id`
- `approved_config_hash != handshake.config_hash`
- `Reconcile(handshake)` payload must equal the envelope handshake (`:2976-2980`)

On mismatch: `Err(TransportError::SessionFenced)`. No partial application, no receipt.

### 1b. ProbeReady readiness gate — Kernel re-proves, does not trust Host
`self_authored_ready_receipt` at `bins/eliot-kernel/src/lib.rs:2795`:
- re-checks `host_process` against the live peer binding → `HandshakeMismatch{field:"host_process"}` (`:2808`)
- deserializes `handshake.job_binding` into a `RecoverableJobBinding`, checks the name matches
  `handshake.job_object_id` (`:2819`), then **reopens the named Job** (`RecoverableJobObject::open`, `:2824`)
  and verifies its own live process is the Job root AND a live member → `ReadinessNotProven` (`:2838`)
- `readiness_configuration_valid()` gate (`:2843`) → `ReadinessNotProven`
- `approved_config_hash != handshake.config_hash` → `HandshakeMismatch{field:"config_hash"}` (`:2848`)
- service must be in `Activating` and hold exactly this handshake (`:2857`) → `ReadinessNotProven`
- canonical store gateway health must be `Ready` (`:2873`), and its
  `snapshot.state_fence.authority_epoch != handshake.kernel_epoch ||
  snapshot.state_fence.resource_generation != request.generation` →
  `HandshakeMismatch{field:"store_state_fence"}` (`:2883-2889`)

The Host side consumes this correctly after the repair: `bins/eliot-host/src/lib.rs:676-684`
issues the ordered `[Reconcile, Shadow, PrepareHandoff, Activate, ProbeReady]` sequence and
at `:735-744` rejects the response unless `message_id`, `request_digest` match, `error` is
`None`, and for `ProbeReady` `response.state == KernelServiceState::Ready`. Host authors no
receipt itself (`:648-650`).

### 1c. Epoch lineage gate in the service state machine
`KernelService::synchronize_authority_epoch` at `crates/kernel/eliot-kernel-service/src/lifecycle.rs:413`:
- refuses while `generation_fenced` → `GenerationFenced` (`:418`)
- front-door and authority mirrors must already agree → `HandshakeMismatch{field:"authority_epoch"}` (`:422`)
- **`target < current` → `HandshakeMismatch{field:"authority_epoch_regression"}`** (`:427`) — a durable
  regression is a startup fence, not an implicit genesis reset
- overflow → `authority_epoch_corrupt` (`:433`); gap > `MAX_EPOCH_SYNC_GAP` → `authority_epoch_oversized` (`:439`)
- both mirrors must land on exactly `target` afterwards (`:443-447`)

`fence_generation` at `lifecycle.rs:270` sets `generation_fenced = true`, records the reason as a
retained `ServiceFailure::Contract`, and transitions to `Failed`. `apply()` at `:396` refuses every
lifecycle command once fenced. The comment at `:266-268` states it cannot be cleared in-process.

### 1d. Generation gateway (durable-before-visible)
`OrsGenerationCoordinator` at `bins/eliot-kernel/src/lib.rs:1721`:
- `persist_and_publish` (`:1785`) computes the candidate router, **stages the cutover as `Armed`
  and commits it to ORS (`:1805-1811`) before any in-memory publication**, rejects a non-`Committed`
  return (`:1812`), then synchronizes the epoch and swaps the router (`:1819-1823`).
- `recover` (`:1730`) reconciles staged cutovers forward-only, takes `max(new_epoch)`, and rejects
  the projection if any record is not `Committed` or claims an epoch above the max →
  `"ORS route projection has invalid committed epochs"` (`:1761`).
- On any publish failure the composition poisons the gateway: `generation_poison` +
  `service.fence_generation(...)`, after which `dispatch_frame` (`:2427`) returns
  `TransportError::SessionFenced` for every frame (`:2431-2438`).

### 1e. Session fence on the data path
`eliot-ipc`: `Session::establish_with_server` (`crates/kernel/eliot-ipc/src/lib.rs:597`) rejects a
client hello unless module id, full `ModuleGeneration`, `artifact_hash`, **`client.authority_epoch ==
server.module_generation.state_fence.authority_epoch`**, and `launch_nonce` all match →
`TransportError::SessionFenced` (`:611`). Per-frame, `Session::accepts` (`:670`) requires
`state == Open && authority_epoch == .. && session_epoch == ..`; `accepts_bound` (`:677`) additionally
requires the full `ModuleGeneration` and `launch_nonce`. `dispatch_frame`
(`bins/eliot-kernel/src/lib.rs:2440-2452`) calls `accepts` and then
`session.module_generation.state_fence.is_compatible_with(&identity.request.state_fence)`,
fencing the session on mismatch.

### 1f. `HostOwnerLease` — installation-wide admission, fail-closed
`crates/kernel/eliot-platform-windows/src/lib.rs:1240`. `acquire` (`:1259`) creates a named mutex whose
name is `SHA-256(installation_id)` (`host_owner_mutex_name`, `:1225`) under an explicitly built
protected security descriptor. **`ERROR_ALREADY_EXISTS` is never joined or waited on** — the handle is
closed and `HostOwnerLeaseError::ExistingObject` is returned (`:1305-1318`); any other Win32 result
yields `OwnershipUncertain`. `release` (`:1349`) deliberately retains handle+ownership on a failed
`ReleaseMutex` rather than abandoning the gate. Called from `bins/eliot-host/src/lib.rs:1729` and
`:1810`, and from `crates/kernel/eliot-host-service/src/service.rs:209`; failures map to
`HostError::OwnerLeaseHeld` / `OwnerLeaseRecovery` at `bins/eliot-host/src/lib.rs:2609-2628`.

**Verdict Q1: IMPLEMENTED.** These are executed comparisons in production call paths with typed
rejections, not type-level modelling.

## Q2 — Host state journal durability: crash-recoverable BUT NOT WIRED

`crates/kernel/eliot-host-state` contains **two independent durable stores**, and the sophisticated
one is not the one Host uses.

### 2a. `HostStateJournal` (journal.rs + redb_journal.rs) — genuinely crash-recoverable
- Framing: `JOURNAL_MAGIC = b"ELIOT-HOST-STATE\n"` + `JOURNAL_VERSION = 1` (`journal.rs:15-16`).
  `frame()` (`journal.rs:103`) writes magic + JSON header (version, sequence, length, SHA-256 of
  payload) + payload.
- `scan_frames` (`journal.rs:151`) fails closed on every torn/altered condition:
  `JournalError::Torn{offset}` on bad magic (`:161`), missing header newline (`:169`), truncated
  payload / missing terminator (`:186`); `UnknownVersion` (`:171`); `Checksum{sequence}` on payload
  digest mismatch (`:190`); `Sequence` on a gap (`:194`). A torn tail is NOT silently truncated.
- Two-phase durable transaction protocol: `JournalBackend` (`backend.rs:75`) =
  `prepare → append_prepared → flush → sync → commit`, with `reconcile()` returning
  `Absent | Prepared | Committed(receipt)`. `HostStateJournal::append` (`journal.rs:770`) calls
  `reconcile` FIRST (`:806`); a `Committed` receipt replays idempotently (`:811-820`), a surviving
  `Prepared` returns `JournalError::OutcomeUnknown{transaction_id}` (`:823`) rather than guessing.
- `RedbJournalBackend` (`redb_journal.rs`) persists every phase in its own redb write transaction
  (`commit_write`, `:535`). `commit` (`:730`) refuses unless flushed+synced (`:747`) and re-verifies
  `sha256_digest(bytes) == descriptor.payload_digest` → `BackendError::Conflict` (`:753`).
  `persist_commit` (`:541`) writes epoch bytes + receipt + payload and removes the PREPARED row in
  **one** redb transaction. `redb = "4.1.0"` (root `Cargo.toml:260`), and no `set_durability` call
  exists anywhere in the workspace — the code relies on redb's default commit durability.
- Path protection: `open` (`redb_journal.rs:160`) requires `require_protected_program_data_path`,
  takes a `ProtectedPathLease`, and re-verifies path identity after `Database::create` (`:174`).
  `inspect_existing` (`:109`) is a read-only, non-creating variant.

### 2b. Corruption recovery / quarantine — real, in the journal reducer
- `load_epochs` (`journal.rs:447`): with `tolerate_corruption == false`, a failed replay returns the
  error (`:487`) — load is blocked. With `tolerate_corruption == true` (`:480`), the failed epoch is
  retained as `EpochEvidence { replay_verified: false, forensic_digest: checksum(bytes), .. }` —
  i.e. quarantined with forensic evidence, not discarded.
- The tolerance flag comes from the CALLER's own identity: `state_for_host` (`journal.rs:575-577`)
  sets `tolerate_corruption = (host.recovery.reason == RecoveryLineageReason::Corruption)`.
- The new-lineage requirement is enforced at `journal.rs:604-613`: a host with `parent == None` is
  accepted only if `recovery.is_some()`, `sequence == 1`, same installation, and **no retained
  epoch shares its lineage**; otherwise `JournalError::RecoveryRequiresNewEpoch`. The recovered
  state is marked `prior_kernel_unknown = true` (`:616`).
- Quarantined receipts stay non-authoritative: `validate_committed_receipts` (`journal.rs:536-546`)
  skips receipts of unverified epochs only under a Corruption recovery for a different host, and
  otherwise rejects with `"committed receipt belongs to an unverified host epoch"`.
- Proven by `redb_corrupt_retained_epoch_is_quarantined_for_recovery`
  (`redb_journal.rs:1630`): flips one payload bit, opens under a NEW lineage with
  `RecoveryLineageReason::Corruption`, asserts the retained epoch is present with
  `replay_verified == false` and the expected `forensic_digest`, asserts the old transaction now
  reconciles to `StaleFence`, appends into the new lineage, reopens and re-verifies.
  The fail-closed counterpart is `redb_corrupt_current_epoch_requires_explicit_recovery`
  (`redb_journal.rs:1591`).

**So: YES — a corrupt retained epoch opens a new lineage rather than blocking load. But only in
this reducer, and only when the caller supplies `RecoveryLineageEvidence`.**

### 2c. The gap: no production caller
`grep` across `bins/`, `crates/`, `workspace/` finds **zero** references to `HostStateJournal`,
`RedbJournalBackend`, `JournalBackend`, or `MemoryBackend` outside `crates/kernel/eliot-host-state`
itself. The only workspace dependant of the crate is `bins/eliot-host` (`bins/eliot-host/Cargo.toml:18`),
and its import list (`bins/eliot-host/src/lib.rs:18-21`) is exactly
`{HostAdmissionState, HostInstallationEpoch, HostRecoverySnapshot, RedbHostReleaseToken, RedbHostStateStore}` —
none of the journal API. The entire two-phase journal is exercised only by the crate's own tests.

What Host actually uses is `RedbHostStateStore` (`redb_store.rs`), a much simpler last-writer-wins
projection:
- `open_epoch` (`redb_store.rs:451`) called from `bins/eliot-host/src/lib.rs:1743`;
  `open_existing` (`redb_store.rs:231`) called from `bins/eliot-host/src/lib.rs:1819`.
- No frame magic, no per-record checksum, no sequence chain, no PREPARED/COMMITTED two-phase set.
  State and epoch are written by two **separate** redb transactions (`write_state` `:505`,
  `write_epoch` `:523`), so `open_epoch` (`:481-493`) is not atomic across the pair.
- `mutate_with_epoch` (`redb_store.rs:573`) does enforce a CAS on the epoch binding inside one write
  transaction (`:600` → `HostStateError::InvalidRecord`), and `commit_activation_atomic`
  (`redb_store.rs:767`) commits activation + process recovery binding in one transaction.
- **`next_epoch` (`redb_store.rs:718`) hardcodes `recovery: None` (`:759`).** The production Host
  epoch advance therefore can never produce a `RecoveryLineageEvidence`, so the corruption/new-lineage
  path in 2b is unreachable from Host.
- A corrupt/undeserializable epoch or state row returns `HostStateError::Unavailable`
  (`read_epoch_from_read` `:652-654`, `read_state_from_read` `:695`) — load is **blocked**, with no
  quarantine and no lineage fork.

**Verdict Q2: journal = IMPLEMENTED but SHELL-by-wiring (no production caller). Production Host
state = a separate, weaker store that fails closed on corruption with no recovery lineage.**

## Q3 — `eliotd` wiring: NOT a shell, but NOT what the question assumed

`bins/eliotd` does **not** contain an in-process Kernel, a Store adapter, or a physical
`ProcessExecutor`. That is deliberate, not missing: `bins/eliotd/src/main.rs:3-5` states
"composes Governor only from that transport and never creates a local Store, `ProcessExecutor`,
or authority source." `eliotd` is the **Governor daemon**, a remote client of Kernel.

Verified from `bins/eliotd/Cargo.toml:16-29`: the dependency set is
`eliot-contracts, eliot-governor, eliot-ipc, eliot-maintenance, eliot-platform,
eliot-platform-windows, eliot-protocol, eliot-receipts, eliot-runtime-contracts,
eliot-store-api, serde, serde_json, tokio, thiserror`. There is **no** `eliot-process`,
`eliot-process-executor`, `eliot-kernel-core`, `eliot-kernel-service`, `eliot-ors`, or
`eliot-store-surreal` dependency — an in-process Kernel or physical executor is not even linkable.

`WindowsProcessExecutor` is constructed in exactly two places, neither of them `eliotd`:
`bins/eliot-kernel/src/lib.rs:1031` (`ProcessExecutionGateway::new`) and
`bins/eliot-user-broker/src/lib.rs:424`.

### What `main` actually constructs (`bins/eliotd/src/main.rs:59-72`)
1. `DaemonConfig::load_protected()` (`bins/eliotd/src/lib.rs:112`) — reads the fixed
   `ProgramData` path through `ProtectedPathLease::open_existing_absolute` + `read_bounded`,
   parses `GovernorLaunchConfig`, and `from_launch` (`:126`) rejects any path that is not the fixed
   protected identity (`:135-139`). No env var, no CLI root override. It derives
   `KernelLaunchBinding { kernel_pipe_name, expected_kernel_sid, expected_kernel_session_id,
   module_generation, authority_epoch, state_fence, launch_nonce, artifact_hash }` (`:141-150`).
2. `DaemonKernelClient::connect(&config)` (`:233`) — real, not a stub. On Windows it builds a
   current-thread tokio runtime and performs `snapshot_request()`, replacing the locally-derived
   expectation with the **server-owned** snapshot (`:251-256`). On non-Windows it returns
   `KernelClientError::Unsupported` (`:258-263`) — no fake success path.
   The transport is `connect_transport` (`:475`): `NamedPipeTransport::connect_authenticated`
   with a `NamedPipePeerExpectation(expected_kernel_sid, expected_kernel_session_id)`, then an
   explicit re-check of `PeerIdentity::Authenticated { process_id != 0, user_identity == sid,
   session_identity == session }` → `KernelClientError::Contract` (`:495-510`), then
   ClientHello/ServerHello with `validate_server_hello` (`:527`).
3. `DaemonComposition::start(config, kernel as Arc<dyn KernelGenerationPort>)` (`:971`) —
   requires the retained config lease (`:977`), `verify_stable_identity()`, re-reads the bytes and
   rejects if they changed since load (`:987-991`, TOCTOU guard), prepares the protected state
   root, opens `daemon.lifecycle` under a `ProtectedPathLease` and rejects an identity change
   (`:993-1001`), then builds `GovernorComposition::new(kernel, &config.launch().kernel,
   QueueLimits::default())` (`:1003`). `GovernorComposition::new`
   (`crates/governor/eliot-governor/src/composition.rs:1195`) takes the port's snapshot, checks it
   against `KernelGenerationExpectation::admits` (`:1201`), and drives `recover_from_kernel` (`:1205`).
4. `kernel.report_ready()` (`bins/eliotd/src/lib.rs:269`) — an authenticated `daemon_ready`
   transaction carrying generation + authority epoch.
5. A current-thread tokio runtime running `run_loop` (`main.rs:113`): `ctrl_c` vs a 5-second
   `KernelTransitionPort::health` heartbeat; a heartbeat failure exits the loop and drives
   `report_degraded` then `report_fatal` (`main.rs:81-92`).

**Verdict Q3: IMPLEMENTED as a Kernel-client Governor daemon.** It is not a shell — every step is
real protected-path, peer-authenticated, snapshot-validated code. But if the architecture expects
`eliotd` to host Kernel in-process, the code contradicts that: see the divergence section.

## Q4 — IPC: bounded YES; peer auth enforced on BOTH paths YES

First, a scope correction: **`crates/eliot-windows-ipc` is not the named-pipe transport.** Its own
header (`crates/eliot-windows-ipc/src/lib.rs:1-4`) describes it as the single audited Win32 FFI
boundary; it holds pinned files, oplock guards, Job Objects, process-tree guards, and
`named_pipe_client_process` (`:377`). Its dependants are `eliot-app`, `eliot-engine`, `eliot-store`,
`eliot-platform-windows`. The Kernel/Host/daemon transport lives entirely in
`crates/kernel/eliot-ipc/src/lib.rs`.

### 4a. Bounds — IMPLEMENTED
- `MAX_FRAME_BYTES = 4 * 1024 * 1024` (`crates/foundation/eliot-protocol/src/lib.rs:36`).
  `TransportLimits::default()` (`crates/kernel/eliot-ipc/src/lib.rs:184`) =
  `{max_frame_bytes: MAX_FRAME_BYTES, queue_capacity: 128, queue_bytes: 8 MiB,
  control_reserve: 4, operation_timeout: 30s}`.
  `TransportLimits::validate` (`:197`) rejects zero/oversized frame bytes, zero capacity,
  `queue_bytes < max_frame_bytes`, `control_reserve >= queue_capacity`, and a zero timeout →
  `TransportError::InvalidLimits`.
- Read path `receive_wire` (`crates/kernel/eliot-ipc/src/lib.rs:1583`): reads the 4-byte LE length
  prefix under `tokio::time::timeout(limits.operation_timeout, ..)` → `TransportError::Timeout`;
  **rejects `length == 0 || length > max_frame_bytes` BEFORE allocating** →
  `ProtocolError::OversizeFrame` (`:1600-1605`); reads the body under the same timeout.
- Streaming path `FrameDecoder::push` (`:826`) inspects the 4-byte prefix before appending
  attacker-controlled bytes (explicit comment at `:836-838`), clears the buffer and errors on
  oversize (`:869-875`), and returns `Backpressure` if a fragment would overrun the declared frame (`:876`).
- `AdmissionQueue::admit` (`:726`) bounds by item count and byte total with a dedicated control
  reserve → `TransportError::Backpressure`; `QueueReservation` is a one-shot token so a caller
  cannot release someone else's capacity.
- Write path `send_wire` (`:1568`) is timeout-bounded and maps both I/O failure and timeout to
  `DeliveryOutcome::UnknownOutcome` — never a fabricated success.
- Pipe names: `validate_pipe_name` (`:1168`) requires the literal prefix `\\.\pipe\eliot\`, length
  <= 240, no control chars, and per-component rejection of `.`/`..`/`/`/`:`/NUL and any non
  `[A-Za-z0-9-_.]` character → `TransportError::InvalidPipeName`.

### 4b. Peer authentication — enforced on BOTH server and client
- **Server authenticating the client**: `NamedPipeServer::wait_for_authenticated_client`
  (`crates/kernel/eliot-ipc/src/lib.rs:1327`) → reads the fixed 8-byte
  `AUTHENTICATION_PREFACE = b"ELIOT-P2"` (mismatch → `TransportError::UnauthenticatedPeer`, `:1565`),
  then `eliot_platform_windows::authenticate_named_pipe_client`
  (`crates/kernel/eliot-platform-windows/src/lib.rs:5813`): validates the pipe DACL (`:5826`),
  `GetNamedPipeClientProcessId` + `OpenProcess`, `admit_named_pipe_peer_process`, reads the process
  token, **impersonates the client and compares the thread token to the process token**, reverts via
  an RAII `ImpersonationGuard`, and rejects on
  `process_token != thread_token || sid != expected_sid || session != expected_session` →
  `WindowsAdapterError::IdentityMismatch` (`:5842-5850`).
- **Client authenticating the server**: `NamedPipeTransport::connect_authenticated` (`:1379`) calls
  `Inner::authenticate` (`:1477`) → `authenticate_named_pipe_server`
  (`crates/kernel/eliot-platform-windows/src/lib.rs:5759`): validates the pipe DACL (`:5772`),
  `GetNamedPipeServerProcessId` + `OpenProcess`, and rejects on SID/session mismatch (`:5788-5790`).
  Only after this does it send the preface.
- **Neither path can exchange frames without proof.** `require_authenticated_peer` (`:270`) returns
  `TransportError::PlanGap { dependency: "eliot-platform-windows", .. }` for a
  `PeerIdentity::Unavailable`, and it gates `NamedPipeServer::send_frame`/`receive_frame`
  (`:1352`, `:1362`) and `NamedPipeTransport::send_frame`/`send_frame_with_cancel`/`receive_frame`
  (`:1392`, `:1406`, `:1424`). `map_platform_error` (`:250`) maps both `IdentityMismatch` and
  `AclMismatch` to `TransportError::UnauthenticatedPeer`.
- Pipe ACL at creation: `PipeSecurityDescriptor::for_principal` (`:1211`) builds the SDDL
  `D:P(A;;GA;;;SY)(A;;GA;;;{expected_sid})` — protected DACL, SYSTEM plus the one expected principal;
  `ServerOptions` sets `reject_remote_clients(true)` and `first_pipe_instance` for the first
  instance (`:1301-1305`). `validate_pipe_dacl`
  (`crates/kernel/eliot-platform-windows/src/lib.rs:6881`) re-reads the live DACL from the handle,
  caps it at 16 ACEs, and requires the expected SID ACE — so an attacker-created squatted pipe fails.
- Production callers use the authenticating variants: Kernel front door
  `bins/eliot-kernel/src/main.rs:167`; Store `bins/eliot-store-surreal/src/main.rs:79-85`;
  Host `bins/eliot-host/src/lib.rs:659-663`; daemon `bins/eliotd/src/lib.rs:481-510`.
- Note (not a hole): `admit_named_pipe_peer_process`
  (`crates/kernel/eliot-platform-windows/src/lib.rs:5721`) only enforces PID/start-time/image when
  `expectation.approved_process_binding()` is `Some`, and Kernel's front door uses
  `current_process_named_pipe_expectation()` (`:5867`) which carries SID + session only. The
  image/PID binding is instead enforced one layer up in `apply_control_request`
  (`bins/eliot-kernel/src/lib.rs:2954-2957`) and by Host in reverse
  (`bins/eliot-host/src/lib.rs:664-676`). Defense in depth is intact, but the transport layer alone
  does not bind the peer image.

### 4c. One real bound gap
`bins/eliot-kernel/src/main.rs:167-169` calls
`front_door.wait_for_authenticated_client(Duration::from_secs(86_400), &principal)`. That single
timeout is used for **both** the accept (`wait_for_client`, `crates/kernel/eliot-ipc/src/lib.rs:1317`)
**and** the authentication-preface read (`:1335`). A peer that connects and then never writes the
8-byte preface holds the accept future for 24 hours; `bind_authenticated_front_door_next()` is only
called after that future resolves (`bins/eliot-kernel/src/main.rs:180-186`), so the front-door accept
loop stalls. Reachability is limited to principals already admitted by the pipe DACL (SYSTEM or the
expected SID), which caps severity. Established sessions are fine — `receive_frame` applies the 30 s
`operation_timeout` per frame.

**Verdict Q4: bounded = IMPLEMENTED; bidirectional peer auth = IMPLEMENTED; one loose accept/preface
timeout (P2).**
