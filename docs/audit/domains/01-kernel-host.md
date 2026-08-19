# Domain: Kernel / Host / runtime topology / installation / IPC

## Scope covered

Code inspected (all paths relative to `C:\Development\Rust\projects\eliot-memory-os`):
- `bins/eliot-host/src/lib.rs` (3011 lines), `bins/eliot-host/src/main.rs` (331)
- `bins/eliot-kernel/src/lib.rs`, `bins/eliot-kernel/src/main.rs`
- `bins/eliotd/src/lib.rs` (1128), `bins/eliotd/src/main.rs` (148), `bins/eliotd/Cargo.toml`
- `bins/eliot-store-surreal/src/main.rs` (transport call site only)
- `crates/kernel/eliot-installation/src/lib.rs`
- `crates/kernel/eliot-kernel-service/src/lifecycle.rs`, `src/protocol.rs`
- `crates/kernel/eliot-host-state/` — `lib.rs`, `backend.rs`, `journal.rs`, `redb_journal.rs`, `redb_store.rs`
- `crates/kernel/eliot-ipc/src/lib.rs` (2178)
- `crates/kernel/eliot-platform-windows/src/lib.rs` (pipe auth, DACL, `HostOwnerLease`)
- `crates/eliot-windows-ipc/src/lib.rs` (header + surface)
- `crates/foundation/eliot-contracts/src/lib.rs`, `crates/foundation/eliot-protocol/src/lib.rs`
- `crates/governor/eliot-governor/src/composition.rs` (`GovernorComposition::new` only)

Docs read: `ELIOT_ARCHITECTURE.md` A2.2 (461), A2.3 (520), A10.2 (1603), A10.3 (1619),
A11.2 (1811), A11.3 (1834), A12.2 (1912), A13.2 (2060), A13.3 (2079).

---

## Q1 — Authority epoch / lease / fence: ENFORCED, not just typed

Enforcement is real and concentrated in six independent gates.

### 1a. Kernel control-wire gate (the strongest one)
`KernelRuntime::apply_control_request` at `bins/eliot-kernel/src/lib.rs:2937`. Every Host
control request is rejected with `TransportError::SessionFenced` when any of these fail
(`:2950-2975`):
- `request.sequence != expected_sequence` (replay / reorder)
- `request.peer_process_id != observed_peer.process_id()` — `observed_peer` comes from the
  transport's handle-proven `PeerIdentity`, not from the payload
- `request.handshake.pipe_identity != self.ipc.name()`
- handle-proven peer PID / `start_time_100ns` / `image_path` != `handshake.host_process.*`
  (the `HostProcessBinding` — PID reuse and image substitution are both observable)
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
issues the ordered `[Reconcile, Shadow, PrepareHandoff, Activate, ProbeReady]` sequence, and at
`:735-744` rejects the response unless `message_id` and `request_digest` match, `error` is `None`,
and for `ProbeReady` `response.state == KernelServiceState::Ready`. Host authors no receipt itself
(comment + code, `:648-655`). `HostKernelHandshake` is populated with the new `host_process`
(`:607-613`, read from the live current-process handle, not `std::process::id()` alone) and
`job_binding` (`:617-625`, an inert projection Kernel must independently reopen).

### 1c. Epoch lineage gate in the service state machine
`KernelService::synchronize_authority_epoch` at `crates/kernel/eliot-kernel-service/src/lifecycle.rs:413`:
- refuses while `generation_fenced` → `GenerationFenced` (`:418`)
- front-door and authority mirrors must already agree → `HandshakeMismatch{field:"authority_epoch"}` (`:422`)
- **`target < current` → `HandshakeMismatch{field:"authority_epoch_regression"}`** (`:427`) — a durable
  regression is a startup fence, not an implicit genesis reset
- overflow → `authority_epoch_corrupt` (`:433`); gap > `MAX_EPOCH_SYNC_GAP` → `authority_epoch_oversized` (`:439`)
- both mirrors must land on exactly `target` afterwards (`:443-447`)

`fence_generation` (`lifecycle.rs:270`) sets `generation_fenced = true`, records the reason as a
retained `ServiceFailure::Contract`, and transitions to `Failed`. `apply()` (`:294`) refuses every
lifecycle command once fenced.

### 1d. Generation gateway (durable-before-visible)
`OrsGenerationCoordinator` at `bins/eliot-kernel/src/lib.rs:1721`:
- `persist_and_publish` (`:1785`) computes the candidate router, **stages the cutover as `Armed`
  and commits it to ORS (`:1805-1811`) before any in-memory publication**, rejects a non-`Committed`
  return (`:1812`), then synchronizes the epoch and swaps the router (`:1819-1823`).
- `recover` (`:1730`) reconciles staged cutovers forward-only, takes `max(new_epoch)`, and rejects
  the projection if any record is not `Committed` or claims an epoch above the max →
  `"ORS route projection has invalid committed epochs"` (`:1761`).
- On any publish failure the composition poisons the gateway (`generation_poison` +
  `service.fence_generation`), after which `dispatch_frame` (`:2427`) returns
  `TransportError::SessionFenced` for every frame (`:2431-2438`) and
  `bind_authenticated_front_door` / `..._next` (`:2662`, `:2683`) refuse to bind a pipe at all.

### 1e. Session fence on the data path
`Session::establish_with_server` (`crates/kernel/eliot-ipc/src/lib.rs:596`) rejects a client hello
unless module id, full `ModuleGeneration`, `artifact_hash`, **`client.authority_epoch ==
server.module_generation.state_fence.authority_epoch`**, and `launch_nonce` all match →
`TransportError::SessionFenced` (`:605-613`). Per-frame, `Session::accepts` (`:670`) requires
`state == Open && authority_epoch == .. && session_epoch == ..`; `accepts_bound` (`:677`)
additionally requires the full `ModuleGeneration` and `launch_nonce`. `dispatch_frame`
(`bins/eliot-kernel/src/lib.rs:2440-2452`) calls `accepts` and then
`session.module_generation.state_fence.is_compatible_with(&identity.request.state_fence)`
(`StateFence::is_compatible_with` is defined at `crates/foundation/eliot-contracts/src/lib.rs:367`),
fencing the session on mismatch.

### 1f. `HostOwnerLease` — installation-wide admission, fail-closed
`crates/kernel/eliot-platform-windows/src/lib.rs:1240`. `acquire` (`:1259`) creates a named mutex
whose name is `SHA-256(installation_id)` (`host_owner_mutex_name`, `:1225`) under an explicitly
built protected security descriptor. **`ERROR_ALREADY_EXISTS` is never joined or waited on** — the
handle is closed and `HostOwnerLeaseError::ExistingObject` is returned (`:1305-1318`); any other
Win32 result yields `OwnershipUncertain`. `release` (`:1349`) deliberately retains handle+ownership
on a failed `ReleaseMutex` rather than abandoning the gate. Called from
`bins/eliot-host/src/lib.rs:1729` and `:1810`, and from
`crates/kernel/eliot-host-service/src/service.rs:209`; failures map to `HostError::OwnerLeaseHeld` /
`OwnerLeaseRecovery` at `bins/eliot-host/src/lib.rs:2609-2628`.

**Verdict Q1: IMPLEMENTED.** These are executed comparisons in production call paths with typed
rejections, not type-level modelling.

---

## Q2 — Host state journal durability: crash-recoverable, but NOT WIRED

`crates/kernel/eliot-host-state` contains **two independent durable stores**, and the sophisticated
one is not the one Host uses.

### 2a. `HostStateJournal` (journal.rs + redb_journal.rs) — genuinely crash-recoverable
- Framing: `JOURNAL_MAGIC = b"ELIOT-HOST-STATE\n"`, `JOURNAL_VERSION = 1` (`journal.rs:15-16`).
  `frame()` (`journal.rs:103`) writes magic + JSON header (version, sequence, length, SHA-256 of
  payload) + payload.
- `scan_frames` (`journal.rs:151`) fails closed on every torn/altered condition:
  `JournalError::Torn{offset}` on bad magic (`:161`), missing header newline (`:169`), truncated
  payload / missing terminator (`:186`); `UnknownVersion` (`:171`); `Checksum{sequence}` on payload
  digest mismatch (`:190`); `Sequence` on a gap (`:194`). A torn tail is NOT silently truncated.
- Two-phase durable protocol: `JournalBackend` (`backend.rs:75`) =
  `prepare → append_prepared → flush → sync → commit`, with `reconcile()` returning
  `Absent | Prepared | Committed(receipt)`. `HostStateJournal::append` (`journal.rs:770`) calls
  `reconcile` FIRST (`:806`); a `Committed` receipt replays idempotently (`:811-820`), a surviving
  `Prepared` returns `JournalError::OutcomeUnknown{transaction_id}` (`:823`) rather than guessing.
- `RedbJournalBackend` persists every phase in its own redb write transaction (`commit_write`,
  `redb_journal.rs:535`). `commit` (`:730`) refuses unless flushed+synced (`:747`) and re-verifies
  `sha256_digest(bytes) == descriptor.payload_digest` → `BackendError::Conflict` (`:753`).
  `persist_commit` (`:541`) writes epoch bytes + receipt + payload and removes the PREPARED row in
  **one** redb transaction.
- Path protection: `open` (`redb_journal.rs:160`) requires `require_protected_program_data_path`,
  takes a `ProtectedPathLease`, and re-verifies path identity after `Database::create` (`:174`).
  `inspect_existing` (`:109`) is a read-only, non-creating variant.

### 2b. Corruption recovery / quarantine — real, in the journal reducer
- `load_epochs` (`journal.rs:447`): with `tolerate_corruption == false`, a failed replay returns the
  error (`:487`) — load is blocked. With `tolerate_corruption == true` (`:480`), the failed epoch is
  retained as `EpochEvidence { replay_verified: false, forensic_digest: checksum(bytes), .. }` —
  quarantined with forensic evidence, not discarded.
- The tolerance flag comes from the caller's own identity: `state_for_host` (`journal.rs:575-577`)
  sets `tolerate_corruption = (host.recovery.reason == RecoveryLineageReason::Corruption)`.
- The new-lineage requirement is enforced at `journal.rs:604-613`: a host with `parent == None` is
  accepted only if `recovery.is_some()`, `sequence == 1`, same installation, and **no retained epoch
  shares its lineage**; otherwise `JournalError::RecoveryRequiresNewEpoch`. The recovered state is
  marked `prior_kernel_unknown = true` (`:616`).
- Quarantined receipts stay non-authoritative: `validate_committed_receipts` (`journal.rs:536-546`)
  skips receipts of unverified epochs only under a Corruption recovery for a different host, and
  otherwise rejects with `"committed receipt belongs to an unverified host epoch"`.
- Proven by `redb_corrupt_retained_epoch_is_quarantined_for_recovery` (`redb_journal.rs:1630`):
  flips one payload bit, opens under a NEW lineage with `RecoveryLineageReason::Corruption`, asserts
  the retained epoch is present with `replay_verified == false` and the expected `forensic_digest`,
  asserts the old transaction now reconciles to `StaleFence`, appends into the new lineage, reopens
  and re-verifies. The fail-closed counterpart is
  `redb_corrupt_current_epoch_requires_explicit_recovery` (`redb_journal.rs:1591`).

**So: YES — a corrupt retained epoch opens a new lineage rather than blocking load. But only in this
reducer, and only when the caller supplies `RecoveryLineageEvidence`.**

### 2c. The gap: no production caller
`grep` across `bins/`, `crates/`, `workspace/` finds **zero** references to `HostStateJournal`,
`RedbJournalBackend`, `JournalBackend`, or `MemoryBackend` outside `crates/kernel/eliot-host-state`
itself. The only workspace dependant of the crate is `bins/eliot-host`
(`bins/eliot-host/Cargo.toml:18`), and its import list (`bins/eliot-host/src/lib.rs:18-21`) is
exactly `{HostAdmissionState, HostInstallationEpoch, HostRecoverySnapshot, RedbHostReleaseToken,
RedbHostStateStore}` — none of the journal API. The two-phase journal is exercised only by the
crate's own tests.

What Host actually uses is `RedbHostStateStore` (`redb_store.rs`), a simpler projection:
- `open_epoch` (`redb_store.rs:451`) called from `bins/eliot-host/src/lib.rs:1743`;
  `open_existing` (`redb_store.rs:231`) called from `bins/eliot-host/src/lib.rs:1819`.
- No frame magic, no per-record checksum, no sequence chain, no PREPARED/COMMITTED set. State and
  epoch are written by two **separate** redb transactions (`write_state` `:505`, `write_epoch`
  `:523`), so `open_epoch` (`:481-493`) is not atomic across the pair.
- It does have real CAS where it matters: `mutate_with_epoch` (`:573`) compares the durable epoch
  binding inside one write transaction (`:600` → `HostStateError::InvalidRecord`), and
  `commit_activation_atomic` (`:767`) commits activation + process-recovery binding in one
  transaction.
- **`next_epoch` (`redb_store.rs:718`) hardcodes `recovery: None` (`:759`).** The production Host
  epoch advance can therefore never produce `RecoveryLineageEvidence`, so 2b is unreachable from Host.
- A corrupt/undeserializable epoch or state row returns `HostStateError::Unavailable`
  (`read_epoch_from_read` `:651-653`, `read_state_from_read` `:695`) — load is **blocked**, with no
  quarantine and no lineage fork. `HostComposition::recover_unclean`
  (`bins/eliot-host/src/lib.rs:1802`) cannot help: it calls `inspect_recovery` first, which
  deserializes the same rows.
- `redb = "4.1.0"` (root `Cargo.toml:260`); no `set_durability` call exists anywhere in the
  workspace, so both stores rely on redb's default commit durability. UNKNOWN whether that default
  satisfies the intended fsync guarantee — not verifiable from this repo.

**Verdict Q2: journal = IMPLEMENTED but dead code by wiring. Production Host state = a separate,
weaker store that fails closed on corruption with no recovery lineage.**

---

## Q3 — `eliotd` wiring: NOT a shell, but NOT an in-process Kernel

`bins/eliotd` contains **no** in-process Kernel, **no** Store adapter, and **no** physical
`ProcessExecutor`. That is deliberate: `bins/eliotd/src/main.rs:3-5` states it "composes Governor
only from that transport and never creates a local Store, `ProcessExecutor`, or authority source."
`eliotd` is the **Governor daemon**, a remote client of Kernel.

Verified from `bins/eliotd/Cargo.toml:16-29`: dependencies are `eliot-contracts, eliot-governor,
eliot-ipc, eliot-maintenance, eliot-platform, eliot-platform-windows, eliot-protocol, eliot-receipts,
eliot-runtime-contracts, eliot-store-api, serde, serde_json, tokio, thiserror`. There is no
`eliot-process`, `eliot-process-executor`, `eliot-kernel-core`, `eliot-kernel-service`, `eliot-ors`,
or `eliot-store-surreal` dependency — an in-process Kernel or physical executor is not linkable.
`WindowsProcessExecutor` is constructed in exactly two places, neither of them `eliotd`:
`bins/eliot-kernel/src/lib.rs:1031` (`ProcessExecutionGateway::new`) and
`bins/eliot-user-broker/src/lib.rs:424`.

### What `main` actually constructs (`bins/eliotd/src/main.rs:59-72`)
1. `DaemonConfig::load_protected()` (`bins/eliotd/src/lib.rs:112`) — reads the fixed `ProgramData`
   path through `ProtectedPathLease::open_existing_absolute` + `read_bounded`, parses
   `GovernorLaunchConfig`; `from_launch` (`:126`) rejects any path that is not the fixed protected
   identity (`:135-139`). No env var, no CLI root override. It derives a `KernelLaunchBinding`
   (pipe name, expected Kernel SID, expected session id, generation, authority epoch, state fence,
   launch nonce, artifact hash) at `:141-150`.
2. `DaemonKernelClient::connect(&config)` (`:233`) — real, not a stub. On Windows it builds a
   current-thread tokio runtime and performs `snapshot_request()`, replacing the locally derived
   expectation with the **server-owned** snapshot (`:251-256`). On non-Windows it returns
   `KernelClientError::Unsupported` (`:258-263`) — no fake success. Transport is `connect_transport`
   (`:475`): `NamedPipeTransport::connect_authenticated` with a `NamedPipePeerExpectation`, then an
   explicit re-check of `PeerIdentity::Authenticated { process_id != 0, user_identity == sid,
   session_identity == session }` → `KernelClientError::Contract` (`:495-510`), then
   ClientHello/ServerHello with `validate_server_hello` (`:527`).
3. `DaemonComposition::start(config, kernel as Arc<dyn KernelGenerationPort>)` (`:971`) — requires
   the retained config lease (`:977`), `verify_stable_identity()`, re-reads the bytes and rejects if
   they changed since load (`:987-991`, a TOCTOU guard), prepares the protected state root, opens
   `daemon.lifecycle` under a `ProtectedPathLease` and rejects an identity change (`:993-1001`), then
   builds `GovernorComposition::new(kernel, &config.launch().kernel, QueueLimits::default())`
   (`:1003`). `GovernorComposition::new`
   (`crates/governor/eliot-governor/src/composition.rs:1195`) takes the port's snapshot, checks it
   with `KernelGenerationExpectation::admits` (`:1201`), and drives `recover_from_kernel` (`:1205`).
4. `kernel.report_ready()` (`bins/eliotd/src/lib.rs:269`) — an authenticated `daemon_ready`
   transaction carrying generation + authority epoch.
5. A current-thread tokio runtime running `run_loop` (`main.rs:113`): `ctrl_c` vs a 5-second
   `KernelTransitionPort::health` heartbeat; a heartbeat failure exits the loop and drives
   `report_degraded` then `report_fatal` (`main.rs:81-92`).

**Verdict Q3: IMPLEMENTED as a Kernel-client Governor daemon, not a shell.** If the architecture
expects `eliotd` to host Kernel in-process, the code contradicts that — see divergences.

---

## Q4 — IPC: bounded YES; peer auth enforced on BOTH paths YES

Scope correction: **`crates/eliot-windows-ipc` is not the named-pipe transport.** Its header
(`crates/eliot-windows-ipc/src/lib.rs:1-4`) describes it as the single audited Win32 FFI boundary;
it holds pinned files, oplock guards, Job Objects, process-tree guards, and
`named_pipe_client_process` (`:377`). Its dependants are `eliot-app`, `eliot-engine`, `eliot-store`,
`eliot-platform-windows`. The Kernel/Host/daemon transport lives entirely in
`crates/kernel/eliot-ipc/src/lib.rs`.

### 4a. Bounds — IMPLEMENTED
- `MAX_FRAME_BYTES = 4 * 1024 * 1024` (`crates/foundation/eliot-protocol/src/lib.rs:36`).
  `TransportLimits::default()` (`crates/kernel/eliot-ipc/src/lib.rs:184`) =
  `{max_frame_bytes: MAX_FRAME_BYTES, queue_capacity: 128, queue_bytes: 8 MiB,
  control_reserve: 4, operation_timeout: 30s}`. `TransportLimits::validate` (`:197`) rejects
  zero/oversized frame bytes, zero capacity, `queue_bytes < max_frame_bytes`,
  `control_reserve >= queue_capacity`, and a zero timeout → `TransportError::InvalidLimits`.
- Read path `receive_wire` (`:1586`): reads the 4-byte LE length prefix under
  `tokio::time::timeout(limits.operation_timeout, ..)` → `TransportError::Timeout`; **rejects
  `length == 0 || length > max_frame_bytes` BEFORE allocating** → `ProtocolError::OversizeFrame`
  (`:1603-1608`); reads the body under the same timeout.
- Streaming path `FrameDecoder::push` (`:826`) inspects the 4-byte prefix before appending
  attacker-controlled bytes (explicit comment at `:836-838`), clears the buffer and errors on
  oversize (`:869-875`), and returns `Backpressure` if a fragment would overrun the declared frame (`:876`).
- `AdmissionQueue::admit` (`:726`) bounds by item count and byte total with a dedicated control
  reserve → `TransportError::Backpressure`; `QueueReservation` is a one-shot token so a caller
  cannot release someone else's capacity.
- Write path `send_wire` (`:1574`) is timeout-bounded and maps both I/O failure and timeout to
  `DeliveryOutcome::UnknownOutcome` — never a fabricated success.
- Pipe names: `validate_pipe_name` (`:1168`) requires the literal prefix `\\.\pipe\eliot\`, length
  <= 240, no control chars, and per-component rejection of `.`/`..`/`/`/`:`/NUL and any non
  `[A-Za-z0-9-_.]` character → `TransportError::InvalidPipeName`.

### 4b. Peer authentication — enforced on BOTH server and client
- **Server authenticating the client**: `NamedPipeServer::wait_for_authenticated_client` (`:1327`)
  reads the fixed 8-byte `AUTHENTICATION_PREFACE = b"ELIOT-P2"` (mismatch →
  `TransportError::UnauthenticatedPeer`, `:1568`), then
  `eliot_platform_windows::authenticate_named_pipe_client`
  (`crates/kernel/eliot-platform-windows/src/lib.rs:5813`): validates the pipe DACL (`:5826`),
  `GetNamedPipeClientProcessId` + `OpenProcess`, `admit_named_pipe_peer_process`, reads the process
  token, **impersonates the client and compares the thread token to the process token**, reverts via
  an RAII `ImpersonationGuard`, and rejects on
  `process_token != thread_token || sid != expected_sid || session != expected_session` →
  `WindowsAdapterError::IdentityMismatch` (`:5842-5850`).
- **Client authenticating the server**: `NamedPipeTransport::connect_authenticated` (`:1379`) calls
  `Inner::authenticate` (`:1477`) → `authenticate_named_pipe_server`
  (`crates/kernel/eliot-platform-windows/src/lib.rs:5759`): validates the pipe DACL (`:5772`),
  `GetNamedPipeServerProcessId` + `OpenProcess`, rejects on SID/session mismatch (`:5788-5790`).
  Only after this does it send the preface.
- **Neither path can exchange frames without proof.** `require_authenticated_peer` (`:270`) returns
  `TransportError::PlanGap { dependency: "eliot-platform-windows", .. }` for a
  `PeerIdentity::Unavailable`, and it gates `NamedPipeServer::send_frame`/`receive_frame`
  (`:1352`, `:1362`) and `NamedPipeTransport::send_frame`/`send_frame_with_cancel`/`receive_frame`
  (`:1392`, `:1406`, `:1424`). `map_platform_error` (`:250`) maps both `IdentityMismatch` and
  `AclMismatch` to `TransportError::UnauthenticatedPeer`.
- Pipe ACL at creation: `PipeSecurityDescriptor::for_principal` (`:1211`) builds SDDL
  `D:P(A;;GA;;;SY)(A;;GA;;;{expected_sid})` — protected DACL, SYSTEM plus one expected principal;
  `ServerOptions` sets `reject_remote_clients(true)` and `first_pipe_instance` for the first instance
  (`:1301-1305`). `validate_pipe_dacl` (`crates/kernel/eliot-platform-windows/src/lib.rs:6881`)
  re-reads the live DACL from the handle, caps it at 16 ACEs, and requires the expected SID ACE — so
  a squatted pipe fails.
- Production callers use the authenticating variants: Kernel front door
  `bins/eliot-kernel/src/main.rs:167`; Store `bins/eliot-store-surreal/src/main.rs:79-85`;
  Host `bins/eliot-host/src/lib.rs:659-663`; daemon `bins/eliotd/src/lib.rs:481-510`.
- Note (not a hole): `admit_named_pipe_peer_process`
  (`crates/kernel/eliot-platform-windows/src/lib.rs:5721`) only enforces PID/start-time/image when
  `expectation.approved_process_binding()` is `Some`, and Kernel's front door uses
  `current_process_named_pipe_expectation()` (`:5867`) which carries SID + session only. The
  image/PID binding is enforced one layer up in `apply_control_request`
  (`bins/eliot-kernel/src/lib.rs:2954-2957`) and by Host in reverse
  (`bins/eliot-host/src/lib.rs:664-676`). Defense in depth is intact, but the transport layer alone
  does not bind the peer image.

### 4c. One real bound gap
`bins/eliot-kernel/src/main.rs:167-169` calls
`front_door.wait_for_authenticated_client(Duration::from_secs(86_400), &principal)`. That single
timeout is used for **both** the accept (`wait_for_client`, `crates/kernel/eliot-ipc/src/lib.rs:1317`)
**and** the authentication-preface read (`:1335`). A peer that connects and never writes the 8-byte
preface holds the accept future for 24 hours; `bind_authenticated_front_door_next()` is only called
after that future resolves (`bins/eliot-kernel/src/main.rs:180-186`), so the front-door accept loop
stalls. Reachability is limited to principals already admitted by the pipe DACL, which caps severity.
Established sessions are fine — `receive_frame` applies the 30 s `operation_timeout` per frame.

**Verdict Q4: bounded = IMPLEMENTED; bidirectional peer auth = IMPLEMENTED; one loose
accept/preface timeout (P2).**

---

## Conformance table

| # | Architecture obligation (handle + one line) | Code owner (path) | Status | Evidence |
|---|---|---|---|---|
| 1 | A13.2 Kernel must not issue unproven authority | `bins/eliot-kernel/src/lib.rs` | IMPLEMENTED | `apply_control_request` at `:2937` rejects on epoch/generation/artifact/config/peer mismatch → `SessionFenced` (`:2950-2980`); called from `serve_connection` at `bins/eliot-kernel/src/main.rs:350 (inside `serve_connection`, `:236`)` |
| 2 | A13.2 Kernel must fence stale owners | `crates/kernel/eliot-kernel-service/src/lifecycle.rs` | IMPLEMENTED | `synchronize_authority_epoch:413` rejects epoch regression (`:427`), corrupt (`:433`), oversized (`:439`); `fence_generation:270` sets a non-clearable fence; called from `bins/eliot-kernel/src/lib.rs:1766` and `:1819` |
| 3 | A13.2 Kernel must safely freeze state rather than proceed on a partial transition | `bins/eliot-kernel/src/lib.rs` | IMPLEMENTED | `OrsGenerationCoordinator::persist_and_publish:1785` commits to ORS at `:1805-1811` before any in-memory publication; `generation_poison` blocks `dispatch_frame:2431` and `bind_authenticated_front_door:2662` |
| 4 | A13.2 Host Supervisor sits outside the Kernel process failure domain | `bins/eliot-host/src/lib.rs`, `src/main.rs` | IMPLEMENTED | Host is its own SCM service (`main.rs:163 run_as_scm_service`, `:200 service_main`); it owns two Job-Object branches `HostJobBranches { kernel, store }` at `lib.rs:271` and never links Kernel in-process |
| 5 | A13.2 Host performs only start/stop/bounded restart/approved rollback, reads no semantics | `bins/eliot-host/src/lib.rs` | IMPLEMENTED | `reconcile_state_machine:331` caps each branch at **one** restart (`state.store_restart_attempts >= 1` at `:359`, kernel at `:380`); beyond that the branch is marked degraded, not looped |
| 6 | A13.2 Watchdog holds a separate service identity | `bins/eliot-host/src/lib.rs` | IMPLEMENTED | `request_watchdog:1933` verifies the watchdog artifact digest under a lease (`:1953`) and registers a distinct SCM service `"eliot-watchdog"` / `LocalSystem` (`:1959-1968`), rejecting `EffectUnknown` (`:1975`) |
| 7 | A13.3 Module lifecycle: start / health / drain / restart / replace / rollback / quarantine / retire | `crates/kernel/eliot-kernel-service/src/lifecycle.rs` | IMPLEMENTED (state machine) | `KernelServiceState:25` covers Cold, Reconciling, ShadowNoAuthority, HandoffPrepared, Activating, Ready, Degraded, Draining, Stopped, Failed, ManualRecovery; driven by `apply:294`, reached from `KernelRuntime::apply_control` (`bins/eliot-kernel/src/lib.rs:2768`, called at `:3006`) |
| 8 | A13.3 Replacement = stop new work → drain → fence old epoch → replace → health → resume or rollback | `bins/eliot-host/src/lib.rs` | SHELL (no caller) | `cutover_with_rollback:1510` drains via `terminate_store_then_kernel` then relaunches only the prior approved images on failure; its only caller is `cutover_generation:2114`, which **has zero callers workspace-wide** |
| 9 | A13.3 Quarantine / bounded restart budget for a replaced module | `crates/kernel/eliot-kernel-service/src/protocol.rs` | IMPLEMENTED (transported), not consumed | `RestartBudget:960` + `consume:980` → `RestartBudgetExhausted`; Host sends `RestartBudget::new(3,3)` at `bins/eliot-host/src/lib.rs:641`, but no code path calls `consume()` |
| 10 | A2.2 Host Supervisor issues no canonical authority | `bins/eliot-host/src/lib.rs` | IMPLEMENTED | Host authors no readiness receipt (`:648-655`); the receipt is produced by Kernel at `bins/eliot-kernel/src/lib.rs:2795` and only validated by Host at `lib.rs:745-749` |
| 11 | A2.3 Kernel owns identity, authority, fencing, canonical transition boundary and recovery entrypoint | `bins/eliot-kernel/src/lib.rs` | IMPLEMENTED | Single `KernelRuntime` composition owns `front_door_policy`, `service`, `generation_gateway:261`, `process_gateway`, `canonical_store_gateway`; all control passes `apply_control_request:2937` |
| 12 | A2.3 Host owns the physical lifecycle of approved generations; Kernel owns logical lifecycle | `bins/eliot-host/src/lib.rs`, `bins/eliot-kernel/src/lib.rs` | IMPLEMENTED | Host spawns suspended and validates image+digest under lease (`HostJobBranches::launch:764`, `spawn_named:843`); Kernel never spawns Host-tier processes — `WindowsProcessExecutor` is only for admitted work (`bins/eliot-kernel/src/lib.rs:1031`) |
| 13 | A12.2 Principal/session bound by the installation boundary, not self-declared | `crates/kernel/eliot-platform-windows/src/lib.rs` | IMPLEMENTED | `authenticate_named_pipe_client:5813` (impersonation + token comparison) and `authenticate_named_pipe_server:5759`; both validate the DACL via `validate_pipe_dacl:6881` |
| 14 | A12.2 Session bound to an Authority Epoch; unknown identity gets minimum privilege | `crates/kernel/eliot-ipc/src/lib.rs` | IMPLEMENTED | `establish_with_server:596` requires exact `authority_epoch` + `launch_nonce` + `ModuleGeneration` (`:604-613`); `require_authenticated_peer:270` blocks all frames without proof |
| 15 | A12.2 Session lifecycle attach → active → suspended → detached/expired/revoked | `crates/kernel/eliot-ipc/src/lib.rs` | IMPLEMENTED (partial) | `SessionState` + `fence:654` (bumps `session_epoch`), `begin_reconnect:660`; `accepts:670` / `accepts_bound:677` refuse a fenced session. No `expired` timer distinct from `Fenced` |
| 16 | A11.2 An unverified executable receives no secrets or elevated authority | `bins/eliot-host/src/lib.rs` + `crates/kernel/eliot-installation/src/lib.rs` | IMPLEMENTED | `HostJobBranches::launch:764` spawns suspended, then `verify_file_digest_with_lease` on artifact + config (`:806-830`) under a retained lease before resume; supplied paths are bound to approved manifest paths by `approved_locator:171` → `verify_approved_path:354` (path + file identity) |
| 17 | A11.2 Installation approval is deterministic human interaction and the trust root is explicit | `crates/kernel/eliot-installation/src/lib.rs` | SHELL | `CandidateManifest.signature_ref:774` is only checked for well-formedness at `:1238`. `descriptor_digest` (`:1107-1113`) is a *self*-digest of the descriptor's own fields, not a signature. No signature verification exists |
| 18 | A11.2 The approved-generation registry is the durable trust record | `bins/eliot-host/src/lib.rs` | SHELL (no writer) | `approve_generation:1876`, `activate_generation:1895`, `rollback_generation:1917`, `cutover_generation:2114` are the only writers of `registry_store.save` — and none of them has any caller anywhere in the workspace |
| 19 | A11.3 Capability Registry (installation identity, transport, model routes, competence, verifier validity, health) | — | ABSENT in this domain | `grep -i capability` over the workspace finds no `CapabilityRegistry`; `crates/kernel/eliot-installation/src/lib.rs:690` explicitly documents `IntegrationDiscoveryCatalogue` as "not a capability registry". UNKNOWN whether a Smart/Governor crate owns it |
| 20 | A10.2 Effect defines impact/authority; process execution is admitted, not assumed | `bins/eliot-kernel/src/lib.rs` | IMPLEMENTED | `ProcessExecutionGateway::new:1013` binds a `ControllerDispatchPort` + `KernelPathAdmission` as `ProcessLaunchAdmission` into `WindowsProcessExecutor::new_with_launch_admission:1031`; dispatch validation at `:1003` maps a binding mismatch to `DispatchBindingMismatch` |
| 21 | A10.3 Material/Critical action needs preconditions, expected observable, rollback and verifier | `bins/eliot-kernel/src/lib.rs` | IMPLEMENTED (process domain) | `OrsProcessReplayStore` (`:422`) records Reserved/Started replay state; the sealed authority snapshot `open:384` rejects a credential-reference mismatch (`:394`) and an authority-id mismatch → `KernelError::FenceMismatch` (`:414`) |
| 22 | A12.3 One governed write path; no second writer to canonical state | `bins/eliotd/src/lib.rs` | IMPLEMENTED | `eliotd` links no Store or executor crate (`bins/eliotd/Cargo.toml:16-29`); every write goes through `KernelTransitionPort::apply_prepared` (`:630`) over the authenticated pipe |
| 23 | A2.3 / A13.2 Host-local operational state must survive crash | `crates/kernel/eliot-host-state` | SHELL (by wiring) | Full two-phase journal exists (`journal.rs:770`, `redb_journal.rs:730`) with corruption quarantine (`journal.rs:480`), but no caller outside the crate; Host uses `RedbHostStateStore` instead (`bins/eliot-host/src/lib.rs:1743`) |
| 24 | IPC frames must be bounded and time-bounded | `crates/kernel/eliot-ipc/src/lib.rs` | IMPLEMENTED | `TransportLimits::validate:197`; `receive_wire:1586` rejects oversize before allocating (`:1600`); `FrameDecoder::push:826` prefix-checks before buffering; `AdmissionQueue::admit:726` bounds items+bytes with a control reserve |
| 25 | IPC peer authentication on both server and client legs | `crates/kernel/eliot-ipc/src/lib.rs` + `crates/kernel/eliot-platform-windows/src/lib.rs` | IMPLEMENTED | Server: `wait_for_authenticated_client:1327` → `authenticate_named_pipe_client:5813`. Client: `connect_authenticated:1379` → `authenticate_named_pipe_server:5759`. Both gated by `require_authenticated_peer:270` before any frame |

---

## Gaps ranked

- **[P1] The approved-generation registry has no writer, so a clean install can never start anything.**
  A11.2/A13.3 require an approved generation to exist before Host launches a contour.
  `HostComposition::open` starts a contour only `if composition.registry.active().is_some()`
  (`bins/eliot-host/src/lib.rs:1781-1785`). The only functions that ever write that registry are
  `approve_generation` (`:1876`), `activate_generation` (`:1895`), `rollback_generation` (`:1917`)
  and `cutover_generation` (`:2114`) — and a workspace-wide grep finds **zero callers** for any of
  them. The console fallback exposes only `Request::Status` and `Request::Stop`
  (`bins/eliot-host/src/main.rs:13-16`). There is no installer, CLI verb, or IPC command that
  approves a generation. Consequence: on a fresh machine Host acquires the owner lease, advances its
  epoch, and then supervises nothing.

- **[P1] The crash-recoverable Host journal is dead code; the store Host actually uses cannot
  recover from corruption.** A13.2 requires Host state to survive and be safely recoverable.
  `HostStateJournal` / `RedbJournalBackend` (two-phase commit, torn-frame detection, corruption
  quarantine, forced new lineage — `journal.rs:770`, `:480`, `:604-613`) has no caller outside
  `crates/kernel/eliot-host-state`. Host uses `RedbHostStateStore`, whose `next_epoch`
  (`redb_store.rs:718`) hardcodes `recovery: None` (`:759`), so the corruption/new-lineage path is
  unreachable. A corrupt epoch row makes `read_epoch_from_read` return `Unavailable`
  (`redb_store.rs:651-653`), which blocks `open_epoch` **and** `inspect_recovery`, so
  `recover_unclean` (`bins/eliot-host/src/lib.rs:1802`) cannot clear it either. The installation is
  unrecoverable in-product.

- **[P1] The generation replacement/rollback lifecycle is unreachable.** A13.3 mandates
  `stop new work → drain → fence old epoch → replace → health → resume or rollback`. The
  implementation exists and is correct-looking (`cutover_with_rollback`,
  `bins/eliot-host/src/lib.rs:1510`, drains then restores only prior approved images), but its sole
  caller `cutover_generation` (`:2114`) has no caller. So the architecture's replacement path is
  library API only. Same for `recover_unclean` (`:1802`).

- **[P1] Installation manifests are not signature-verified.** A11.2: "Непроверенный executable не
  получает secrets или elevated authority." The *executables* are digest-verified against the
  manifest (`bins/eliot-host/src/lib.rs:806-830`), which is good. But the manifest that declares
  those digests carries only `signature_ref: PlatformHandle`
  (`crates/kernel/eliot-installation/src/lib.rs:774`), validated for text well-formedness at
  `:1238`. `descriptor_digest` (`:1107`) is a self-hash of the descriptor's own fields — it detects
  accidental edit, not forgery. The trust root is therefore filesystem ACLs on the protected
  ProgramData registry, not a verified approval chain.

- **[P2] Kernel front-door accept and preface read share an 86,400-second timeout.**
  `bins/eliot-kernel/src/main.rs:167-169` passes `Duration::from_secs(86_400)` into
  `wait_for_authenticated_client`, which uses it for both `wait_for_client`
  (`crates/kernel/eliot-ipc/src/lib.rs:1317`) and `read_authentication_preface` (`:1335`). A peer
  that connects and stays silent stalls the accept loop for 24 hours because
  `bind_authenticated_front_door_next()` runs only after that future resolves
  (`bins/eliot-kernel/src/main.rs:180-186`). Bounded by the pipe DACL to SYSTEM/expected-SID
  principals, which is why this is P2 and not P1.

- **[P2] Host startup depends on `ELIOT_KERNEL_BINARY` / `ELIOT_STORE_BINARY` environment
  variables.** `HostComposition::open` reads them via `configured_image`
  (`bins/eliot-host/src/lib.rs:2639`, `:1782-1783`) even though `active.manifest.runtime_paths()`
  (`crates/kernel/eliot-installation/src/lib.rs:1255`) already carries the approved paths. Not a
  security hole — `approved_locator` (`bins/eliot-host/src/lib.rs:171`) binds the supplied path to
  the approved path by protected-lease identity — but an SCM service whose startup depends on
  process environment is fragile, and a missing variable silently degrades to "no contour".

- **[P2] `RestartBudget` is transported but never consumed.** Host sends `RestartBudget::new(3, 3)`
  in every handshake (`bins/eliot-host/src/lib.rs:641`) and
  `crates/kernel/eliot-kernel-service/src/protocol.rs:980` implements `consume()` →
  `RestartBudgetExhausted`, but nothing calls it. Host's own bound is a separate hardcoded
  one-restart-per-branch counter (`bins/eliot-host/src/lib.rs:359`, `:380`). Two independent
  restart policies, one of them inert.

- **[P2] `open_epoch` is not atomic across state and epoch.** `RedbHostStateStore::open_epoch`
  (`crates/kernel/eliot-host-state/src/redb_store.rs:481-493`) calls `write_state` (`:505`) and
  `write_epoch` (`:523`) as two separate redb transactions. A crash between them leaves an
  installation row without its epoch row. `mutate_with_epoch` (`:573`) and
  `commit_activation_atomic` (`:767`) do get this right, so the pattern is understood — the open
  path just does not follow it.

- **[P2] A11.3 Capability Registry has no owner in this domain.** No `CapabilityRegistry` type
  exists anywhere in the workspace; `crates/kernel/eliot-installation/src/lib.rs:690` explicitly
  disclaims that role for `IntegrationDiscoveryCatalogue`. Whether a Smart or Governor crate owns
  it is out of my scope — flagged so another domain worker confirms or the gap is recorded.

---

## Divergences where CODE looks RIGHT and the DOC looks stale

- **`eliotd` is a Kernel *client*, not a Kernel host.** A2.3 lists Kernel at layer 0 and does not
  describe a separate Governor daemon process. The code's topology is explicit and coherent:
  `bins/eliotd/src/main.rs:3-5` says it never creates a local Store, `ProcessExecutor`, or authority
  source, and `bins/eliotd/Cargo.toml:16-29` makes that structurally enforceable by not depending on
  any of those crates. The code's separation is stronger than the doc's; the doc should name the
  daemon explicitly rather than leaving the reader to infer that `eliotd` hosts Kernel.

- **The store-engine / store-bridge split is a real topology decision the doc does not carry.**
  Host launches exactly two Job-Object branches — Kernel and the canonical store engine
  (`bins/eliot-host/src/lib.rs:271`). `eliot-store-surreal.exe` is deliberately *not* Host-owned:
  `crates/kernel/eliot-installation/src/lib.rs:751-753` states "The bridge is route evidence only
  and is not a Host-owned process", and `runtime_paths()` (`:1255`) hands Host only
  (kernel, canonical_store, config). A2.3's "Kernel владеет логическим lifecycle и fencing Modules;
  внешний Host Supervisor выполняет physical lifecycle" is compatible but does not describe the
  bridge's non-supervised status, which is a load-bearing choice.

- **Readiness authorship is inverted relative to the naive reading of A13.2/A13.3.** One might read
  "Host Supervisor выполняет start, stop, bounded restart" as Host declaring a service healthy. The
  code deliberately refuses that: Host authors no receipt (`bins/eliot-host/src/lib.rs:648-655`) and
  Kernel proves its own readiness from its live process, reopened Job, config hash, service state
  and Store fence (`bins/eliot-kernel/src/lib.rs:2795-2889`). This is the correct reading of "не
  выдаёт canonical authority" and the doc could state it as an explicit obligation.

---

## Confidence

**High confidence** on Q1, Q3, Q4 and on the "no caller" findings — these are exhaustive
workspace-wide greps plus reads of the actual function bodies, and every claim above carries a
`path:line`.

**What I could not check:**
- **No runtime evidence.** The product is not installed and not running, so nothing about actual
  crash behaviour, actual fsync ordering, actual DACL enforcement by the OS, or actual timeout
  behaviour is proven. All claims are source-level.
- **redb durability semantics.** No `set_durability` call exists in the workspace, so both stores
  use redb 4.1.0's default commit durability. I did not verify what that default is; if it is not a
  synchronous flush, the two-phase protocol in `journal.rs` is weaker than it reads. Marked UNKNOWN.
- **A11.3 Capability Registry** may be owned by a Smart/Governor crate outside my scope. I searched
  the whole workspace for the type name and found nothing, but I did not audit those crates'
  semantics, so "ABSENT" is scoped to this domain.
- **`crates/eliot-windows-ipc`** was read at header + public-surface level only (3063 lines of Win32
  FFI). I confirmed it is not the Kernel/Host transport and identified its dependants; I did not
  audit its `unsafe` blocks. If Win32 FFI correctness matters, that crate needs its own pass.
- **Whether the missing installer is intentional.** Findings P1-1, P1-3 assume the product is meant
  to reach a running state without an out-of-repo installer. If an external installer (MSI, separate
  repo) writes `installation-registry.redb` directly, those two gaps collapse to "no in-repo
  installer", which is a packaging question rather than a contract break. I found no such component
  in this repository.
