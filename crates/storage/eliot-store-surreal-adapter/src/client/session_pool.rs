//! Fixed bounded RPC session set under one provider generation.
//!
//! S-CONC-CLIENTS (issue #987): separate read, normal-write and protected
//! health/admin admission over the single provider process owned by #986's
//! process/session seam, without changing Store transaction semantics and
//! without implementing the global write scheduler (a later child).
//!
//! Design notes:
//!
//! - Slots are fixed at construction from [`ClientSetLimits`](crate::config::ClientSetLimits):
//!   one semaphore plus one free-list plus one checked-out counter per closed
//!   [`SessionRole`]. Checkout can never exceed the configured bound, and a
//!   second checkout of an exhausted role waits (async) or refuses
//!   deterministically ([`SessionPool::try_checkout`]).
//! - Sessions connect lazily on first checkout of a slot, always against the
//!   same provider owner handle the pool was built from. A session never
//!   starts or stops a process, so the pool cannot launch a second provider
//!   even under concurrent checkout.
//! - A broken generation fails checkouts with
//!   [`AdapterError::ProviderUnavailable`](crate::error::AdapterError) and is
//!   replaced explicitly by rebuilding the transport; in-flight writes with
//!   unknown outcome resolve by `WriteReceipt` before any replay (I14.21).
//! - No Store transaction semantics live here: this module only allocates
//!   authenticated sockets. The process-global write mutex stays in place
//!   until the separate complete-scope runtime integration replaces it.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::sync::{Mutex, OnceCell, Semaphore};
use tokio::time::Instant;

use super::provider_owner::ProviderOwner;
use super::session::RpcSession;
use super::{RpcResults, json_codec};
use crate::config::ClientSetLimits;
use crate::error::AdapterError;

/// Closed admission role for one pooled session.
///
/// The roles mirror I5.9's fixed client set: named reads under a read
/// semaphore, canonical transactions under the `WriteCoordinator` limit, and
/// an isolated health/admin lane that normal workload cannot consume (Control
/// Reserve, I14.3).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionRole {
    /// Named read operations.
    Read,
    /// Normal-write canonical transactions.
    NormalWrite,
    /// Protected health/admin operations (version, schema, backup, health).
    HealthAdmin,
}

impl SessionRole {
    /// Stable role name used in diagnostics. Never logged with credentials.
    /// Test evidence until production diagnostics consume it.
    #[cfg(test)]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::NormalWrite => "normal_write",
            Self::HealthAdmin => "health_admin",
        }
    }

    /// All roles in fixed declaration order.
    const ALL: [Self; 3] = [Self::Read, Self::NormalWrite, Self::HealthAdmin];

    /// Index into the pool's per-role tables.
    const fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::NormalWrite => 1,
            Self::HealthAdmin => 2,
        }
    }
}

#[cfg(test)]
impl fmt::Display for SessionRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One fixed session slot. The connection is established lazily on first
/// checkout so construction never pays for idle lanes; the slot count itself
/// is immutable after pool construction.
struct SessionSlot {
    cell: OnceCell<RpcSession>,
}

impl SessionSlot {
    fn new() -> Self {
        Self {
            cell: OnceCell::new(),
        }
    }
}

/// Per-role bounded allocation state. The semaphore owns the bound (exactly
/// one permit per slot); the free list owns slot identity; the counter owns
/// exact checked-out evidence. All three move together under the permit.
struct RoleState {
    semaphore: Arc<Semaphore>,
    free: Mutex<VecDeque<usize>>,
    checked_out: AtomicUsize,
}

impl RoleState {
    fn new(slot_count: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(slot_count)),
            free: Mutex::new((0..slot_count).collect()),
            checked_out: AtomicUsize::new(0),
        }
    }
}

struct PoolInner {
    owner: Arc<ProviderOwner>,
    connect_timeout: Duration,
    slots: Vec<SessionSlot>,
    roles: Vec<RoleState>,
    role_base: [usize; 3],
}

impl fmt::Debug for PoolInner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionPoolInner")
            .field("owner", &self.owner)
            .field("slots", &self.slots.len())
            .finish_non_exhaustive()
    }
}

/// Fixed bounded session set under one provider generation.
///
/// Clone shares the same generation, slots, and bounds: there is still one
/// pool, never a second provider process.
#[derive(Clone, Debug)]
pub struct SessionPool {
    inner: Arc<PoolInner>,
}

impl SessionPool {
    /// Builds the fixed slot set for `limits` against one provider owner.
    /// No session connects here; slots connect lazily on first checkout.
    /// `limits` is already validated (every role admits 1..=8 sessions), so
    /// no role can be born with zero permits.
    #[must_use]
    pub fn new(owner: Arc<ProviderOwner>, limits: ClientSetLimits) -> Self {
        let counts = [
            limits.read_sessions as usize,
            limits.write_sessions as usize,
            limits.admin_sessions as usize,
        ];
        let connect_timeout = Duration::from_millis(owner.config.connect_timeout_ms.max(1));
        let mut slots = Vec::with_capacity(counts.iter().sum());
        let mut roles = Vec::with_capacity(SessionRole::ALL.len());
        let mut role_base = [0usize; 3];
        for (index, count) in counts.iter().enumerate() {
            role_base[index] = slots.len();
            for _ in 0..*count {
                slots.push(SessionSlot::new());
            }
            roles.push(RoleState::new(*count));
        }
        Self {
            inner: Arc::new(PoolInner {
                owner,
                connect_timeout,
                slots,
                roles,
                role_base,
            }),
        }
    }

    /// Fixed slot count for `role`: free permits plus checked-out sessions.
    /// Test/diagnostic evidence only; the scheduler child (#988) and runtime
    /// integration (#993) promote this to production use.
    #[cfg(test)]
    #[must_use]
    pub fn slot_count(&self, role: SessionRole) -> usize {
        self.available(role) + self.checked_out(role)
    }

    /// Currently checked-out sessions for `role`. Exact counter evidence for
    /// boundedness proofs and diagnostics; never admission authority.
    /// Test evidence until the scheduler/runtime children consume it.
    #[cfg(test)]
    #[must_use]
    pub fn checked_out(&self, role: SessionRole) -> usize {
        self.inner.roles[role.index()]
            .checked_out
            .load(Ordering::SeqCst)
    }

    /// Currently available sessions for `role` (permits not held). Test
    /// evidence until the scheduler/runtime children consume it.
    #[cfg(test)]
    #[must_use]
    pub fn available(&self, role: SessionRole) -> usize {
        self.inner.roles[role.index()].semaphore.available_permits()
    }

    /// Checks out one session of `role`, connecting its slot on first use.
    /// Waits while the role is exhausted; concurrent checkouts of distinct
    /// slots proceed without sharing a socket.
    pub async fn checkout(&self, role: SessionRole) -> Result<PooledSession, AdapterError> {
        let state = &self.inner.roles[role.index()];
        let permit = state
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| AdapterError::ProviderUnavailable)?;
        let index = {
            let mut free = state.free.lock().await;
            free.pop_front().ok_or(AdapterError::ProviderUnavailable)?
        };
        let absolute = self.inner.role_base[role.index()] + index;
        let slot = &self.inner.slots[absolute];
        let deadline = Instant::now() + self.inner.connect_timeout;
        if let Err(error) = slot
            .cell
            .get_or_try_init(|| RpcSession::connect(&self.inner.owner, deadline))
            .await
        {
            self.release_slot(role, index);
            return Err(error);
        }
        state.checked_out.fetch_add(1, Ordering::SeqCst);
        Ok(PooledSession {
            pool: self.clone(),
            role,
            slot: index,
            _permit: permit,
        })
    }

    /// Non-blocking checkout. Returns `None` immediately when no connected
    /// session of `role` is free — either because the role is exhausted or
    /// because its free slots are still cold. Cold slots report unavailable
    /// here; [`SessionPool::checkout`] warms them. Callers that must shed
    /// load instead of queueing behind a lane use this entrypoint.
    pub fn try_checkout(&self, role: SessionRole) -> Option<PooledSession> {
        let state = &self.inner.roles[role.index()];
        let permit = state.semaphore.clone().try_acquire_owned().ok()?;
        let mut free = state.free.try_lock().ok()?;
        let base = self.inner.role_base[role.index()];
        let position = free
            .iter()
            .position(|index| self.inner.slots[base + index].cell.initialized())?;
        let index = free.remove(position)?;
        state.checked_out.fetch_add(1, Ordering::SeqCst);
        Some(PooledSession {
            pool: self.clone(),
            role,
            slot: index,
            _permit: permit,
        })
    }

    /// Returns a slot to its role's free list and releases its checked-out
    /// count. The semaphore permit releases on guard drop.
    fn release_slot(&self, role: SessionRole, index: usize) {
        if let Ok(mut free) = self.inner.roles[role.index()].free.try_lock()
            && !free.contains(&index)
        {
            free.push_back(index);
        }
    }

    /// Executes one closed named operation on a freshly checked-out session
    /// of `role`. The statement stays private schema data; callers provide a
    /// name and bindings, never a provider client or query string.
    ///
    /// A non-blocking fast path reuses a free connected slot without
    /// touching the semaphore queue; otherwise checkout waits for the next
    /// free slot of the role.
    pub async fn query(
        &self,
        role: SessionRole,
        operation: &'static str,
        statement: &str,
        bindings: Map<String, Value>,
    ) -> Result<RpcResults, AdapterError> {
        if let Some(session) = self.try_checkout(role) {
            return session.query(operation, statement, bindings).await;
        }
        let session = self.checkout(role).await?;
        session.query(operation, statement, bindings).await
    }

    /// The provider generation every slot of this pool connects against.
    /// Test/diagnostic evidence that independent sessions share one process.
    /// The runtime integration (#993) consumes this for generation checks.
    #[cfg(test)]
    #[must_use]
    pub fn provider(&self) -> &Arc<ProviderOwner> {
        &self.inner.owner
    }
}

/// One checked-out pooled session. Dropping the guard returns the slot and
/// releases its bound permit; the underlying socket stays connected for
/// reuse. The guard borrows nothing: the pool outlives it through the
/// internal `Arc`.
#[derive(Debug)]
pub struct PooledSession {
    pool: SessionPool,
    role: SessionRole,
    slot: usize,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl PooledSession {
    /// Role this session was checked out under. Test evidence until the
    /// runtime integration (#993) routes by role.
    #[cfg(test)]
    #[must_use]
    pub const fn role(&self) -> SessionRole {
        self.role
    }

    /// The connected session behind this guard. Every guard is constructed
    /// only after its slot's lazy connection succeeds, and slots never
    /// reset, so the cell is always initialized here.
    fn session(&self) -> &RpcSession {
        let absolute = self.pool.inner.role_base[self.role.index()] + self.slot;
        match self.pool.inner.slots[absolute].cell.get() {
            Some(session) => session,
            None => unreachable!("checked-out pool slot is always connected"),
        }
    }

    /// Executes one closed named operation on this checked-out session.
    pub async fn query(
        &self,
        operation: &'static str,
        statement: &str,
        bindings: Map<String, Value>,
    ) -> Result<RpcResults, AdapterError> {
        let (statement, bindings, prefix_len) = json_codec::encode_bindings(statement, bindings)?;
        let value = self
            .session()
            .request(
                operation,
                "query",
                json!([statement, Value::Object(bindings)]),
            )
            .await?;
        let mut results = RpcResults::from_value(&value)?;
        if results.values_len() < prefix_len {
            return Err(AdapterError::Serialization(
                "RPC query omitted binding decode results".to_owned(),
            ));
        }
        results.drain_prefix(prefix_len);
        Ok(results)
    }

    /// Issues one raw provider request on this session (version checks and
    /// test-only proof operations). The wire child (#991) promotes this to
    /// production use for reserved-write framing.
    #[cfg(test)]
    pub async fn request(
        &self,
        operation: &'static str,
        method: &'static str,
        params: Value,
    ) -> Result<Value, AdapterError> {
        self.session().request(operation, method, params).await
    }
}

impl Drop for PooledSession {
    fn drop(&mut self) {
        self.pool.release_slot(self.role, self.slot);
        self.pool.inner.roles[self.role.index()]
            .checked_out
            .fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(all(test, windows))]
mod pool_behavior_tests {
    #![allow(clippy::expect_used, clippy::print_stdout, clippy::large_futures)]

    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    use eliot_platform_windows::WindowsPlatform;
    use secrecy::{ExposeSecret, SecretString};
    use tokio::net::TcpStream;
    use tokio::process::Command;
    use tokio::time::{Instant, sleep};
    use uuid::Uuid;

    use super::super::RpcTransport;
    use super::super::provider_owner::{configure_provider_command, provider_environment};
    use super::*;
    use crate::config::MAX_CLIENT_SET_SESSIONS_PER_ROLE;
    use crate::{
        PINNED_SURREALDB_MAJOR, SchemaGeneration, SurrealAdapterConfig, SurrealStoreAdapter,
    };

    struct PoolHarness {
        root: PathBuf,
        config: SurrealAdapterConfig,
        adapter: Option<SurrealStoreAdapter>,
    }

    /// First genesis manifest entry: the same bootstrap the composition
    /// owner binds. Reproves `SurrealStoreAdapter::new_with_client_set`
    /// through the public constructor on every attempt.
    fn genesis_manifest() -> eliot_store_api::NamedOperationManifest {
        eliot_store_api::generated_operation_manifests()
            .expect("operation catalogue")
            .into_iter()
            .find(|entry| entry.name == eliot_store_api::GENESIS_MANIFEST_NAME)
            .expect("genesis manifest")
    }

    impl PoolHarness {
        async fn provision() -> Self {
            let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve loopback");
            let port = reservation.local_addr().expect("address").port();
            let root = std::env::temp_dir().join(format!("eliot-987-{}", Uuid::new_v4()));
            let exe = root.join("bin/surreal.exe");
            for path in [
                root.join("bin"),
                root.join("store/data"),
                root.join("store/work"),
                root.join("store/tmp"),
            ] {
                std::fs::create_dir_all(path).expect("isolated directory");
            }
            let provider = std::env::var_os("ELIOT_TEST_SURREAL_EXE").map_or_else(
                || PathBuf::from(r"C:\Tools\SurrealDB\surreal.exe"),
                PathBuf::from,
            );
            std::fs::copy(provider, &exe).expect("stage provider");
            let bind = format!("127.0.0.1:{port}");
            let mut config = SurrealAdapterConfig {
                endpoint: format!("ws://{bind}/rpc"),
                namespace: "pool987".into(),
                database: "selected987".into(),
                username: "pool987-user".into(),
                password: SecretString::new(format!("test-{}", Uuid::new_v4()).into()),
                provider_bind_address: bind,
                installation_id: "pool987".into(),
                installation_profile: "portable_dev".into(),
                runtime_state_roots_digest: "a".repeat(64),
                provider_executable_path: exe.to_string_lossy().into_owned(),
                provider_artifact_digest: eliot_store_api::sha256_hex(
                    &std::fs::read(&exe).expect("provider bytes"),
                ),
                provider_arguments: Vec::new(),
                store_data_root: root.join("store/data").to_string_lossy().into_owned(),
                store_work_root: root.join("store/work").to_string_lossy().into_owned(),
                store_temp_root: root.join("store/tmp").to_string_lossy().into_owned(),
                connect_timeout_ms: 30_000,
                query_timeout_ms: 30_000,
                expected_provider_major: PINNED_SURREALDB_MAJOR,
                expected_schema_generation: SchemaGeneration::v2(),
            };
            config.provider_arguments = config.expected_provider_arguments();
            // Bootstrap warm-up (986 pattern): prove the staged provider
            // binary starts and accepts its endpoint before the bounded
            // adapter window begins, so cold-start cost (fresh temp path,
            // first bind) cannot consume the whole readiness deadline. The
            // throwaway child is stopped and reaped; the adapter spawns its
            // own owned provider afterwards.
            let mut command = Command::new(&exe);
            configure_provider_command(
                &mut command,
                &config,
                &provider_environment(&config).expect("environment"),
            );
            command
                .env("SURREAL_USER", &config.username)
                .env("SURREAL_PASS", config.password.expose_secret());
            drop(reservation);
            let mut bootstrap = command.spawn().expect("bootstrap child");
            let bootstrap_deadline = Instant::now() + Duration::from_secs(30);
            loop {
                assert!(
                    bootstrap.try_wait().expect("bootstrap state").is_none(),
                    "staged provider exited during warm-up"
                );
                if TcpStream::connect(&config.provider_bind_address)
                    .await
                    .is_ok()
                {
                    break;
                }
                assert!(
                    Instant::now() < bootstrap_deadline,
                    "staged provider warm-up timed out"
                );
                sleep(Duration::from_millis(50)).await;
            }
            bootstrap.kill().await.expect("stop bootstrap");
            bootstrap.wait().await.expect("reap bootstrap");
            Self {
                root,
                config,
                adapter: None,
            }
        }

        /// Starts the adapter through the production path
        /// (`adapter.connect` → `apply::client` →
        /// `RpcTransport::connect_with_limits`) with bounded readiness retry
        /// (PR #1488 pattern): slow provider authentication waits up to ~30s
        /// with 100ms backoff instead of failing on the first attempt. The
        /// failed adapter is dropped before each retry because its client
        /// cell caches the first connection outcome.
        async fn start(&mut self, limits: ClientSetLimits) {
            let platform = WindowsPlatform::new(self.root.clone()).expect("platform");
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut last_error = None;
            loop {
                let lease = platform
                    .retain_process_path_lease(
                        Path::new(&self.config.provider_executable_path),
                        Path::new(&self.config.store_work_root),
                        &self.config.provider_artifact_digest,
                    )
                    .expect("process lease");
                let adapter = SurrealStoreAdapter::new_with_client_set(
                    self.config.clone(),
                    lease,
                    genesis_manifest(),
                    limits,
                )
                .expect("adapter");
                match tokio::time::timeout_at(deadline, adapter.connect()).await {
                    Ok(Ok(())) => {
                        self.adapter = Some(adapter);
                        return;
                    }
                    Ok(Err(error)) => last_error = Some(error),
                    Err(_) => {
                        self.adapter = None;
                        panic!("provider readiness timed out; last error: {last_error:?}");
                    }
                }
                self.adapter = None;
                assert!(
                    Instant::now() < deadline,
                    "provider readiness timed out; last error: {last_error:?}"
                );
                sleep(
                    Duration::from_millis(100)
                        .min(deadline.saturating_duration_since(Instant::now())),
                )
                .await;
            }
        }

        fn transport(&self) -> &RpcTransport {
            self.adapter
                .as_ref()
                .expect("started adapter")
                .client
                .get()
                .expect("connected")
                .as_ref()
                .expect("transport")
        }

        async fn cleanup(mut self) {
            // Ownership discipline: every `SessionPool` clone and
            // `PooledSession` guard must be dropped by the test body BEFORE
            // this runs. A surviving clone keeps the provider owner alive,
            // and the owner holds the data-root lease and executable handles
            // open, which fails fixture deletion with a sharing violation.
            // Owned values drop at scope end (not at last use), so say the
            // drops explicitly at each call site.
            if let Some(adapter) = self.adapter.take()
                && let Some(Ok(transport)) = adapter.client.get()
            {
                let mut child = transport.provider.provider_child.lock().await;
                child.kill().await.expect("stop exact child");
                child.wait().await.expect("reap exact child");
            }
            remove_fixture(&self.root).await;
        }
    }

    async fn remove_fixture(root: &Path) {
        // Windows can keep an exiting image mapped briefly after its process
        // becomes unqueryable. A failed delete is not proof of resource release.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match std::fs::remove_dir_all(root) {
                Ok(()) => return,
                Err(error)
                    if matches!(error.raw_os_error(), Some(5 | 32))
                        && Instant::now() < deadline =>
                {
                    sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("isolated fixture cleanup failed: {error}"),
            }
        }
    }

    // WORK_UNIT_CASE: 987/1
    #[tokio::test]
    async fn transport_carries_the_configured_bounded_profile() {
        let mut h = PoolHarness::provision().await;
        let limits = ClientSetLimits::new(2, 2, 1).expect("valid limits");
        h.start(limits).await;
        let pool = h.transport().session_pool().clone();
        assert_eq!(pool.slot_count(SessionRole::Read), 2);
        assert_eq!(pool.slot_count(SessionRole::NormalWrite), 2);
        assert_eq!(pool.slot_count(SessionRole::HealthAdmin), 1);
        assert_eq!(pool.checked_out(SessionRole::Read), 0);
        // The facade session still connects against the same provider owner.
        let facade_owner = &h.transport().provider;
        assert!(Arc::ptr_eq(&pool.provider().clone(), facade_owner));
        // Release the owner before teardown (see `cleanup` discipline).
        drop(pool);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 987/2
    #[tokio::test]
    async fn independent_role_sessions_share_one_provider_generation() {
        let mut h = PoolHarness::provision().await;
        h.start(ClientSetLimits::new(2, 2, 1).expect("valid limits"))
            .await;
        let pool = h.transport().session_pool().clone();
        let read = pool.checkout(SessionRole::Read).await.expect("read lane");
        let write = pool
            .checkout(SessionRole::NormalWrite)
            .await
            .expect("write lane");
        let admin = pool
            .checkout(SessionRole::HealthAdmin)
            .await
            .expect("admin lane");
        assert_eq!(read.role(), SessionRole::Read);
        assert_eq!(write.role(), SessionRole::NormalWrite);
        assert_eq!(admin.role(), SessionRole::HealthAdmin);
        // All three lanes are live at once: no socket-level serialization
        // across independent sessions.
        let mut read_result = read
            .query(
                "proof.987.read",
                "RETURN $value;",
                Map::from_iter([("value".into(), Value::String("lane:read".into()))]),
            )
            .await
            .expect("read lane query");
        assert!(read_result.take_errors().is_empty());
        assert_eq!(
            read_result.take::<String>(0).expect("read value"),
            "lane:read"
        );
        let mut write_result = write
            .query(
                "proof.987.write",
                "RETURN $value;",
                Map::from_iter([("value".into(), Value::String("lane:write".into()))]),
            )
            .await
            .expect("write lane query");
        assert!(write_result.take_errors().is_empty());
        assert_eq!(
            write_result.take::<String>(0).expect("write value"),
            "lane:write"
        );
        let version = admin
            .request("proof.987.version", "version", Value::Array(Vec::new()))
            .await
            .expect("admin lane version");
        assert!(version.is_string() || version.is_object());
        // One provider generation behind every lane.
        let identity = pool.provider().provider_process_identity.clone();
        let observed = WindowsPlatform::new(h.root.clone())
            .expect("platform")
            .process_identity(identity.process_id)
            .expect("observed identity");
        assert_eq!(observed, identity);
        println!(
            "987/2 provider_process_id={} lanes=read+write+admin",
            identity.process_id
        );
        drop(read);
        drop(write);
        drop(admin);
        assert_eq!(pool.checked_out(SessionRole::Read), 0);
        assert_eq!(pool.checked_out(SessionRole::NormalWrite), 0);
        assert_eq!(pool.checked_out(SessionRole::HealthAdmin), 0);
        // Release the owner before teardown (see `cleanup` discipline).
        drop(pool);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 987/3
    #[tokio::test]
    async fn exhausted_role_refuses_deterministically_and_recycles_slots() {
        let mut h = PoolHarness::provision().await;
        h.start(ClientSetLimits::compatibility()).await;
        let pool = h.transport().session_pool().clone();
        let held = pool
            .checkout(SessionRole::Read)
            .await
            .expect("only read slot");
        assert_eq!(pool.checked_out(SessionRole::Read), 1);
        assert_eq!(pool.available(SessionRole::Read), 0);
        // Exhausted role refuses without waiting; other roles are unaffected.
        assert!(pool.try_checkout(SessionRole::Read).is_none());
        drop(held);
        assert_eq!(pool.checked_out(SessionRole::Read), 0);
        assert_eq!(pool.available(SessionRole::Read), 1);
        // The warmed slot is reused, not reconnected into a second process.
        let reused = pool.try_checkout(SessionRole::Read);
        assert!(reused.is_some());
        let before = pool.provider().provider_process_identity.clone();
        drop(reused);
        let after = pool.provider().provider_process_identity.clone();
        assert_eq!(before, after);
        // Release the owner before teardown (see `cleanup` discipline).
        drop(pool);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 987/4
    #[tokio::test]
    async fn role_lanes_are_independent_under_exhaustion() {
        let mut h = PoolHarness::provision().await;
        h.start(ClientSetLimits::compatibility()).await;
        let pool = h.transport().session_pool().clone();
        let held_read = pool.checkout(SessionRole::Read).await.expect("read slot");
        // A saturated read lane never blocks the write or admin lanes.
        let write = pool
            .checkout(SessionRole::NormalWrite)
            .await
            .expect("write lane");
        let admin = pool
            .checkout(SessionRole::HealthAdmin)
            .await
            .expect("admin lane");
        assert!(pool.try_checkout(SessionRole::Read).is_none());
        assert!(pool.try_checkout(SessionRole::NormalWrite).is_none());
        assert!(pool.try_checkout(SessionRole::HealthAdmin).is_none());
        drop(held_read);
        drop(write);
        drop(admin);
        // Staged dispatch entrypoints reach their lanes. The write-lane call
        // below proves lane dispatch only; canonical-write concurrency stays
        // closed until the transaction (#989) and runtime (#993) children.
        let mut dispatched = h
            .transport()
            .query_write(
                "proof.987.write_dispatch",
                "RETURN $value;",
                Map::from_iter([("value".into(), Value::String("write-lane".into()))]),
            )
            .await
            .expect("write lane dispatch");
        assert!(dispatched.take_errors().is_empty());
        assert_eq!(dispatched.take::<String>(0).expect("value"), "write-lane");
        let mut probed = h
            .transport()
            .query_admin(
                "proof.987.admin_dispatch",
                "RETURN $value;",
                Map::from_iter([("value".into(), Value::String("admin-lane".into()))]),
            )
            .await
            .expect("admin lane dispatch");
        assert!(probed.take_errors().is_empty());
        assert_eq!(probed.take::<String>(0).expect("value"), "admin-lane");
        // Release the owner before teardown (see `cleanup` discipline).
        drop(pool);
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 987/5
    #[tokio::test]
    async fn pre_pool_facade_dispatch_is_preserved() {
        let mut h = PoolHarness::provision().await;
        h.start(ClientSetLimits::compatibility()).await;
        // The original single-session facade still dispatches named reads.
        let mut response = super::super::query(
            h.transport(),
            &h.config,
            "proof.987.facade",
            "RETURN $value;",
            Map::from_iter([("value".into(), Value::String("facade".into()))]),
        )
        .await
        .expect("facade query");
        assert!(response.take_errors().is_empty());
        assert_eq!(response.take::<String>(0).expect("value"), "facade");
        // New role dispatch reaches the same provider through pooled lanes.
        let mut pooled = h
            .transport()
            .query_read(
                "proof.987.pooled",
                "RETURN $value;",
                Map::from_iter([("value".into(), Value::String("pooled".into()))]),
            )
            .await
            .expect("pooled read");
        assert!(pooled.take_errors().is_empty());
        assert_eq!(pooled.take::<String>(0).expect("value"), "pooled");
        // Pool diagnostics never carry credentials.
        let rendered = format!("{:?} {:?}", h.transport(), h.transport().session_pool());
        assert!(!rendered.contains(h.config.password.expose_secret()));
        h.cleanup().await;
    }

    // WORK_UNIT_CASE: 987/6
    #[test]
    fn compatibility_profile_is_a_const_bounded_default() {
        const COMPAT: ClientSetLimits = ClientSetLimits::compatibility();
        assert_eq!(COMPAT.total_sessions(), 3);
        assert_eq!(COMPAT, ClientSetLimits::new(1, 1, 1).expect("compat"));
    }

    #[test]
    fn roles_have_stable_names_and_indexes() {
        assert_eq!(SessionRole::Read.as_str(), "read");
        assert_eq!(SessionRole::NormalWrite.as_str(), "normal_write");
        assert_eq!(SessionRole::HealthAdmin.as_str(), "health_admin");
        assert_eq!(SessionRole::Read.to_string(), "read");
        let all = SessionRole::ALL;
        assert_eq!(all.len(), 3);
        let mut indexes: Vec<usize> = all.iter().map(|role| role.index()).collect();
        indexes.sort_unstable();
        indexes.dedup();
        assert_eq!(indexes.len(), 3);
    }

    #[test]
    fn limits_reject_zero_and_overflow() {
        assert!(ClientSetLimits::new(0, 1, 1).is_err());
        assert!(ClientSetLimits::new(1, 0, 1).is_err());
        assert!(ClientSetLimits::new(1, 1, 0).is_err());
        assert!(ClientSetLimits::new(MAX_CLIENT_SET_SESSIONS_PER_ROLE + 1, 1, 1).is_err());
        assert!(ClientSetLimits::new(1, 1, MAX_CLIENT_SET_SESSIONS_PER_ROLE).is_ok());
        let full = ClientSetLimits::new(
            MAX_CLIENT_SET_SESSIONS_PER_ROLE,
            MAX_CLIENT_SET_SESSIONS_PER_ROLE,
            MAX_CLIENT_SET_SESSIONS_PER_ROLE,
        )
        .expect("max limits");
        assert_eq!(
            full.total_sessions(),
            u16::from(MAX_CLIENT_SET_SESSIONS_PER_ROLE) * 3
        );
    }

    #[test]
    fn compatibility_profile_separates_all_roles_minimally() {
        let profile = ClientSetLimits::compatibility();
        assert_eq!(profile.read_sessions, 1);
        assert_eq!(profile.write_sessions, 1);
        assert_eq!(profile.admin_sessions, 1);
        assert_eq!(profile.total_sessions(), 3);
    }
}
