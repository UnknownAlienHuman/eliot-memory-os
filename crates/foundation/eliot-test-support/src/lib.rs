//! Bounded test-only support for ELIOT contract and adapter tests.
//!
//! This crate deliberately contains no process, store, network, provider, or
//! authority implementation.  It supplies deterministic in-memory fixtures
//! and a recoverable temporary-root guard for tests.  Production crates must
//! not depend on it; this boundary is also declared in package metadata as
//! `test_only = true` and `authority = false`.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use eliot_contracts::{
    AuthorityEpoch, ClockReading, ProductId, RequestId, RequestMetadata, ResourceGeneration,
    SourceId, StateFence, TransactionSequence,
};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Compile-time marker used by integration tests to document the boundary.
pub const TEST_SUPPORT_ONLY: bool = true;
/// This crate never carries product authority.
pub const HAS_AUTHORITY: bool = false;

/// Deterministic, monotonic clock for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeClock {
    now_ms: i64,
    step_ms: i64,
}

impl FakeClock {
    /// Creates a clock at `now_ms` with a zero default step.
    pub const fn new(now_ms: i64) -> Self {
        Self { now_ms, step_ms: 0 }
    }

    /// Creates a clock whose `tick` advances by `step_ms`.
    pub const fn with_step(now_ms: i64, step_ms: i64) -> Self {
        Self { now_ms, step_ms }
    }

    /// Reads the current deterministic time without advancing it.
    pub const fn now_ms(self) -> i64 {
        self.now_ms
    }

    /// Returns the configured tick size.
    pub const fn step_ms(self) -> i64 {
        self.step_ms
    }

    /// Changes the tick size.
    pub fn set_step(&mut self, step_ms: i64) {
        self.step_ms = step_ms;
    }

    /// Advances by `delta_ms`, returning an error on integer overflow.
    pub fn advance(&mut self, delta_ms: i64) -> Result<i64, ClockError> {
        self.now_ms = self
            .now_ms
            .checked_add(delta_ms)
            .ok_or(ClockError::Overflow)?;
        Ok(self.now_ms)
    }

    /// Advances by the configured step and returns the new time.
    pub fn tick(&mut self) -> Result<i64, ClockError> {
        self.advance(self.step_ms)
    }

    /// Converts this reading into the shared contract clock shape.
    pub const fn reading(self) -> ClockReading {
        ClockReading {
            valid_time_ms: Some(self.now_ms),
            known_time_ms: Some(self.now_ms),
            transaction_sequence: Some(TransactionSequence::genesis()),
            monotonic_ns: None,
        }
    }
}

/// Failure returned when a fake clock would overflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ClockError {
    /// The requested advance is outside the representable range.
    #[error("fake clock advance overflowed")]
    Overflow,
}

/// Deterministic identifier factory for contract fixtures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeterministicIds {
    prefix: String,
    next: u64,
}

impl DeterministicIds {
    /// Creates a factory with a validated, stable prefix.
    pub fn new(prefix: impl Into<String>) -> Result<Self, IdError> {
        let prefix = prefix.into();
        if prefix.trim().is_empty() || prefix.chars().any(char::is_control) {
            return Err(IdError::InvalidPrefix);
        }
        Ok(Self { prefix, next: 1 })
    }

    /// Returns the next raw deterministic identifier text.
    pub fn next_text(&mut self) -> Result<String, IdError> {
        let sequence = self.next;
        self.next = self.next.checked_add(1).ok_or(IdError::Exhausted)?;
        Ok(format!("{}-{sequence}", self.prefix))
    }

    /// Returns the next request identifier.
    pub fn request_id(&mut self) -> Result<RequestId, IdError> {
        self.next_text()
            .and_then(|v| RequestId::new(v).map_err(IdError::Contract))
    }
    /// Returns the next product identifier.
    pub fn product_id(&mut self) -> Result<ProductId, IdError> {
        self.next_text()
            .and_then(|v| ProductId::new(v).map_err(IdError::Contract))
    }
    /// Returns the next source identifier.
    pub fn source_id(&mut self) -> Result<SourceId, IdError> {
        self.next_text()
            .and_then(|v| SourceId::new(v).map_err(IdError::Contract))
    }

    /// Returns the next sequence number without exposing mutable global state.
    pub const fn next_value(&self) -> u64 {
        self.next
    }
}

/// Error returned by deterministic identifier generation.
#[derive(Debug, Error)]
pub enum IdError {
    /// Prefix contains no usable identifier text.
    #[error("deterministic id prefix is blank or contains a control character")]
    InvalidPrefix,
    /// The finite counter cannot advance further.
    #[error("deterministic id sequence exhausted")]
    Exhausted,
    /// Shared contract validation rejected generated text.
    #[error(transparent)]
    Contract(#[from] eliot_contracts::ContractError),
}

/// A valid request fixture composed only from C0-01 primitives.
pub fn valid_request_fixture(
    ids: &mut DeterministicIds,
    clock: FakeClock,
) -> Result<RequestMetadata, FixtureError> {
    let request = RequestMetadata {
        request_id: ids.request_id()?,
        session_id: None,
        task_id: None,
        product_id: ids.product_id()?,
        source_id: ids.source_id()?,
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        clock: clock.reading(),
    };
    request.validate()?;
    Ok(request)
}

/// Serializes and deserializes a fixture, exercising its wire compatibility.
pub fn roundtrip<T>(value: &T) -> Result<T, FixtureError>
where
    T: Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_vec(value)?;
    Ok(serde_json::from_slice(&encoded)?)
}

/// Fixture construction or validation failure.
#[derive(Debug, Error)]
pub enum FixtureError {
    /// Identifier or shared-contract validation failed.
    #[error(transparent)]
    Contract(#[from] eliot_contracts::ContractError),
    /// JSON encoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Deterministic ID generation failed.
    #[error(transparent)]
    Id(#[from] IdError),
}

/// In-memory named failpoints.  No global or process state is touched.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Failpoints {
    enabled: BTreeMap<String, String>,
}

impl Failpoints {
    /// Enables a named failpoint with a stable diagnostic message.
    pub fn enable(
        &mut self,
        name: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<(), FailpointError> {
        let name = valid_name(name.into())?;
        self.enabled.insert(name, message.into());
        Ok(())
    }

    /// Disables a named failpoint; absence is harmless.
    pub fn disable(&mut self, name: &str) -> Result<(), FailpointError> {
        let name = valid_name(name.to_owned())?;
        self.enabled.remove(&name);
        Ok(())
    }

    /// Checks a failpoint and returns its typed failure when enabled.
    pub fn check(&self, name: &str) -> Result<(), FailpointError> {
        let name = valid_name(name.to_owned())?;
        match self.enabled.get(&name) {
            Some(message) => Err(FailpointError::Triggered {
                name,
                message: message.clone(),
            }),
            None => Ok(()),
        }
    }

    /// Reports whether a failpoint is enabled.
    pub fn is_enabled(&self, name: &str) -> Result<bool, FailpointError> {
        let name = valid_name(name.to_owned())?;
        Ok(self.enabled.contains_key(&name))
    }

    /// Returns the number of enabled failpoints.
    pub fn len(&self) -> usize {
        self.enabled.len()
    }

    /// Returns whether no failpoints are enabled.
    pub fn is_empty(&self) -> bool {
        self.enabled.is_empty()
    }
}

fn valid_name(name: String) -> Result<String, FailpointError> {
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        return Err(FailpointError::InvalidName);
    }
    Ok(name)
}

/// Typed failpoint failure.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum FailpointError {
    /// A name cannot be blank or contain control characters.
    #[error("failpoint name is blank or contains a control character")]
    InvalidName,
    /// The requested failpoint is enabled.
    #[error("failpoint {name} triggered: {message}")]
    Triggered { name: String, message: String },
}

/// A bounded fake process state machine; it never launches a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeProcess {
    id: String,
    state: ProcessState,
}

impl FakeProcess {
    /// Creates a non-running fake process.
    pub fn new(id: impl Into<String>) -> Result<Self, FakeProcessError> {
        let id = id.into();
        if id.trim().is_empty() || id.chars().any(char::is_control) {
            return Err(FakeProcessError::InvalidId);
        }
        Ok(Self {
            id,
            state: ProcessState::Created,
        })
    }

    /// Returns the fake process identity.
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the current fake state.
    pub const fn state(&self) -> ProcessState {
        self.state
    }
    /// Moves a created process to running.
    pub fn start(&mut self) -> Result<(), FakeProcessError> {
        if self.state != ProcessState::Created {
            return Err(FakeProcessError::InvalidTransition);
        }
        self.state = ProcessState::Running;
        Ok(())
    }
    /// Records an exit code without running external code.
    pub fn exit(&mut self, code: i32) -> Result<(), FakeProcessError> {
        if self.state != ProcessState::Running {
            return Err(FakeProcessError::InvalidTransition);
        }
        self.state = ProcessState::Exited(code);
        Ok(())
    }
    /// Records cancellation of a running fake process.
    pub fn cancel(&mut self) -> Result<(), FakeProcessError> {
        if self.state != ProcessState::Running {
            return Err(FakeProcessError::InvalidTransition);
        }
        self.state = ProcessState::Cancelled;
        Ok(())
    }
}

/// State of a fake process helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    Running,
    Exited(i32),
    Cancelled,
}

/// Error from the in-memory fake process state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FakeProcessError {
    /// The process identity is invalid.
    #[error("fake process id is blank or contains a control character")]
    InvalidId,
    /// The requested state transition is not admitted.
    #[error("invalid fake process state transition")]
    InvalidTransition,
}

/// In-memory store helper for tests; it performs no disk or database IO.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeStore<T> {
    records: BTreeMap<String, T>,
}

impl<T> FakeStore<T> {
    /// Creates an empty fake store.
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }
    /// Inserts or replaces a bounded in-memory record.
    pub fn put(&mut self, key: impl Into<String>, value: T) -> Result<Option<T>, FakeStoreError> {
        let key = valid_name(key.into()).map_err(|_| FakeStoreError::InvalidKey)?;
        if key.len() > 256 {
            return Err(FakeStoreError::KeyTooLong);
        }
        Ok(self.records.insert(key, value))
    }
    /// Reads a record by key without cloning it.
    pub fn get(&self, key: &str) -> Result<Option<&T>, FakeStoreError> {
        let key = valid_name(key.to_owned()).map_err(|_| FakeStoreError::InvalidKey)?;
        Ok(self.records.get(&key))
    }
    /// Removes a record by key.
    pub fn remove(&mut self, key: &str) -> Result<Option<T>, FakeStoreError> {
        let key = valid_name(key.to_owned()).map_err(|_| FakeStoreError::InvalidKey)?;
        Ok(self.records.remove(&key))
    }
    /// Returns the number of in-memory records.
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Returns whether the store has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Error from the in-memory fake store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FakeStoreError {
    /// A key is blank or contains control characters.
    #[error("fake store key is invalid")]
    InvalidKey,
    /// Keys are intentionally bounded to keep fixtures finite.
    #[error("fake store key exceeds the 256-byte bound")]
    KeyTooLong,
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const MAX_COMPONENT_LENGTH: usize = 64;

/// Recoverable, bounded temporary root for filesystem fixtures.
///
/// Only this explicitly test-facing guard performs filesystem operations.  It
/// creates one child under the host temp directory and never accepts path
/// separators or parent components from callers.
pub struct TempRoot {
    path: PathBuf,
    keep: bool,
}

impl TempRoot {
    /// Creates a unique directory under the platform temp directory.
    pub fn new(label: &str) -> Result<Self, TempRootError> {
        validate_component(label)?;
        let base = std::env::temp_dir();
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!("eliot-test-{label}-{sequence}"));
        fs::create_dir(&path)?;
        Ok(Self { path, keep: false })
    }

    /// Returns the root path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Resolves a safe immediate child path without creating it.
    pub fn child(&self, component: &str) -> Result<PathBuf, TempRootError> {
        validate_component(component)?;
        Ok(self.path.join(component))
    }

    /// Keeps the directory after drop and returns its path for recovery.
    pub fn retain(mut self) -> PathBuf {
        self.keep = true;
        self.path.clone()
    }
}

impl fmt::Debug for TempRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempRoot")
            .field("path", &self.path)
            .field("keep", &self.keep)
            .finish()
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn validate_component(component: &str) -> Result<(), TempRootError> {
    if component.is_empty()
        || component.len() > MAX_COMPONENT_LENGTH
        || component == "."
        || component == ".."
        || component.contains('/')
        || component.contains('\\')
        || component.chars().any(char::is_control)
    {
        return Err(TempRootError::UnsafeComponent);
    }
    Ok(())
}

/// Error from bounded temporary-root operations.
#[derive(Debug, Error)]
pub enum TempRootError {
    /// Caller supplied a path component outside the safe bounded grammar.
    #[error("temporary-root component is unsafe or exceeds its bound")]
    UnsafeComponent,
    /// Host temporary directory operation failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_and_ids_are_deterministic() -> Result<(), Box<dyn std::error::Error>> {
        let mut clock = FakeClock::with_step(100, 5);
        assert_eq!(clock.tick()?, 105);
        let mut ids = DeterministicIds::new("fixture")?;
        assert_eq!(ids.next_text()?, "fixture-1");
        assert_eq!(ids.request_id()?.as_str(), "fixture-2");
        Ok(())
    }

    #[test]
    fn valid_request_fixture_roundtrips() -> Result<(), Box<dyn std::error::Error>> {
        let mut ids = DeterministicIds::new("request")?;
        let request = valid_request_fixture(&mut ids, FakeClock::new(10))?;
        assert_eq!(roundtrip(&request)?, request);
        Ok(())
    }

    #[test]
    fn malformed_fixture_is_rejected_by_c0_contracts() {
        let malformed = serde_json::json!({
            "request_id": 7,
            "product_id": "p",
            "source_id": "s",
            "state_fence": {"authority_epoch": 1, "resource_generation": 1},
            "clock": {}
        });
        assert!(serde_json::from_value::<RequestMetadata>(malformed).is_err());
    }

    #[test]
    fn failpoints_are_local_and_typed() -> Result<(), Box<dyn std::error::Error>> {
        let mut points = Failpoints::default();
        points.enable("network", "offline")?;
        assert!(matches!(
            points.check("network"),
            Err(FailpointError::Triggered { .. })
        ));
        points.disable("network")?;
        assert!(points.check("network").is_ok());
        assert!(points.enable("bad\nname", "x").is_err());
        Ok(())
    }

    #[test]
    fn fake_process_and_store_never_cross_io_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let mut process = FakeProcess::new("proc-1")?;
        process.start()?;
        process.exit(0)?;
        assert_eq!(process.state(), ProcessState::Exited(0));
        let mut store = FakeStore::new();
        store.put("record", 7_u32)?;
        assert_eq!(store.get("record")?, Some(&7));
        assert_eq!(store.remove("record")?, Some(7));
        Ok(())
    }

    #[test]
    fn temp_root_rejects_escape_and_cleans_up() -> Result<(), Box<dyn std::error::Error>> {
        let path = {
            let root = TempRoot::new("fixture")?;
            assert!(root.child("..\\escape").is_err());
            assert!(root.child("nested/file").is_err());
            let path = root.path().to_path_buf();
            assert!(path.starts_with(std::env::temp_dir()));
            path
        };
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn production_boundary_is_explicitly_negative() {
        let boundary = std::hint::black_box((TEST_SUPPORT_ONLY, HAS_AUTHORITY));
        assert_eq!(boundary, (true, false));
    }
}
