//! Durable scheduling and lifecycle state for the instrument test daemon.
//!
//! The daemon deliberately keeps execution outside this crate.  It owns the
//! admission record, project-local ordering, leases, retry timing, and the
//! immutable transition journal.  A process adapter may therefore restart at
//! any point and recover exactly which work is safe to run next.

#![forbid(unsafe_code)]

use eliot_instrument_api::{
    ExecutionStatus, InstrumentInvocation, InstrumentKind, VerificationRun,
};
use eliot_process::ProcessRequest;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_jobs_v1");
const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_events_v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_meta_v1");

/// Persistent daemon failures.
#[derive(Debug, Error)]
pub enum TestdError {
    /// The supplied identity or policy value is invalid.
    #[error("invalid {field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    /// A job was submitted again with a different immutable payload.
    #[error("job {0} already exists with a different payload")]
    JobConflict(String),
    /// The requested state change is not valid for the current state.
    #[error("job {job_id} cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        job_id: String,
        from: JobState,
        to: JobState,
    },
    /// The lease is absent, expired, or belongs to another worker.
    #[error("lease rejected for job {0}")]
    LeaseRejected(String),
    /// The durable database could not complete an operation.
    #[error("database error: {0}")]
    Database(String),
    /// A persisted record was not decodable.
    #[error("corrupt persisted record: {0}")]
    Corrupt(String),
    /// A contract supplied by an instrument or process adapter is invalid.
    #[error("contract validation failed: {0}")]
    Contract(String),
    /// The durable plane only admits test profiles.
    #[error("testd accepts only TEST instrument invocations")]
    WrongInstrumentKind,
    /// The instrument request and process admission were not bound together.
    #[error("instrument and process admissions are not bound")]
    InvalidBinding,
}

fn database<E: std::fmt::Display>(error: E) -> TestdError {
    TestdError::Database(error.to_string())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), TestdError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(TestdError::Invalid {
            field,
            reason: "must be non-blank and control-free",
        });
    }
    Ok(())
}

/// Durable lifecycle of a scheduled test.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    RetryWait,
    Succeeded,
    Failed,
    Cancelled,
    Quarantined,
}

impl JobState {
    /// Whether no worker may claim this job again.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Quarantined
        )
    }
}

/// The serializable portion of a one-shot process admission.
///
/// `ProcessRequest` intentionally cannot be cloned or deserialized: its permit
/// is a consuming capability.  Testd persists this identity projection and
/// receives a freshly-issued request from Kernel for each physical attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessAdmission {
    /// Kernel process-job identity bound to the consuming permit.
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: u64,
    pub invocation_digest: String,
}

impl ProcessAdmission {
    fn from_request(request: &ProcessRequest) -> Self {
        Self {
            job_id: request.job_id().as_str().to_owned(),
            operation_id: request.operation_id().as_str().to_owned(),
            process_tree_id: request.process_tree_id().as_str().to_owned(),
            generation: request.generation().get(),
            authority_epoch: request.fence().authority_epoch(),
            invocation_digest: request.invocation_digest().to_owned(),
        }
    }
}

/// Canonical roots bound to one isolated execution job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRoots {
    /// Source/worktree root used as the process working directory.
    pub source_root: String,
    /// Dedicated external Cargo target/build root.
    pub target_root: String,
    /// Cache root; D0 requires this to be the same canonical root as target.
    pub cache_root: String,
}

impl TargetRoots {
    /// Creates and validates a path-identity projection.
    pub fn new(
        source_root: impl Into<String>,
        target_root: impl Into<String>,
        cache_root: impl Into<String>,
    ) -> Result<Self, TestdError> {
        let roots = Self {
            source_root: source_root.into(),
            target_root: target_root.into(),
            cache_root: cache_root.into(),
        };
        roots.validate()?;
        Ok(roots)
    }

    /// Revalidates immutable path identity before a later execution stage.
    pub fn validate(&self) -> Result<(), TestdError> {
        let source = validate_root_identity(&self.source_root, "source_root")?;
        let target = validate_root_identity(&self.target_root, "target_root")?;
        let cache = validate_root_identity(&self.cache_root, "cache_root")?;
        if cache != target {
            return Err(TestdError::Invalid {
                field: "cache_root",
                reason: "must equal the canonical target_root in the active profile",
            });
        }
        if paths_overlap(&source, &target) {
            return Err(TestdError::Invalid {
                field: "target_root",
                reason: "external target root must not contain or be contained by source_root",
            });
        }
        Ok(())
    }
}

/// A durable test job plus the process identity it must be re-issued for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestJob {
    /// Caller-owned idempotency key.
    pub job_id: String,
    /// Project-local FIFO ordering key.
    pub project_id: String,
    /// Monotonic sequence assigned by the durable store.
    pub project_sequence: u64,
    /// Instrument contract to execute.
    pub invocation: InstrumentInvocation,
    /// Identity projection of the consuming process contract.
    pub process: ProcessAdmission,
    /// Canonical roots retained for later execution/reconciliation checks.
    pub target_roots: TargetRoots,
    /// Scheduling priority; larger values run first among ready heads.
    pub priority: i32,
    /// Durable lifecycle state.
    pub state: JobState,
    /// Number of physical execution attempts.
    pub attempts: u32,
    /// Earliest time at which the job can be claimed.
    pub not_before_ms: u64,
    /// Worker lease, if the job is running.
    pub lease: Option<Lease>,
    /// Last execution projection, retained across restarts.
    pub execution: Option<ExecutionStatus>,
    /// Verifier output, when a verifier has completed.
    pub verification: Option<VerificationRun>,
    /// Exact receipt identity retained with a completed attempt.
    pub receipt: Option<ReceiptBinding>,
    /// Last durable mutation time.
    pub updated_at_ms: u64,
    /// Immutable digest of the submitted contracts and scheduling fields.
    pub payload_digest: String,
}

/// Contract spelling used by the test-execution-plane boundary.
pub type TestdJob = TestJob;
/// A worker fence is the durable lease for one physical attempt.
pub type Fence = Lease;

/// Fencing lease for one physical attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    /// Worker identity.
    pub owner: String,
    /// Random fence token.
    pub token: String,
    /// Monotonic attempt epoch.
    pub epoch: u64,
    /// Absolute expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

/// Exact identity tuple carried by a verifier receipt at finish.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBinding {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: u64,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
}

/// Append-only explanation for every durable lifecycle mutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobEvent {
    /// Job identity.
    pub job_id: String,
    /// Project sequence at the time of the event.
    pub project_sequence: u64,
    /// Event sequence within this job.
    pub sequence: u64,
    /// Previous state.
    pub from: Option<JobState>,
    /// New state.
    pub to: JobState,
    /// Worker or API actor causing the change.
    pub actor: String,
    /// Event timestamp.
    pub at_ms: u64,
    /// Optional machine-readable reason.
    pub reason: Option<String>,
}

/// A bounded retry policy. Delays are applied in order and then capped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Retry delays in milliseconds.
    pub delays_ms: Vec<u64>,
    /// Maximum number of physical attempts.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            delays_ms: vec![100, 250, 500, 1_000, 2_000, 5_000, 10_000],
            max_attempts: 8,
        }
    }
}

/// One durable test-daemon state owner.
pub struct TestdStore {
    database: Arc<Database>,
    retry: RetryPolicy,
}

impl TestdStore {
    /// Opens or creates the persistent state file and all schema tables.
    pub fn open(path: impl AsRef<Path>, retry: RetryPolicy) -> Result<Self, TestdError> {
        if retry.max_attempts == 0 || retry.delays_ms.is_empty() {
            return Err(TestdError::Invalid {
                field: "retry_policy",
                reason: "must have bounded attempts and delays",
            });
        }
        let db = Database::create(path).map_err(database)?;
        let write = db.begin_write().map_err(database)?;
        drop(write.open_table(JOBS).map_err(database)?);
        drop(write.open_table(EVENTS).map_err(database)?);
        drop(write.open_table(META).map_err(database)?);
        write.commit().map_err(database)?;
        Ok(Self {
            database: Arc::new(db),
            retry,
        })
    }

    /// Returns the durable record for a job.
    pub fn get(&self, job_id: &str) -> Result<Option<TestJob>, TestdError> {
        validate_text(job_id, "job_id")?;
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(JOBS).map_err(database)?;
        table
            .get(job_id)
            .map_err(database)?
            .map_or(Ok(None), |value| {
                serde_json::from_slice(value.value())
                    .map(Some)
                    .map_err(|error| TestdError::Corrupt(error.to_string()))
            })
    }

    /// Submits a job exactly once and assigns its project-local sequence.
    pub fn submit(
        &self,
        job_id: impl Into<String>,
        project_id: impl Into<String>,
        invocation: InstrumentInvocation,
        process: ProcessRequest,
        target_roots: TargetRoots,
        priority: i32,
        at_ms: u64,
    ) -> Result<TestJob, TestdError> {
        let job_id = job_id.into();
        let project_id = project_id.into();
        validate_text(&job_id, "job_id")?;
        validate_text(&project_id, "project_id")?;
        invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        process
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        if !matches!(invocation.kind, InstrumentKind::Test) {
            return Err(TestdError::WrongInstrumentKind);
        }
        if invocation.request.request_id.as_str() != process.operation_id().as_str() {
            return Err(TestdError::InvalidBinding);
        }
        target_roots.validate()?;
        let digest = payload_digest(&invocation, &process, &target_roots, priority)?;
        let process = ProcessAdmission::from_request(&process);
        let write = self.database.begin_write().map_err(database)?;
        let existing = {
            let table = write.open_table(JOBS).map_err(database)?;
            table
                .get(job_id.as_str())
                .map_err(database)?
                .map(|value| serde_json::from_slice::<TestJob>(value.value()))
        };
        if let Some(existing) = existing {
            let existing = existing.map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if existing.payload_digest != digest {
                return Err(TestdError::JobConflict(job_id));
            }
            return Ok(existing);
        }
        let sequence_key = format!("project:{project_id}");
        let sequence = {
            let mut meta = write.open_table(META).map_err(database)?;
            let previous = meta
                .get(sequence_key.as_str())
                .map_err(database)?
                .map_or(0, |value| {
                    serde_json::from_slice::<u64>(value.value()).unwrap_or(0)
                });
            let next = previous.saturating_add(1);
            let encoded = serde_json::to_vec(&next)
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            meta.insert(sequence_key.as_str(), encoded.as_slice())
                .map_err(database)?;
            next
        };
        let job = TestJob {
            job_id: job_id.clone(),
            project_id,
            project_sequence: sequence,
            invocation,
            process,
            target_roots,
            priority,
            state: JobState::Queued,
            attempts: 0,
            not_before_ms: at_ms,
            lease: None,
            execution: None,
            verification: None,
            receipt: None,
            updated_at_ms: at_ms,
            payload_digest: digest,
        };
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table
            .insert(job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(&write, &job, None, JobState::Queued, "submit", at_ms, None)?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Claims the oldest ready head of a project, with priority as a tie-breaker.
    pub fn claim_next(
        &self,
        owner: impl Into<String>,
        now: u64,
        lease_ms: u64,
    ) -> Result<Option<TestJob>, TestdError> {
        let owner = owner.into();
        validate_text(&owner, "owner")?;
        if lease_ms == 0 {
            return Err(TestdError::Invalid {
                field: "lease_ms",
                reason: "must be non-zero",
            });
        }
        let candidates = self.ready_heads(now)?;
        let Some(candidate) = candidates.into_iter().max_by(compare_ready) else {
            return Ok(None);
        };
        let mut job = candidate;
        let write = self.database.begin_write().map_err(database)?;
        let persisted = {
            let table = write.open_table(JOBS).map_err(database)?;
            let current = table
                .get(job.job_id.as_str())
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("claimed job disappeared".to_owned()))?;
            serde_json::from_slice::<TestJob>(current.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        job = persisted;
        job.target_roots.validate()?;
        if !matches!(job.state, JobState::Queued | JobState::RetryWait)
            || job.not_before_ms > now
            || job.lease.is_some()
        {
            return Ok(None);
        }
        let previous = job.state;
        job.state = JobState::Running;
        job.attempts = job.attempts.saturating_add(1);
        job.execution = Some(ExecutionStatus::Running);
        job.lease = Some(Lease {
            owner: owner.clone(),
            token: Uuid::new_v4().to_string(),
            epoch: u64::from(job.attempts),
            expires_at_ms: now.saturating_add(lease_ms),
        });
        job.updated_at_ms = now;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table
            .insert(job.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(previous),
            JobState::Running,
            &owner,
            now,
            None,
        )?;
        write.commit().map_err(database)?;
        Ok(Some(job))
    }

    /// Completes an attempt, or durably schedules a bounded retry.
    pub fn finish(
        &self,
        job_id: &str,
        lease: &Lease,
        execution: ExecutionStatus,
        verification: Option<VerificationRun>,
        receipt: &ReceiptBinding,
        now: u64,
        reason: Option<String>,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        if let Some(run) = &verification {
            run.validate()
                .map_err(|error| TestdError::Contract(error.to_string()))?;
        }
        let mut job = self
            .get(job_id)?
            .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
        if !lease_matches(&job, lease, now) {
            return Err(TestdError::LeaseRejected(job_id.to_owned()));
        }
        validate_receipt_binding(&job, receipt)?;
        if let Some(run) = &verification
            && run.invocation_id.as_str() != job.invocation.request.request_id.as_str()
        {
            return Err(TestdError::InvalidBinding);
        }
        let previous = job.state;
        job.execution = Some(execution);
        job.verification = verification;
        job.receipt = Some(receipt.clone());
        job.lease = None;
        let retryable = matches!(
            execution,
            ExecutionStatus::Unknown | ExecutionStatus::Failed
        );
        let terminal = if matches!(execution, ExecutionStatus::Succeeded) {
            JobState::Succeeded
        } else if retryable && job.attempts < self.retry.max_attempts {
            JobState::RetryWait
        } else if matches!(execution, ExecutionStatus::Cancelled) {
            JobState::Cancelled
        } else {
            JobState::Failed
        };
        job.state = terminal;
        job.not_before_ms = if terminal == JobState::RetryWait {
            now.saturating_add(
                self.retry.delays_ms
                    [(job.attempts.saturating_sub(1) as usize).min(self.retry.delays_ms.len() - 1)],
            )
        } else {
            now
        };
        job.updated_at_ms = now;
        let write = self.database.begin_write().map_err(database)?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        table
            .insert(job.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(previous),
            terminal,
            &lease.owner,
            now,
            reason,
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Cancels a queued or currently leased job using its current fence.
    pub fn cancel(
        &self,
        job_id: &str,
        lease: Option<&Lease>,
        actor: &str,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        let mut job = self
            .get(job_id)?
            .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
        if job.state.is_terminal() {
            return Ok(job);
        }
        validate_cancellation_lease(&job, lease, actor, now)?;
        validate_text(actor, "actor")?;
        let previous = job.state;
        job.state = JobState::Cancelled;
        job.lease = None;
        job.execution = Some(ExecutionStatus::Cancelled);
        job.updated_at_ms = now;
        let write = self.database.begin_write().map_err(database)?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        table
            .insert(job.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(previous),
            JobState::Cancelled,
            actor,
            now,
            Some("cancelled".to_owned()),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Reads the immutable transition history for one job.
    pub fn events(&self, job_id: &str) -> Result<Vec<JobEvent>, TestdError> {
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(EVENTS).map_err(database)?;
        let prefix = format!("{job_id}:");
        let mut events = Vec::new();
        for item in table.iter().map_err(database)? {
            let (key, value) = item.map_err(database)?;
            if key.value().starts_with(&prefix) {
                events.push(
                    serde_json::from_slice(value.value())
                        .map_err(|error| TestdError::Corrupt(error.to_string()))?,
                );
            }
        }
        events.sort_by_key(|event: &JobEvent| event.sequence);
        Ok(events)
    }

    fn ready_heads(&self, now: u64) -> Result<Vec<TestJob>, TestdError> {
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(JOBS).map_err(database)?;
        let mut jobs = Vec::new();
        for item in table.iter().map_err(database)? {
            let (_, value) = item.map_err(database)?;
            jobs.push(
                serde_json::from_slice::<TestJob>(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?,
            );
        }
        drop(table);
        jobs.retain(|job| {
            matches!(job.state, JobState::Queued | JobState::RetryWait)
                && job.not_before_ms <= now
                && job.lease.is_none()
        });
        let snapshot = jobs.clone();
        jobs.retain(|job| {
            !snapshot.iter().any(|other| {
                other.project_id == job.project_id
                    && other.project_sequence < job.project_sequence
                    && !other.state.is_terminal()
            })
        });
        Ok(jobs)
    }
}

fn payload_digest(
    invocation: &InstrumentInvocation,
    process: &ProcessRequest,
    target_roots: &TargetRoots,
    priority: i32,
) -> Result<String, TestdError> {
    let bytes = serde_json::to_vec(&(invocation, process, target_roots, priority))
        .map_err(|error| TestdError::Corrupt(error.to_string()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn validate_root_identity(value: &str, field: &'static str) -> Result<PathBuf, TestdError> {
    validate_text(value, field)?;
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(TestdError::Invalid {
            field,
            reason: "must be an absolute path",
        });
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(TestdError::Invalid {
            field,
            reason: "parent traversal is forbidden",
        });
    }
    reject_reparse_components(path, field)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| TestdError::Invalid {
        field,
        reason: "must identify an existing canonical root",
    })?;
    if !canonical.is_absolute() {
        return Err(TestdError::Invalid {
            field,
            reason: "must resolve to an absolute root",
        });
    }
    let metadata = std::fs::symlink_metadata(&canonical).map_err(|_| TestdError::Invalid {
        field,
        reason: "root metadata is unavailable",
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(TestdError::Invalid {
            field,
            reason: "must be a non-reparse directory",
        });
    }
    reject_reparse_components(&canonical, field)?;
    Ok(canonical)
}

fn reject_reparse_components(path: &Path, field: &'static str) -> Result<(), TestdError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(TestdError::Invalid {
                    field,
                    reason: "parent traversal is forbidden",
                });
            }
            Component::Normal(part) => {
                current.push(part);
                let metadata =
                    std::fs::symlink_metadata(&current).map_err(|_| TestdError::Invalid {
                        field,
                        reason: "root traversal contains an unavailable component",
                    })?;
                if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                    return Err(TestdError::Invalid {
                        field,
                        reason: "symlink or reparse traversal is forbidden",
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn validate_receipt_binding(job: &TestJob, receipt: &ReceiptBinding) -> Result<(), TestdError> {
    job.target_roots.validate()?;
    let matches = receipt.job_id == job.job_id
        && receipt.operation_id == job.process.operation_id
        && receipt.process_tree_id == job.process.process_tree_id
        && receipt.generation == job.process.generation
        && receipt.authority_epoch == job.process.authority_epoch
        && receipt_invocation_matches(receipt, job.invocation.request.request_id.as_str())
        && receipt.invocation_digest == job.process.invocation_digest
        && receipt.source_root == job.target_roots.source_root
        && receipt.target_root == job.target_roots.target_root
        && receipt.cache_root == job.target_roots.cache_root;
    if matches {
        Ok(())
    } else {
        Err(TestdError::InvalidBinding)
    }
}

fn receipt_invocation_matches(receipt: &ReceiptBinding, invocation_id: &str) -> bool {
    receipt.invocation_id == invocation_id
}

fn lease_matches(job: &TestJob, lease: &Lease, now: u64) -> bool {
    running_lease_matches(job.state, job.lease.as_ref(), lease, now)
}

fn running_lease_matches(
    state: JobState,
    current: Option<&Lease>,
    supplied: &Lease,
    now: u64,
) -> bool {
    current.is_some_and(|current| {
        current == supplied && current.expires_at_ms > now && state == JobState::Running
    })
}

/// Validates the exact current running fence before a consuming request may
/// start.  This is intentionally pure so protocol/composition callers cannot
/// accidentally replace it with a local lease check.
pub fn validate_running_lease(job: &TestJob, lease: &Lease, now: u64) -> Result<(), TestdError> {
    if lease_matches(job, lease, now) {
        Ok(())
    } else {
        Err(TestdError::LeaseRejected(job.job_id.clone()))
    }
}

fn validate_cancellation_lease(
    job: &TestJob,
    lease: Option<&Lease>,
    actor: &str,
    now: u64,
) -> Result<(), TestdError> {
    if !cancellation_lease_matches(job.state, job.lease.as_ref(), lease, actor, now) {
        return Err(TestdError::LeaseRejected(job.job_id.clone()));
    }
    Ok(())
}

fn cancellation_lease_matches(
    state: JobState,
    current: Option<&Lease>,
    supplied: Option<&Lease>,
    actor: &str,
    now: u64,
) -> bool {
    match state {
        JobState::Running => supplied.is_some_and(|lease| {
            running_lease_matches(state, current, lease, now) && actor == lease.owner
        }),
        _ => supplied.is_none_or(|lease| running_lease_matches(state, current, lease, now)),
    }
}

fn compare_ready(left: &TestJob, right: &TestJob) -> Ordering {
    left.priority
        .cmp(&right.priority)
        .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
        .then_with(|| right.project_sequence.cmp(&left.project_sequence))
        .then_with(|| right.job_id.cmp(&left.job_id))
}

fn append_event(
    write: &redb::WriteTransaction,
    job: &TestJob,
    from: Option<JobState>,
    to: JobState,
    actor: &str,
    at_ms: u64,
    reason: Option<String>,
) -> Result<(), TestdError> {
    let prefix = format!("{}:", job.job_id);
    let sequence = {
        let table = write.open_table(EVENTS).map_err(database)?;
        let mut highest = 0_u64;
        for item in table.iter().map_err(database)? {
            let (key, _) = item.map_err(database)?;
            if let Some(value) = key.value().strip_prefix(&prefix) {
                highest = highest.max(value.parse::<u64>().unwrap_or(0));
            }
        }
        highest.saturating_add(1)
    };
    let event = JobEvent {
        job_id: job.job_id.clone(),
        project_sequence: job.project_sequence,
        sequence,
        from,
        to,
        actor: actor.to_owned(),
        at_ms,
        reason,
    };
    let encoded =
        serde_json::to_vec(&event).map_err(|error| TestdError::Corrupt(error.to_string()))?;
    let key = format!("{}:{:020}", job.job_id, sequence);
    let mut table = write.open_table(EVENTS).map_err(database)?;
    table
        .insert(key.as_str(), encoded.as_slice())
        .map_err(database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> Lease {
        Lease {
            owner: "worker-a".to_owned(),
            token: "fence-a".to_owned(),
            epoch: 3,
            expires_at_ms: 200,
        }
    }

    #[test]
    fn running_cancel_without_exact_fence_is_rejected() {
        let current = lease();
        assert!(!cancellation_lease_matches(
            JobState::Running,
            Some(&current),
            None,
            "worker-a",
            100,
        ));
        assert!(!cancellation_lease_matches(
            JobState::Running,
            Some(&current),
            Some(&current),
            "other-worker",
            100,
        ));
        assert!(!cancellation_lease_matches(
            JobState::Running,
            Some(&current),
            Some(&current),
            "worker-a",
            200,
        ));
    }

    #[test]
    fn receipt_invocation_identity_cannot_be_substituted() {
        let receipt = ReceiptBinding {
            job_id: "job".to_owned(),
            operation_id: "operation".to_owned(),
            process_tree_id: "tree".to_owned(),
            generation: 1,
            authority_epoch: 1,
            invocation_id: "invocation-a".to_owned(),
            invocation_digest: "digest".to_owned(),
            source_root: "source".to_owned(),
            target_root: "target".to_owned(),
            cache_root: "target".to_owned(),
        };
        assert!(receipt_invocation_matches(&receipt, "invocation-a"));
        assert!(!receipt_invocation_matches(&receipt, "invocation-b"));
    }
}
