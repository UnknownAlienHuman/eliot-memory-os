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
use std::path::Path;
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
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub invocation_digest: String,
}

impl ProcessAdmission {
    fn from_request(request: &ProcessRequest) -> Self {
        Self {
            operation_id: request.operation_id().as_str().to_owned(),
            process_tree_id: request.process_tree_id().as_str().to_owned(),
            generation: request.generation().get(),
            invocation_digest: request.invocation_digest().to_owned(),
        }
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
        let digest = payload_digest(&invocation, &process, priority)?;
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
            priority,
            state: JobState::Queued,
            attempts: 0,
            not_before_ms: at_ms,
            lease: None,
            execution: None,
            verification: None,
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
        let previous = job.state;
        job.execution = Some(execution);
        job.verification = verification;
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
        if let Some(lease) = lease {
            if !lease_matches(&job, lease, now) {
                return Err(TestdError::LeaseRejected(job_id.to_owned()));
            }
        }
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
    priority: i32,
) -> Result<String, TestdError> {
    let bytes = serde_json::to_vec(&(invocation, process, priority))
        .map_err(|error| TestdError::Corrupt(error.to_string()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn lease_matches(job: &TestJob, lease: &Lease, now: u64) -> bool {
    job.lease.as_ref().is_some_and(|current| {
        current == lease && current.expires_at_ms >= now && job.state == JobState::Running
    })
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
