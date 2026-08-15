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
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
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

/// Neutral request delivered to the injected Kernel/Governor admission port.
///
/// This is an inert description only. It contains no contour authority and
/// cannot be used to construct a process permit without the core sealing
/// boundary below.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelProcessAdmissionRequest {
    pub job_id: String,
    pub project_id: String,
    pub invocation: InstrumentInvocation,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
}

impl KernelProcessAdmissionRequest {
    fn validate(&self) -> Result<(), TestdError> {
        validate_text(&self.job_id, "job_id")?;
        validate_text(&self.project_id, "project_id")?;
        for (field, value) in [
            ("source_root", self.source_root.as_str()),
            ("target_root", self.target_root.as_str()),
            ("cache_root", self.cache_root.as_str()),
        ] {
            validate_text(value, field)?;
        }
        self.invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))
    }
}

/// Evidence returned by the Kernel/Governor admission provider.
///
/// The consuming [`ProcessRequest`] is already authenticated by Kernel. The
/// contour and grant identity remain inert provider evidence until this crate
/// privately seals them into [`ProcessAdmissionPermit`].
#[derive(Debug)]
pub struct KernelProcessAdmissionEvidence {
    pub process: ProcessRequest,
    pub contour_root: String,
    pub grant_id: String,
}

/// Public neutral seam for the external Kernel/Governor admission owner.
///
/// Implementations return the already-issued one-shot process request and
/// issuer-selected contour evidence. They never construct a Testd grant or
/// permit; [`issue_process_admission`] performs that private sealing step.
pub trait KernelProcessAdmissionProvider: Send + Sync {
    fn admit(
        &self,
        request: &KernelProcessAdmissionRequest,
    ) -> Result<KernelProcessAdmissionEvidence, TestdError>;
}

/// Seals one provider response into a consuming, non-serializable permit.
pub fn issue_process_admission(
    provider: &dyn KernelProcessAdmissionProvider,
    request: &KernelProcessAdmissionRequest,
) -> Result<ProcessAdmissionPermit, TestdError> {
    request.validate()?;
    let evidence = provider.admit(request)?;
    evidence
        .process
        .validate()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    if evidence.process.job_id().as_str() != request.job_id
        || evidence.process.operation_id().as_str()
            != request.invocation.request.request_id.as_str()
        || evidence.process.working_directory() != request.source_root
        || evidence
            .process
            .environment()
            .non_secret()
            .get("CARGO_TARGET_DIR")
            != Some(&request.target_root)
        || evidence
            .process
            .environment()
            .non_secret()
            .get("CARGO_HOME")
            != Some(&request.cache_root)
        || evidence.process.fence().authority_epoch()
            != request
                .invocation
                .request
                .state_fence
                .authority_epoch
                .value()
        || evidence.process.generation().get()
            != request
                .invocation
                .request
                .state_fence
                .resource_generation
                .value()
    {
        return Err(TestdError::InvalidBinding);
    }
    let grant = ExecutionContourGrant::issue(
        evidence.contour_root,
        request.job_id.clone(),
        request.invocation.request.request_id.as_str().to_owned(),
        &evidence.process,
        evidence.grant_id,
    )?;
    ProcessAdmissionPermit::issued(evidence.process, grant)
}

/// Governor/Kernel-issued external execution contour grant.
///
/// Fields are private and the grant is neither deserializable nor cloneable.
/// Only the injected issuer boundary can produce the consuming permit that
/// carries this grant with its one-shot [`ProcessRequest`].
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContourGrant {
    contour_root: String,
    job_id: String,
    invocation_id: String,
    operation_id: String,
    process_tree_id: String,
    authority_epoch: u64,
    resource_generation: u64,
    grant_id: String,
    grant_digest: String,
}

impl ExecutionContourGrant {
    /// Constructs a grant inside the trusted issuer boundary.
    ///
    /// The N4 Kernel/Governor adapter is the only caller. Keeping this seam
    /// crate-private prevents a deserialized or ordinary caller-owned value
    /// from minting execution authority.
    #[allow(dead_code)]
    pub(crate) fn issue(
        contour_root: impl Into<String>,
        job_id: impl Into<String>,
        invocation_id: impl Into<String>,
        process: &ProcessRequest,
        grant_id: impl Into<String>,
    ) -> Result<Self, TestdError> {
        let grant = Self {
            contour_root: contour_root.into(),
            job_id: job_id.into(),
            invocation_id: invocation_id.into(),
            operation_id: process.operation_id().as_str().to_owned(),
            process_tree_id: process.process_tree_id().as_str().to_owned(),
            authority_epoch: process.fence().authority_epoch(),
            resource_generation: process.generation().get(),
            grant_id: grant_id.into(),
            grant_digest: String::new(),
        };
        grant.with_digest()
    }

    #[allow(dead_code)]
    fn with_digest(mut self) -> Result<Self, TestdError> {
        for (field, value) in [
            ("contour_root", self.contour_root.as_str()),
            ("job_id", self.job_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("operation_id", self.operation_id.as_str()),
            ("process_tree_id", self.process_tree_id.as_str()),
            ("grant_id", self.grant_id.as_str()),
        ] {
            validate_text(value, field)?;
        }
        self.grant_digest = contour_grant_digest(&self);
        Ok(self)
    }

    /// Returns the issuer-selected contour root; it grants no authority alone.
    pub fn contour_root(&self) -> &str {
        &self.contour_root
    }

    pub fn validate_for_process(
        &self,
        job_id: &str,
        invocation_id: &str,
        process: &ProcessRequest,
    ) -> Result<(), TestdError> {
        self.validate_integrity()?;
        if self.job_id != job_id
            || self.invocation_id != invocation_id
            || self.operation_id != process.operation_id().as_str()
            || self.process_tree_id != process.process_tree_id().as_str()
            || self.authority_epoch != process.fence().authority_epoch()
            || self.resource_generation != process.generation().get()
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    fn validate_integrity(&self) -> Result<(), TestdError> {
        for (field, value) in [
            ("contour_root", self.contour_root.as_str()),
            ("job_id", self.job_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("operation_id", self.operation_id.as_str()),
            ("process_tree_id", self.process_tree_id.as_str()),
            ("grant_id", self.grant_id.as_str()),
        ] {
            validate_text(value, field)?;
        }
        if self.grant_digest != contour_grant_digest(self) {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// One-shot Kernel process permit plus its immutable external-contour grant.
///
/// This type intentionally has no `Clone`, `Serialize`, or `Deserialize`
/// implementation. The issuer is the sole provenance boundary.
#[derive(Debug)]
pub struct ProcessAdmissionPermit {
    request: ProcessRequest,
    grant: ExecutionContourGrant,
}

impl ProcessAdmissionPermit {
    /// Seals the consuming request with the issuer's already-bound grant.
    ///
    /// This remains crate-private with the grant constructor so only the
    /// injected authority adapter can establish permit provenance.
    #[allow(dead_code)]
    pub(crate) fn issued(
        request: ProcessRequest,
        grant: ExecutionContourGrant,
    ) -> Result<Self, TestdError> {
        grant.validate_for_process(request.job_id().as_str(), &grant.invocation_id, &request)?;
        Ok(Self { request, grant })
    }

    /// Borrows the consuming request for pre-consumption validation only.
    pub fn request(&self) -> &ProcessRequest {
        &self.request
    }

    /// Borrows the issuer grant without exposing mutable construction.
    pub fn grant(&self) -> &ExecutionContourGrant {
        &self.grant
    }

    pub fn into_parts(self) -> (ProcessRequest, ExecutionContourGrant) {
        (self.request, self.grant)
    }
}

fn contour_grant_digest(grant: &ExecutionContourGrant) -> String {
    let bytes = serde_json::to_vec(&(
        &grant.contour_root,
        &grant.job_id,
        &grant.invocation_id,
        &grant.operation_id,
        &grant.process_tree_id,
        grant.authority_epoch,
        grant.resource_generation,
        &grant.grant_id,
    ))
    .unwrap_or_default();
    blake3::hash(&bytes).to_hex().to_string()
}

/// Canonical roots bound to one isolated execution job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRoots {
    /// Kernel/Governor-issued external execution contour.
    pub allowed_contour_root: String,
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
        allowed_contour_root: impl Into<String>,
        source_root: impl Into<String>,
        target_root: impl Into<String>,
        cache_root: impl Into<String>,
    ) -> Result<Self, TestdError> {
        let roots = Self {
            allowed_contour_root: allowed_contour_root.into(),
            source_root: source_root.into(),
            target_root: target_root.into(),
            cache_root: cache_root.into(),
        };
        roots.validate()?;
        Ok(roots)
    }

    /// Revalidates immutable path identity before a later execution stage.
    pub fn validate(&self) -> Result<(), TestdError> {
        let contour = validate_root_identity(&self.allowed_contour_root, "allowed_contour_root")?;
        let source = validate_root_identity(&self.source_root, "source_root")?;
        let target = validate_root_identity(&self.target_root, "target_root")?;
        let cache = validate_root_identity(&self.cache_root, "cache_root")?;
        if cache != target {
            return Err(TestdError::Invalid {
                field: "cache_root",
                reason: "must equal the canonical target_root in the active profile",
            });
        }
        if paths_overlap(&contour, &source) {
            return Err(TestdError::Invalid {
                field: "allowed_contour_root",
                reason: "external execution contour must not contain or be contained by source_root",
            });
        }
        if !is_strict_descendant(&target, &contour) {
            return Err(TestdError::Invalid {
                field: "target_root",
                reason: "must be a strict descendant of the allowed external execution contour",
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
    pub allowed_contour_root: String,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
}

/// A raw process artifact captured before any normalization.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawArtifact {
    pub handle: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
    pub length: u64,
    pub sha256: String,
    pub truncated: bool,
}

impl RawArtifact {
    /// Captures immutable bytes and computes a length-domain-separated digest.
    pub fn from_bytes(
        handle: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        truncated: bool,
    ) -> Result<Self, TestdError> {
        let length = bytes.len() as u64;
        let sha256 = sha256_artifact(length, &bytes);
        let artifact = Self {
            handle: handle.into(),
            content_type: content_type.into(),
            bytes,
            length,
            sha256,
            truncated,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Revalidates exact bytes, canonical length, and digest correspondence.
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.handle.trim().is_empty()
            || self.content_type.trim().is_empty()
            || self.handle.chars().any(char::is_control)
            || self.content_type.chars().any(char::is_control)
        {
            return Err(TestdError::Invalid {
                field: "raw_artifact",
                reason: "handle and content_type must be non-blank and control-free",
            });
        }
        if self.length != self.bytes.len() as u64
            || sha256_artifact(self.length, &self.bytes) != self.sha256
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// Observation-only normalized evidence bound to raw process handles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedEvidence {
    pub kind: String,
    pub summary: String,
    pub raw_handles: Vec<String>,
    pub execution: ExecutionStatus,
}

/// Candidate verification receipt accepted by the canonical finish boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: u64,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub allowed_contour_root: String,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
    pub execution: ExecutionStatus,
    pub raw_artifacts: Vec<RawArtifact>,
    pub normalized: Vec<NormalizedEvidence>,
}

impl VerificationReceipt {
    /// Returns the exact durable identity tuple after validation.
    pub fn binding(&self) -> ReceiptBinding {
        ReceiptBinding {
            job_id: self.job_id.clone(),
            operation_id: self.operation_id.clone(),
            process_tree_id: self.process_tree_id.clone(),
            generation: self.generation,
            authority_epoch: self.authority_epoch,
            invocation_id: self.invocation_id.clone(),
            invocation_digest: self.invocation_digest.clone(),
            allowed_contour_root: self.allowed_contour_root.clone(),
            source_root: self.source_root.clone(),
            target_root: self.target_root.clone(),
            cache_root: self.cache_root.clone(),
        }
    }

    /// Validates identity and exact raw-handle lineage before publication.
    pub fn validate(&self, job: &TestJob) -> Result<(), TestdError> {
        job.target_roots.validate()?;
        let binding = self.binding();
        validate_receipt_binding(job, &binding)?;
        let mut artifacts = BTreeMap::new();
        for artifact in &self.raw_artifacts {
            artifact.validate()?;
            if artifacts
                .insert(artifact.handle.clone(), artifact)
                .is_some()
            {
                return Err(TestdError::InvalidBinding);
            }
        }
        let mut referenced = BTreeSet::new();
        for evidence in &self.normalized {
            for handle in &evidence.raw_handles {
                if !referenced.insert(handle.clone()) || !artifacts.contains_key(handle) {
                    return Err(TestdError::InvalidBinding);
                }
            }
        }
        if artifacts.len() != referenced.len() {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// A bounded evidence sink for one testd operation.
#[derive(Clone, Default)]
pub struct EvidenceCollector {
    records: Arc<Mutex<Vec<eliot_process::ProcessEvidence>>>,
    raw_artifacts: Arc<Mutex<BTreeMap<String, RawArtifact>>>,
}

impl EvidenceCollector {
    /// Returns a stable snapshot for receipt composition.
    pub fn snapshot(&self) -> Vec<eliot_process::ProcessEvidence> {
        self.records
            .lock()
            .map_or_else(|_| Vec::new(), |items| items.clone())
    }

    /// Captures bytes before normalization; the digest is always over bytes.
    pub fn record_raw_artifact(
        &self,
        handle: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        truncated: bool,
    ) -> Result<(), TestdError> {
        let artifact = RawArtifact::from_bytes(handle, content_type, bytes, truncated)?;
        let mut artifacts = self
            .raw_artifacts
            .lock()
            .map_err(|_| TestdError::Contract("evidence collector lock poisoned".to_owned()))?;
        if let Some(existing) = artifacts.get(&artifact.handle) {
            if existing != &artifact {
                return Err(TestdError::InvalidBinding);
            }
        } else {
            artifacts.insert(artifact.handle.clone(), artifact);
        }
        Ok(())
    }

    /// Builds an observation-only receipt from captured process handles.
    pub fn verification_receipt(
        &self,
        job: &TestJob,
        execution: ExecutionStatus,
    ) -> VerificationReceipt {
        let records = self.snapshot();
        let raw = self
            .raw_artifacts
            .lock()
            .map_or_else(|_| BTreeMap::new(), |artifacts| artifacts.clone());
        let mut raw_artifacts = Vec::new();
        let mut handles = BTreeSet::new();
        for record in &records {
            for handle in [record.stdout_ref(), record.stderr_ref()]
                .into_iter()
                .flatten()
            {
                if handles.insert(handle.to_owned())
                    && let Some(artifact) = raw.get(handle)
                {
                    raw_artifacts.push(artifact.clone());
                }
            }
        }
        raw_artifacts.sort_by(|left, right| left.handle.cmp(&right.handle));
        let normalized = records
            .iter()
            .map(|record| NormalizedEvidence {
                kind: "process.observation".to_owned(),
                summary: format!("process lifecycle: {:?}", record.view().lifecycle()),
                raw_handles: [record.stdout_ref(), record.stderr_ref()]
                    .into_iter()
                    .flatten()
                    .map(str::to_owned)
                    .collect(),
                execution,
            })
            .collect();
        VerificationReceipt {
            job_id: job.job_id.clone(),
            operation_id: job.process.operation_id.clone(),
            process_tree_id: job.process.process_tree_id.clone(),
            generation: job.process.generation,
            authority_epoch: job.process.authority_epoch,
            invocation_id: job.invocation.request.request_id.as_str().to_owned(),
            invocation_digest: job.process.invocation_digest.clone(),
            allowed_contour_root: job.target_roots.allowed_contour_root.clone(),
            source_root: job.target_roots.source_root.clone(),
            target_root: job.target_roots.target_root.clone(),
            cache_root: job.target_roots.cache_root.clone(),
            execution,
            raw_artifacts,
            normalized,
        }
    }
}

impl eliot_process::ProcessEvidenceSink for EvidenceCollector {
    fn record(
        &self,
        evidence: eliot_process::ProcessEvidence,
    ) -> Result<(), eliot_process::EvidenceSinkError> {
        self.records
            .lock()
            .map_err(|_| eliot_process::EvidenceSinkError {
                message: "evidence collector lock poisoned".to_owned(),
            })
            .map(|mut records| records.push(evidence))
    }
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
        permit: ProcessAdmissionPermit,
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
        let (process, grant) = permit.into_parts();
        process
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        grant.validate_for_process(&job_id, invocation.request.request_id.as_str(), &process)?;
        if !matches!(invocation.kind, InstrumentKind::Test) {
            return Err(TestdError::WrongInstrumentKind);
        }
        if invocation.request.request_id.as_str() != process.operation_id().as_str() {
            return Err(TestdError::InvalidBinding);
        }
        if invocation.request.state_fence.authority_epoch.value()
            != process.fence().authority_epoch()
            || invocation.request.state_fence.resource_generation.value()
                != process.generation().get()
        {
            return Err(TestdError::InvalidBinding);
        }
        let mut target_roots = target_roots;
        target_roots.allowed_contour_root = grant.contour_root.clone();
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
        receipt: &VerificationReceipt,
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
        receipt.validate(&job)?;
        if receipt.execution != execution {
            return Err(TestdError::InvalidBinding);
        }
        let binding = receipt.binding();
        if let Some(run) = &verification
            && (run.invocation_id.as_str() != job.invocation.request.request_id.as_str()
                || run.state_fence != job.invocation.request.state_fence)
        {
            return Err(TestdError::InvalidBinding);
        }
        let previous = job.state;
        job.execution = Some(execution);
        job.verification = verification;
        job.receipt = Some(binding);
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

fn is_strict_descendant(path: &Path, parent: &Path) -> bool {
    if path == parent {
        return false;
    }
    #[cfg(windows)]
    {
        let path = path.to_string_lossy().replace('/', "\\");
        let parent = parent.to_string_lossy().replace('/', "\\");
        let path = path.trim_end_matches('\\').to_ascii_lowercase();
        let parent = parent.trim_end_matches('\\').to_ascii_lowercase();
        return path.starts_with(&format!("{parent}\\"));
    }
    #[cfg(not(windows))]
    {
        path.starts_with(parent)
    }
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
        && receipt.allowed_contour_root == job.target_roots.allowed_contour_root
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

/// Computes a lowercase SHA-256 digest over bytes only.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// Computes a length-domain-separated SHA-256 digest for one raw artifact.
///
/// The fixed-width big-endian length prefix makes the encoded tuple
/// unambiguous and prevents a detached length field from being accepted.
pub fn sha256_artifact(length: u64, bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest.finalize() {
        output.push_str(&format!("{byte:02x}"));
    }
    output
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
            allowed_contour_root: "contour".to_owned(),
            source_root: "source".to_owned(),
            target_root: "target".to_owned(),
            cache_root: "target".to_owned(),
        };
        assert!(receipt_invocation_matches(&receipt, "invocation-a"));
        assert!(!receipt_invocation_matches(&receipt, "invocation-b"));
    }

    #[test]
    fn forged_contour_cannot_widen_issuer_grant() {
        let mut grant = ExecutionContourGrant {
            contour_root: "C:\\approved-contour".to_owned(),
            job_id: "job".to_owned(),
            invocation_id: "invocation".to_owned(),
            operation_id: "operation".to_owned(),
            process_tree_id: "tree".to_owned(),
            authority_epoch: 7,
            resource_generation: 3,
            grant_id: "grant-1".to_owned(),
            grant_digest: String::new(),
        };
        grant.grant_digest = contour_grant_digest(&grant);
        grant.contour_root = "C:\\caller-widened-contour".to_owned();
        assert!(grant.validate_integrity().is_err());
    }
}
