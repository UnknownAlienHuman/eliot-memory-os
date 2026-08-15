//! Composition root for the isolated ELIOT build/test execution plane.
//!
//! Testd accepts a declared profile and a Kernel-issued, one-shot process
//! request.  Durable scheduling is delegated to `eliot-testd-core`; physical
//! process semantics are delegated to the shared Windows ProcessExecutor.  No
//! task finish, budget, memory, or canonical-write authority exists here.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use eliot_instrument_api::{ExecutionStatus, InstrumentContractError, InstrumentInvocation};
use eliot_process::{
    ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessExecutor, ProcessRequest,
    ProcessStartReceipt,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_testd_core::{TestJob, TestdError, TestdStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Stable daemon service identity.
pub const SERVICE_NAME: &str = "eliot-testd";
/// Stable line-protocol revision.
pub const PROTOCOL_VERSION: &str = "eliot.testd.v2";
/// Maximum number of profiles retained by one external worker pool.
pub const MAX_PROFILE_ARGUMENTS: usize = 128;

/// Declared external roots owned by one isolated test job.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetContract {
    /// Source/worktree target, never interpreted as a shell command.
    pub target: String,
    /// Dedicated build output root.
    pub build_root: String,
    /// Dedicated dependency/cache root.
    pub cache_root: String,
    /// Process-tree identity assigned by the authority.
    pub process_tree_id: String,
}

impl TargetContract {
    /// Validates textual identity and rejects shared/current-directory roots.
    pub fn validate(&self) -> Result<(), TestdError> {
        for (field, value) in [
            ("target", self.target.as_str()),
            ("build_root", self.build_root.as_str()),
            ("cache_root", self.cache_root.as_str()),
            ("process_tree_id", self.process_tree_id.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be non-blank and control-free",
                });
            }
        }
        if self.build_root == self.cache_root || self.build_root == self.target {
            return Err(TestdError::Invalid {
                field: "build_root",
                reason: "must be an isolated external root",
            });
        }
        Ok(())
    }
}

/// Typed request accepted over the testd protocol.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestdJobRequest {
    pub job_id: String,
    pub project_id: String,
    pub invocation: InstrumentInvocation,
    pub target_contract: TargetContract,
    pub priority: i32,
}

/// Compatibility spelling for older protocol clients; it no longer contains
/// a private serialized process-request duplicate.
pub type TestRequest = TestdJobRequest;

/// A candidate receipt returned by testd after durable admission/observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TestReceipt {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub invocation_digest: String,
    pub state: String,
}

/// A raw process artifact handle retained before normalization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawArtifact {
    pub handle: String,
    pub content_type: String,
    pub sha256: String,
    pub truncated: bool,
}

/// Observation-only normalized evidence.  It cannot grant verifier or finish
/// authority and remains bound to one raw process handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedEvidence {
    pub kind: String,
    pub summary: String,
    pub raw_handles: Vec<String>,
    pub execution: ExecutionStatus,
}

/// Candidate verification receipt emitted for an owning verifier to assess.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub execution: ExecutionStatus,
    pub raw_artifacts: Vec<RawArtifact>,
    pub normalized: Vec<NormalizedEvidence>,
}

/// A bounded evidence sink for one testd operation.
#[derive(Clone, Default)]
pub struct EvidenceCollector {
    records: Arc<Mutex<Vec<ProcessEvidence>>>,
}

impl EvidenceCollector {
    /// Returns a stable snapshot for receipt composition.
    pub fn snapshot(&self) -> Vec<ProcessEvidence> {
        self.records
            .lock()
            .map_or_else(|_| Vec::new(), |items| items.clone())
    }

    /// Builds an observation-only receipt from captured process handles.
    pub fn verification_receipt(
        &self,
        job: &TestJob,
        execution: ExecutionStatus,
    ) -> VerificationReceipt {
        let records = self.snapshot();
        let mut raw_artifacts = Vec::new();
        let mut handles = Vec::new();
        for record in &records {
            for (kind, handle) in [
                ("stdout", record.stdout_ref()),
                ("stderr", record.stderr_ref()),
            ] {
                if let Some(handle) = handle {
                    if !handles.iter().any(|known| known == handle) {
                        handles.push(handle.to_owned());
                        raw_artifacts.push(RawArtifact {
                            handle: handle.to_owned(),
                            content_type: format!("application/x-eliot-process-{kind}"),
                            sha256: sha256_hex(handle.as_bytes()),
                            truncated: false,
                        });
                    }
                }
            }
        }
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
            execution,
            raw_artifacts,
            normalized,
        }
    }
}

impl ProcessEvidenceSink for EvidenceCollector {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), eliot_process::EvidenceSinkError> {
        self.records
            .lock()
            .map_err(|_| eliot_process::EvidenceSinkError {
                message: "evidence collector lock poisoned".to_owned(),
            })
            .map(|mut records| records.push(evidence))
    }
}

/// Supplies a fresh consuming process request for each physical attempt.
pub trait ProcessRequestIssuer: Send + Sync {
    fn issue(
        &self,
        invocation: &InstrumentInvocation,
        target: &TargetContract,
    ) -> Result<ProcessRequest, TestdError>;
}

/// Explicit failure issuer used by the standalone line protocol until Kernel
/// binds a live authority.  It prevents testd from minting local permits.
pub struct UnavailableProcessIssuer;

impl ProcessRequestIssuer for UnavailableProcessIssuer {
    fn issue(
        &self,
        _invocation: &InstrumentInvocation,
        _target: &TargetContract,
    ) -> Result<ProcessRequest, TestdError> {
        Err(TestdError::Contract(
            "Kernel-issued ProcessRequest is required".to_owned(),
        ))
    }
}

/// Composition root over the durable TestdJob store.
pub struct TestdComposition {
    store: TestdStore,
    issuer: Arc<dyn ProcessRequestIssuer>,
}

impl TestdComposition {
    /// Opens the local execution-plane state and binds a request issuer.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        issuer: Arc<dyn ProcessRequestIssuer>,
    ) -> Result<Self, TestdError> {
        Ok(Self {
            store: TestdStore::open(path, Default::default())?,
            issuer,
        })
    }

    /// Admits one exact typed profile through TestdJob/Fence admission.
    pub fn submit(&self, request: TestdJobRequest) -> Result<TestReceipt, TestdError> {
        request.target_contract.validate()?;
        request
            .invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        if request.invocation.arguments.len() > MAX_PROFILE_ARGUMENTS {
            return Err(TestdError::Invalid {
                field: "invocation.arguments",
                reason: "profile argument limit exceeded",
            });
        }
        let process = self
            .issuer
            .issue(&request.invocation, &request.target_contract)?;
        let job = self.store.submit(
            request.job_id,
            request.project_id,
            request.invocation,
            process,
            request.priority,
            unix_ms(),
        )?;
        Ok(receipt(&job))
    }

    /// Returns the durable status projection for one job.
    pub fn status(&self, job_id: &str) -> Result<TestReceipt, TestdError> {
        self.store
            .get(job_id)?
            .map(|job| receipt(&job))
            .ok_or_else(|| TestdError::Invalid {
                field: "job_id",
                reason: "unknown job",
            })
    }

    /// Cancels a queued or leased job under the durable store fence.
    pub fn cancel(&self, job_id: &str) -> Result<TestReceipt, TestdError> {
        let job = self.store.cancel(job_id, None, SERVICE_NAME, unix_ms())?;
        Ok(receipt(&job))
    }

    /// Starts one claimed stage through the shared ProcessExecutor.
    ///
    /// The request is intentionally supplied freshly by Kernel for this
    /// attempt; the durable TestdJob projection can never be substituted for
    /// its consuming permit.
    pub async fn start_claimed<E: ProcessExecutor + 'static>(
        &self,
        job: &TestJob,
        request: ProcessRequest,
        executor: &E,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, TestdError> {
        let operation_id = request.operation_id().clone();
        let process_tree_id = request.process_tree_id().as_str().to_owned();
        let generation = request.generation().get();
        let digest = request.invocation_digest().to_owned();
        if operation_id.as_str() != job.process.operation_id
            || process_tree_id != job.process.process_tree_id
            || generation != job.process.generation
            || digest != job.process.invocation_digest
        {
            return Err(TestdError::InvalidBinding);
        }
        executor
            .start(request, sink)
            .await
            .map_err(|error: ProcessExecutionError| TestdError::Contract(error.to_string()))
    }
}

/// Instantiates the sole concrete ProcessExecutor with an authority-owned
/// validation port.  Testd owns this instance's operation trees; Kernel owns
/// permit issuance and validation.
pub fn compose_process_executor(
    authority: Arc<dyn DispatchValidationPort>,
) -> WindowsProcessExecutor {
    WindowsProcessExecutor::new(authority)
}

fn receipt(job: &TestJob) -> TestReceipt {
    TestReceipt {
        job_id: job.job_id.clone(),
        operation_id: job.process.operation_id.clone(),
        process_tree_id: job.process.process_tree_id.clone(),
        generation: job.process.generation,
        invocation_digest: job.process.invocation_digest.clone(),
        state: format!("{:?}", job.state),
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        })
}

/// Stable content digest for a captured artifact handle payload.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Binary/protocol errors use the same typed TestdError surface.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("instrument contract: {0}")]
    Instrument(#[from] InstrumentContractError),
}
