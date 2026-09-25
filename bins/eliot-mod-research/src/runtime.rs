//! Production composition for one Kernel-presented research-provider attempt.
//!
//! The dispatch contour places a typed, session-bound material file beside the
//! executable. This root reads that fixed material path only; it never reads
//! caller arguments, stdin, environment variables, or an arbitrary executable
//! path. The material is validated against its Registry snapshot before the
//! in-process broker authority issues the one-shot process request.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    EnvironmentProjection, FencingToken, Generation, ImageId, JobId, KernelDispatchKey,
    OperationId, PermitIssuance, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
    SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_research_exchange::ExchangeError;
use eliot_research_exchange_api::{
    ResearchDispatchGrant, ResearchDispatchMaterial, ResearchEvidenceBundle,
    ResearchProtectedMaterial, ResearchProviderFailure, ResearchQueryRequest,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::admission::{BridgeContract, ProviderAdmission, ProviderRegistry};
use crate::evidence::{ProviderAttemptReceipt, ProviderIntentRecord, RawProviderEvidence};
use crate::execution::{ProviderBridge, ResearchRequestPort};
use crate::protocol::{PROVIDER_CHANNEL_ARGUMENT, ResearchRequestChannel, SubmitEnvelope};
use crate::{compose_admitted, submit};

/// Fixed dispatch material filename. It is not a command/path selector.
pub const ADMISSION_MATERIAL_FILE_NAME: &str = "eliot-mod-research.admitted-provider.json";
/// Fixed durable evidence filename emitted by this one-shot root.
pub const EVIDENCE_FILE_NAME: &str = "eliot-mod-research.provider-evidence.jsonl";
/// Fixed append-only operation/candidate/reconciliation journal.
pub const JOURNAL_FILE_NAME: &str = "eliot-mod-research.provider-journal.jsonl";
const MAX_MATERIAL_BYTES: u64 = 1024 * 1024;

/// The protected material type is owned by the shared exchange API. The alias
/// keeps the binary-facing name stable while making the Kernel claim shape
/// explicit at the composition boundary.
pub type AdmittedResearchMaterial = ResearchDispatchMaterial;
pub type ResearchLaunchGrant = ResearchDispatchGrant;

/// Resolves the shared Kernel material through the closed provider contract
/// and registry types. No local file is treated as authority by itself: the
/// claim, grant, request, and provider binding are all re-proved here.
pub fn resolve_material(
    material: &AdmittedResearchMaterial,
) -> Result<ProviderAdmission, RuntimeError> {
    material
        .validate(now_unix_ms())
        .map_err(|_| RuntimeError::InvalidMaterial("Kernel claim or launch grant is invalid"))?;
    let contract: BridgeContract = serde_json::from_value(material.claim.provider_contract.clone())
        .map_err(|_| RuntimeError::InvalidMaterial("provider contract is not typed JSON"))?;
    let registry: ProviderRegistry =
        serde_json::from_value(material.claim.provider_registry.clone())
            .map_err(|_| RuntimeError::InvalidMaterial("provider registry is not typed JSON"))?;
    let operation = OperationId::new(material.claim.operation_id.clone())
        .map_err(|_| RuntimeError::InvalidMaterial("Kernel operation identity is invalid"))?;
    let admission = ProviderAdmission::from_contract(contract, operation, &registry)
        .map_err(|_| RuntimeError::InvalidMaterial("contract did not resolve Registry evidence"))?;
    admission
        .validate_request(&material.claim.request)
        .map_err(|_| {
            RuntimeError::InvalidMaterial("request does not match the admitted contract")
        })?;
    if admission.bridge().executable() != material.claim.provider_executable
        || admission.bridge().executable_sha256() != material.claim.provider_executable_sha256
        || admission.epoch() != &material.claim.authority_epoch
        || admission.fence() != &material.claim.state_fence
        || admission.process_generation().get() != material.claim.process_generation
        || admission.cancellation().cancellation_id != material.claim.cancellation_id
        || material.claim.owner_principal_digest.trim().is_empty()
        || material.claim.session_id.trim().is_empty()
    {
        return Err(RuntimeError::InvalidMaterial(
            "Kernel claim is not bound to the provider contract, session, owner, and fence",
        ));
    }
    Ok(admission)
}

/// Runtime boundary failures. They never contain provider bytes or secrets.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("no admitted provider material is present: RESEARCH_SOURCE_UNAVAILABLE")]
    MaterialUnavailable,
    #[error("admitted provider material is invalid: {0}")]
    InvalidMaterial(&'static str),
    #[error("provider runtime is unavailable: {0}")]
    Unavailable(String),
    #[error("provider operation requires exact reconciliation")]
    ReconcileRequired,
    #[error("provider evidence could not be durably recorded: {0}")]
    Evidence(String),
    #[error("research provider degraded: {failure}")]
    Provider {
        failure: ResearchProviderFailure,
        receipt: Option<Box<ProviderAttemptReceipt>>,
    },
}

/// Fixed-path material reader. The path is derived only from `current_exe`.
pub fn read_admitted_material() -> Result<Option<AdmittedResearchMaterial>, RuntimeError> {
    let path = material_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(RuntimeError::Unavailable(format!("material read: {error}"))),
    };
    if bytes.len() as u64 > MAX_MATERIAL_BYTES {
        return Err(RuntimeError::InvalidMaterial(
            "material exceeds the bounded wire size",
        ));
    }
    let envelope: ResearchProtectedMaterial = serde_json::from_slice(&bytes)
        .map_err(|_| RuntimeError::InvalidMaterial("protected material is not exact typed JSON"))?;
    envelope
        .validate(now_unix_ms())
        .map_err(|_| RuntimeError::InvalidMaterial("protected material failed authenticated readback"))?;
    let material = envelope.material;
    let _ = resolve_material(&material)?;
    Ok(Some(material))
}

fn material_path() -> Result<PathBuf, RuntimeError> {
    let executable = std::env::current_exe()
        .map_err(|error| RuntimeError::Unavailable(format!("current executable: {error}")))?;
    let parent = executable.parent().ok_or(RuntimeError::Unavailable(
        "executable has no installation parent".to_owned(),
    ))?;
    Ok(parent.join(ADMISSION_MATERIAL_FILE_NAME))
}

fn evidence_path() -> Result<PathBuf, RuntimeError> {
    let executable = std::env::current_exe()
        .map_err(|error| RuntimeError::Unavailable(format!("current executable: {error}")))?;
    let parent = executable.parent().ok_or(RuntimeError::Unavailable(
        "executable has no installation parent".to_owned(),
    ))?;
    Ok(parent.join(EVIDENCE_FILE_NAME))
}

fn journal_path() -> Result<PathBuf, RuntimeError> {
    let executable = std::env::current_exe()
        .map_err(|error| RuntimeError::Unavailable(format!("current executable: {error}")))?;
    let parent = executable.parent().ok_or(RuntimeError::Unavailable(
        "executable has no installation parent".to_owned(),
    ))?;
    Ok(parent.join(JOURNAL_FILE_NAME))
}

/// Appends typed pre-start intent and process evidence to the fixed
/// installation-local evidence spool. The full stream handles remain in the
/// process evidence record; this adapter writes only typed custody records.
struct DurableEvidenceSink {
    path: PathBuf,
}

impl DurableEvidenceSink {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn append_json<T: Serialize>(&self, value: &T) -> Result<(), eliot_process::EvidenceSinkError> {
        let line = serde_json::to_vec(value).map_err(|error| eliot_process::EvidenceSinkError {
            message: format!("evidence serialization failed: {error}"),
        })?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| eliot_process::EvidenceSinkError {
                message: format!("evidence spool open failed: {error}"),
            })?;
        file.write_all(&line)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| eliot_process::EvidenceSinkError {
                message: format!("evidence spool write failed: {error}"),
            })
    }

    fn record_intent(
        &self,
        intent: &ProviderIntentRecord,
    ) -> Result<(), eliot_process::EvidenceSinkError> {
        self.append_json(intent)
    }
}

impl ProcessEvidenceSink for DurableEvidenceSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), eliot_process::EvidenceSinkError> {
        self.append_json(&evidence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DurablePhase {
    Reserved,
    Running,
    Completed,
    Failed,
    Cancelled,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableResearchRecord {
    operation_id: String,
    request_sha256: String,
    phase: DurablePhase,
    receipt: Option<ProviderAttemptReceipt>,
    candidate: Option<ResearchEvidenceBundle>,
    raw_evidence: Option<RawProviderEvidence>,
    failure: Option<ResearchProviderFailure>,
    process_error: Option<String>,
}

struct DurableResearchJournal {
    path: PathBuf,
}

impl DurableResearchJournal {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn append(&self, record: &DurableResearchRecord) -> Result<(), RuntimeError> {
        let line = serde_json::to_vec(record)
            .map_err(|error| RuntimeError::Evidence(error.to_string()))?;
        if line.len() > 2 * 1024 * 1024 {
            return Err(RuntimeError::Evidence(
                "durable research record exceeds its bound".to_owned(),
            ));
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| RuntimeError::Evidence(error.to_string()))?;
        file.write_all(&line)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| RuntimeError::Evidence(error.to_string()))
    }

    fn latest(&self, operation_id: &str) -> Result<Option<DurableResearchRecord>, RuntimeError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(RuntimeError::Evidence(error.to_string())),
        };
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(RuntimeError::Evidence(
                "durable research journal exceeds its bound".to_owned(),
            ));
        }
        let mut latest = None;
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let record: DurableResearchRecord = serde_json::from_slice(line)
                .map_err(|error| RuntimeError::Evidence(error.to_string()))?;
            if record.operation_id == operation_id {
                latest = Some(record);
            }
        }
        Ok(latest)
    }

    fn reserve(
        &self,
        material: &AdmittedResearchMaterial,
        request_sha256: &str,
    ) -> Result<Option<ProviderAttemptReceipt>, RuntimeError> {
        let operation_id = material.claim.operation_id.as_str();
        if let Some(existing) = self.latest(operation_id)? {
            if existing.request_sha256 != request_sha256 {
                return Err(RuntimeError::InvalidMaterial(
                    "durable operation identity is already bound to another request",
                ));
            }
            return match existing.phase {
                DurablePhase::Completed | DurablePhase::Failed | DurablePhase::Cancelled => {
                    Ok(existing.receipt)
                }
                DurablePhase::Reserved | DurablePhase::Running | DurablePhase::Unknown => {
                    Err(RuntimeError::ReconcileRequired)
                }
            };
        }
        self.append(&DurableResearchRecord {
            operation_id: operation_id.to_owned(),
            request_sha256: request_sha256.to_owned(),
            phase: DurablePhase::Reserved,
            receipt: None,
            candidate: None,
            raw_evidence: None,
            failure: None,
            process_error: None,
        })?;
        Ok(None)
    }

    fn finish(
        &self,
        operation_id: &str,
        request_sha256: &str,
        receipt: Option<ProviderAttemptReceipt>,
        candidate: Option<ResearchEvidenceBundle>,
        failure: Option<ResearchProviderFailure>,
        process_error: Option<String>,
    ) -> Result<(), RuntimeError> {
        let phase =
            receipt
                .as_ref()
                .map_or(DurablePhase::Failed, |receipt| match receipt.outcome {
                    crate::execution::ProviderOutcome::Completed => DurablePhase::Completed,
                    crate::execution::ProviderOutcome::Cancelled => DurablePhase::Cancelled,
                    crate::execution::ProviderOutcome::Unknown => DurablePhase::Unknown,
                    crate::execution::ProviderOutcome::Crashed
                    | crate::execution::ProviderOutcome::TimedOut => DurablePhase::Failed,
                });
        self.append(&DurableResearchRecord {
            operation_id: operation_id.to_owned(),
            request_sha256: request_sha256.to_owned(),
            phase,
            raw_evidence: receipt.as_ref().map(|value| value.raw_evidence.clone()),
            receipt,
            candidate,
            failure,
            process_error,
        })
    }
}

/// Child-side broker adapter for one Kernel-issued grant. It contains no
/// provider policy or independent authority; the permit is consumed only for
/// the exact claim-bound process intent.
pub struct ResearchDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl ResearchDispatchAuthority {
    /// Creates the child-side broker view from the signed Kernel authority
    /// projection. The private signing key is not present here; only the
    /// Kernel-authorized, operation-bound dispatch key is consumed.
    fn from_material(material: &AdmittedResearchMaterial) -> Result<Self, RuntimeError> {
        let authority_id = DispatchAuthorityId::new(material.authority.authority_id().to_owned())
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        let key_bytes = material
            .authority
            .key_bytes()
            .map_err(|_| RuntimeError::InvalidMaterial("Kernel authority signature is invalid"))?;
        let key = KernelDispatchKey::from_secret_bytes(key_bytes)
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    fn issue(
        &self,
        material: &AdmittedResearchMaterial,
        admission: &ProviderAdmission,
        envelope: &SubmitEnvelope,
        request: &ResearchQueryRequest,
        channel: &ResearchRequestChannel,
        now: u64,
    ) -> Result<ProcessRequest, RuntimeError> {
        if envelope.request_sha256 != channel.request_sha256()
            || envelope.budget_units != request.budget_units
            || envelope.deadline_unix_ms != request.deadline_ms
        {
            return Err(RuntimeError::InvalidMaterial(
                "request channel is not bound to the exact request terms",
            ));
        }
        let generation = Generation::new(admission.process_generation().get())
            .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?;
        let fence = FencingToken::new(
            material.grant.authority_epoch.clone(),
            generation,
            material.grant.fence_nonce.clone(),
        )
        .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?;
        let executable = admission.bridge().executable();
        let working_directory = PathBuf::from(&material.child_working_directory);
        let remaining = request
            .deadline_ms
            .saturating_sub(i64::try_from(now).unwrap_or(i64::MAX))
            .max(1);
        let limits = ResourceLimits::new(
            u64::try_from(remaining).unwrap_or(30_000),
            Some(10_000),
            Some(512_000_000),
            1024 * 1024,
            1024 * 1024,
            8,
        )
        .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?;
        let intent = ProcessIntent::new(
            admission.operation_id().clone(),
            ProcessTreeId::new(format!("tree-{}", admission.operation_id().as_str()))
                .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?,
            JobId::new(format!("job-{}", admission.operation_id().as_str()))
                .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?,
            ImageId::new(format!("image-{}", admission.bridge().executable_sha256()))
                .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?,
            SessionId::new(material.claim.session_id.clone())
                .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?,
            generation,
            executable,
            admission.bridge().executable_sha256(),
            vec![
                PROVIDER_CHANNEL_ARGUMENT.to_owned(),
                channel.token().to_owned(),
            ],
            working_directory.to_string_lossy().into_owned(),
            EnvironmentProjection::new(
                BTreeMap::new(),
                Vec::new(),
                eliot_process::EnvironmentInheritance::None,
            )
            .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?,
            limits,
        )
        .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?;
        let heads = BTreeMap::from([
            (
                "research-launch-grant".to_owned(),
                material.grant.grant_sha256.clone(),
            ),
            (
                "research-claim".to_owned(),
                material.claim.claim_sha256.clone(),
            ),
        ]);
        let issuance = PermitIssuance::new(
            ActionLeaseRef::new(material.grant.idempotency_key.clone())
                .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?,
            fence.clone(),
            heads.clone(),
            now.saturating_sub(1).max(1),
            material.grant.expires_at_unix_ms,
            material.grant.grant_sha256.clone(),
        )
        .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| RuntimeError::Unavailable("dispatch authority lock poisoned".to_owned()))?
            .issue(&intent, issuance)
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(now).unwrap_or(i64::MAX)),
                known_time_ms: Some(i64::try_from(now).unwrap_or(i64::MAX)),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            material.grant.authority_epoch.clone(),
            heads,
            1,
        )
        .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        *self.context.lock().map_err(|_| {
            RuntimeError::Unavailable("dispatch context lock poisoned".to_owned())
        })? = Some(context);
        ProcessRequest::new(intent, permit)
            .map_err(|error| RuntimeError::Unavailable(error.to_string()))
    }
}

impl DispatchValidationPort for ResearchDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let context = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("research context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("missing research validation context".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("research authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &context)
            .map_err(ProcessExecutionError::from)
    }
}

struct MaterialResearchRequestPort {
    material: AdmittedResearchMaterial,
    authority: Arc<ResearchDispatchAuthority>,
    sink: Arc<DurableEvidenceSink>,
}

impl ResearchRequestPort for MaterialResearchRequestPort {
    fn bind(
        &self,
        admission: &ProviderAdmission,
        envelope: &SubmitEnvelope,
        request: &ResearchQueryRequest,
        channel: &ResearchRequestChannel,
    ) -> Result<ProcessRequest, crate::RequestPortError> {
        if envelope.operation_id != admission.operation_id().as_str()
            || envelope.route_id != admission.route().route_id
            || envelope.request_sha256 != channel.request_sha256()
            || envelope.budget_units != request.budget_units
            || envelope.deadline_unix_ms != request.deadline_ms
        {
            return Err(crate::RequestPortError::WireDeliveryRefused);
        }
        let working_directory = Path::new(&self.material.child_working_directory);
        let request_path = working_directory.join(channel.request_file_name());
        let result_path = working_directory.join(channel.result_file_name());
        let mut request_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&request_path)
            .map_err(|_| crate::RequestPortError::EvidenceUnavailable)?;
        request_file
            .write_all(channel.request_bytes())
            .and_then(|()| request_file.sync_all())
            .map_err(|_| crate::RequestPortError::EvidenceUnavailable)?;
        if result_path.exists() {
            return Err(crate::RequestPortError::WireDeliveryRefused);
        }
        let intent = ProviderIntentRecord {
            operation_id: envelope.operation_id.clone(),
            wire_sha256: channel.request_sha256().to_owned(),
            artifact_sha256: admission.bridge().executable_sha256().to_owned(),
            config_digest: admission.config_digest().to_owned(),
            protocol_digest: admission.protocol_digest().to_owned(),
            registry_evidence_sha256: envelope.registry_evidence_sha256.clone(),
            module_id: admission.module_id().to_owned(),
            module_generation_id: admission.module_generation_id().to_owned(),
            route_id: envelope.route_id.clone(),
            provider_id: envelope.provider_id.clone(),
            bridge_generation: envelope.bridge_generation.clone(),
            protocol_revision: envelope.protocol_revision,
            required_schema: envelope.required_schema.clone(),
            disclosure: envelope.disclosure,
            data_class: envelope.data_class.clone(),
            credential_binding_id: envelope.credential_binding_id.clone(),
            credential_owner_principal: admission.credential_binding().owner_principal.clone(),
            credential_acting_principal: admission.credential_binding().acting_principal.clone(),
            process_generation: envelope.process_generation,
            state_fence: admission.fence().clone(),
            budget_units: envelope.budget_units,
            deadline_unix_ms: envelope.deadline_unix_ms,
            cancellation_id: envelope.cancellation_id.clone(),
            recorded_at_unix_ms: now_unix_ms(),
        };
        self.sink
            .record_intent(&intent)
            .map_err(|_| crate::RequestPortError::EvidenceUnavailable)?;
        self.authority
            .issue(
                &self.material,
                admission,
                envelope,
                request,
                channel,
                now_unix_ms().max(1),
            )
            .map_err(|_| crate::RequestPortError::Refused)
    }

    fn admitted_working_directory(
        &self,
        _admission: &ProviderAdmission,
    ) -> Result<PathBuf, crate::RequestPortError> {
        Ok(PathBuf::from(&self.material.child_working_directory))
    }

    fn admitted_fence_nonce(
        &self,
        _admission: &ProviderAdmission,
    ) -> Result<String, crate::RequestPortError> {
        Ok(self.material.grant.fence_nonce.clone())
    }
}

/// One-shot production entry. A missing material file is a typed unavailable
/// source; a present material file drives the real shared executor and the
/// same operation is never relaunched after a durable reservation.
pub fn run_once() -> Result<Option<ProviderAttemptReceipt>, RuntimeError> {
    let Some(material) = read_admitted_material()? else {
        return Err(RuntimeError::MaterialUnavailable);
    };
    let admission = resolve_material(&material)?;
    let request = material.claim.request.clone();
    let request_sha256 = material.claim.request_sha256.clone();
    let journal = DurableResearchJournal::new(journal_path()?);
    if let Some(receipt) = journal.reserve(&material, &request_sha256)? {
        return Ok(Some(receipt));
    }
    if journal.latest(&material.claim.operation_id)?.is_some() {
        return Err(RuntimeError::ReconcileRequired);
    }
    let sink = Arc::new(DurableEvidenceSink::new(evidence_path()?));
    let authority = Arc::new(ResearchDispatchAuthority::from_material(&material)?);
    let port = Arc::new(MaterialResearchRequestPort {
        material: material.clone(),
        authority: Arc::clone(&authority),
        sink: Arc::clone(&sink),
    });
    let executor = Arc::new(WindowsProcessExecutor::new(
        authority as Arc<dyn DispatchValidationPort>,
    ));
    let runner = ProviderBridge::new(executor, port, sink);
    let mut researcher = compose_admitted(runner, admission);
    let submit_result = submit(&mut researcher, request);
    let (bridge, snapshot) = researcher.into_exchange().into_parts();
    let receipt = bridge.last_receipt().cloned();
    let candidate = snapshot
        .jobs
        .get(&material.claim.operation_id)
        .and_then(|job| job.result.clone());
    let failure = bridge.last_failure();
    let process_error = match &submit_result {
        Ok(_) => None,
        Err(error) => Some(error.to_string()),
    };
    journal.finish(
        &material.claim.operation_id,
        &request_sha256,
        receipt.clone(),
        candidate,
        failure.clone(),
        process_error,
    )?;
    match submit_result {
        Ok(_) => Ok(receipt),
        Err(ExchangeError::Provider { failure, .. }) => Err(RuntimeError::Provider {
            failure,
            receipt: receipt.map(Box::new),
        }),
        Err(error) => Err(RuntimeError::Unavailable(error.to_string())),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
