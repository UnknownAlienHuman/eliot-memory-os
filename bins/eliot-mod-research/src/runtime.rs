//! Production composition for one Kernel-presented research-provider attempt.
//!
//! The dispatch contour places a typed, session-bound material file beside the
//! executable. This root reads that fixed material path only; it never reads
//! caller arguments, stdin, environment variables, or an arbitrary executable
//! path. The material is validated against its Registry snapshot before the
//! in-process broker authority issues the one-shot process request.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
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
use eliot_research_exchange_api::{ResearchProviderFailure, ResearchQueryRequest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::admission::{BridgeContract, ProviderAdmission, ProviderRegistry};
use crate::evidence::{ProviderAttemptReceipt, ProviderIntentRecord};
use crate::execution::{ProviderBridge, ResearchRequestPort};
use crate::protocol::{PROVIDER_WIRE_ARGUMENT, SubmitEnvelope};
use crate::{compose_admitted, submit};

/// Fixed dispatch material filename. It is not a command/path selector.
pub const ADMISSION_MATERIAL_FILE_NAME: &str = "eliot-mod-research.admitted-provider.json";
/// Fixed durable evidence filename emitted by this one-shot root.
pub const EVIDENCE_FILE_NAME: &str = "eliot-mod-research.provider-evidence.jsonl";
const MATERIAL_WIRE_VERSION: u16 = 1;
const MAX_MATERIAL_BYTES: u64 = 1024 * 1024;

/// Kernel-issued one-shot process grant carried beside the admitted contract.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchLaunchGrant {
    pub grant_digest: String,
    pub authority_epoch: eliot_contracts::EpochId,
    pub fence_generation: u64,
    pub fence_nonce: String,
    pub idempotency_key: String,
    pub expires_at_unix_ms: u64,
    pub operation_id: String,
}

/// Session-bound material delivered by the authenticated dispatch contour.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedResearchMaterial {
    pub wire_version: u16,
    pub contract: BridgeContract,
    pub registry: ProviderRegistry,
    pub request: ResearchQueryRequest,
    pub grant: ResearchLaunchGrant,
}

impl AdmittedResearchMaterial {
    /// Resolves the contract through the closed Registry snapshot and binds
    /// the exact operation identity carried by the cancellation contract.
    pub fn admission(&self) -> Result<ProviderAdmission, RuntimeError> {
        if self.wire_version != MATERIAL_WIRE_VERSION {
            return Err(RuntimeError::InvalidMaterial(
                "unsupported material wire version",
            ));
        }
        self.contract
            .validate()
            .map_err(|_| RuntimeError::InvalidMaterial("bridge contract is not closed"))?;
        let operation = OperationId::new(self.grant.operation_id.clone())
            .map_err(|_| RuntimeError::InvalidMaterial("grant operation identity is invalid"))?;
        let admission =
            ProviderAdmission::from_contract(self.contract.clone(), operation, &self.registry)
                .map_err(|_| {
                    RuntimeError::InvalidMaterial("contract did not resolve Registry evidence")
                })?;
        admission.validate_request(&self.request).map_err(|_| {
            RuntimeError::InvalidMaterial("request does not match the admitted contract")
        })?;
        if !crate::is_lowercase_sha256(&self.grant.grant_digest)
            || bounded_text(&self.grant.fence_nonce).is_err()
            || bounded_text(&self.grant.idempotency_key).is_err()
        {
            return Err(RuntimeError::InvalidMaterial(
                "launch grant identity is malformed",
            ));
        }
        if self.grant.authority_epoch != *admission.epoch()
            || self.grant.fence_generation != admission.fence().resource_generation.value()
            || self.grant.fence_nonce != admission.cancellation().cancellation_id
            || self.grant.idempotency_key != self.request.idempotency_key
            || self.grant.operation_id != admission.operation_id().as_str()
            || self.grant.expires_at_unix_ms <= now_unix_ms()
            || self.grant.expires_at_unix_ms
                > u64::try_from(admission.deadline_ms()).unwrap_or(u64::MAX)
        {
            return Err(RuntimeError::InvalidMaterial(
                "launch grant is stale or foreign",
            ));
        }
        Ok(admission)
    }
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
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(None);
    };
    if bytes.len() as u64 > MAX_MATERIAL_BYTES {
        return Err(RuntimeError::InvalidMaterial(
            "material exceeds the bounded wire size",
        ));
    }
    let material: AdmittedResearchMaterial = serde_json::from_slice(&bytes)
        .map_err(|_| RuntimeError::InvalidMaterial("material is not exact typed JSON"))?;
    let _ = material.admission()?;
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

/// Ephemeral broker authority for the single process request. The key is
/// generated in this process and never crosses the material or wire boundary.
pub struct ResearchDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl ResearchDispatchAuthority {
    fn new() -> Result<Self, RuntimeError> {
        let authority_id =
            DispatchAuthorityId::new(format!("research-dispatch-{}", std::process::id()))
                .map_err(|error| RuntimeError::Unavailable(error.to_string()))?;
        let nonce = Uuid::new_v4();
        let mut key_bytes = [0_u8; 32];
        key_bytes[..16].copy_from_slice(nonce.as_bytes());
        key_bytes[16..].copy_from_slice(&Sha256::digest(nonce.as_bytes())[..16]);
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
        wire_bytes: &[u8],
        now: u64,
    ) -> Result<ProcessRequest, RuntimeError> {
        let delivered: SubmitEnvelope = serde_json::from_slice(wire_bytes).map_err(|_| {
            RuntimeError::InvalidMaterial("wire bytes are not the admitted envelope")
        })?;
        if &delivered != envelope {
            return Err(RuntimeError::InvalidMaterial(
                "wire bytes do not match the admitted envelope",
            ));
        }
        let generation = Generation::new(admission.process_generation().get())
            .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?;
        let fence = FencingToken::new(
            admission.epoch().clone(),
            generation,
            material.grant.fence_nonce.clone(),
        )
        .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?;
        let executable = admission.bridge().executable();
        let working_directory = PathBuf::from(executable)
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let remaining = admission
            .deadline_ms()
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
            SessionId::new("session-research-provider")
                .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?,
            generation,
            executable,
            admission.bridge().executable_sha256(),
            vec![
                PROVIDER_WIRE_ARGUMENT.to_owned(),
                String::from_utf8_lossy(wire_bytes).into_owned(),
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
        let heads = BTreeMap::from([(
            "research-launch-grant".to_owned(),
            material.grant.grant_digest.clone(),
        )]);
        let issuance = PermitIssuance::new(
            ActionLeaseRef::new(material.grant.idempotency_key.clone())
                .map_err(|error| RuntimeError::InvalidMaterial(error.to_string().leak()))?,
            fence.clone(),
            heads.clone(),
            now.saturating_sub(1).max(1),
            material.grant.expires_at_unix_ms,
            material.grant.grant_digest.clone(),
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
            admission.epoch().clone(),
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
        wire_bytes: &[u8],
    ) -> Result<ProcessRequest, crate::RequestPortError> {
        if envelope.operation_id != admission.operation_id().as_str()
            || envelope.route_id != admission.route().route_id
        {
            return Err(crate::RequestPortError::WireDeliveryRefused);
        }
        let intent = ProviderIntentRecord {
            operation_id: envelope.operation_id.clone(),
            wire_sha256: crate::sha256_hex(wire_bytes),
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
                wire_bytes,
                now_unix_ms().max(1),
            )
            .map_err(|error| {
                let _ = error;
                crate::RequestPortError::Refused
            })
    }
}

/// One-shot production entry. A missing material file is a typed unavailable
/// source; a present material file drives the real shared executor.
pub fn run_once() -> Result<Option<ProviderAttemptReceipt>, RuntimeError> {
    let Some(material) = read_admitted_material()? else {
        return Err(RuntimeError::MaterialUnavailable);
    };
    let admission = material.admission()?;
    let sink = Arc::new(DurableEvidenceSink::new(evidence_path()?));
    let authority = Arc::new(ResearchDispatchAuthority::new()?);
    let port = Arc::new(MaterialResearchRequestPort {
        material: material.clone(),
        authority: Arc::clone(&authority),
        sink: Arc::clone(&sink),
    });
    let executor = Arc::new(WindowsProcessExecutor::new(authority));
    let runner = ProviderBridge::new(executor, port, sink);
    let mut researcher = compose_admitted(runner, admission);
    let request = material.request.clone();
    match submit(&mut researcher, request) {
        Ok(job) => {
            let (bridge, _) = researcher.into_exchange().into_parts();
            let _ = job;
            Ok(bridge.last_receipt().cloned())
        }
        Err(ExchangeError::Provider { failure, .. }) => {
            let (bridge, _) = researcher.into_exchange().into_parts();
            Err(RuntimeError::Provider {
                failure,
                receipt: bridge.last_receipt().cloned().map(Box::new),
            })
        }
        Err(error) => Err(RuntimeError::Unavailable(error.to_string())),
    }
}

fn bounded_text(value: &str) -> Result<(), &'static str> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err("grant text is blank or carries control characters")
    } else {
        Ok(())
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[allow(dead_code)]
fn _assert_no_direct_launch() {
    // The composition root owns no process constructor. The shared executor
    // type is the only process implementation in this crate's dependency path.
    let _ = std::any::TypeId::of::<WindowsProcessExecutor>();
}
