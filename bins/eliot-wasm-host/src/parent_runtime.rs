//! Production parent-drive runtime assembly (issue #1955).
//!
//! Connects staged owner-admitted dispatch material to the injected WASM
//! runtime through live-constructed execution ports. Every input is
//! owner-issued or caller-provided: the material (owner-published bytes),
//! the governor ports (central-built from live Governor records — the typed
//! handoff this path consumes), the installed image (re-hashed real bytes),
//! and edge time (read once at composition, enforced against the owner
//! window by the contour and permit types). Nothing here mints authority,
//! issues caller-clock freshness, or fabricates receipts: the ephemeral
//! permit authority binds only the owner grant, and unbound inputs refuse
//! fail-closed before any spawn.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use eliot_process::{
    CancellationReceipt, EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError,
    Generation, ImageId, JobId, OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessIntent,
    ProcessStartReceipt, ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_process_executor::{wasm_p03_adapter::WasmP03ProcessAdapter, WindowsProcessExecutor};
use eliot_wasm_runtime::{
    AuthorityResolutionPort, EngineBinding, GovernorResolutionPort, P03ReceiptVerifierPort,
    PortError, ProcessBinding, ProcessLaunchEnvelope, PromotionVerificationPort, RuntimePorts,
    Sha256Digest, SourceVerificationPort, WasmRuntime,
};

use crate::child_engine::{IsolatedChildEngine, ISOLATED_CHILD_IMPLEMENTATION_ID};
use crate::contour::PINNED_WASMTIME_VERSION;
use crate::dispatch_drive::{
    drive_admission, guest_exec_argv, map_invocation_result, DispatchDriveResponse, DriveError,
};
use crate::dispatch_material::{
    ValidatedDispatchMaterial, WASM_HOST_GUEST_ARTIFACT_FILE_NAME, WASM_HOST_GUEST_INPUT_FILE_NAME,
};
use crate::installed_binary::{resolve_installed_binary, WasmHostBinaryBinding};
use crate::parent_authority::ParentDispatchAuthority;
use crate::typed_bindings::typed_wit_digest;
use crate::wasmtime_provider::provider_configuration_digest;

/// Central-built governor ports this drive consumes.
///
/// Constructed by the invocation owner from live Governor records (never
/// locally); the drive builds the process, receipt-verifier, and engine
/// slots itself from the admitted material because only the drive holds the
/// per-drive one-shot permit they must validate. Central MUST NOT depend on
/// its own process/engine slots being used on this path.
pub struct GovernorPorts {
    /// Manifest, generation, lease, revision, and limit resolution.
    pub governor: Box<dyn GovernorResolutionPort>,
    /// Owner, `WorkScope`, work-unit, and ceiling resolution.
    pub authority: Box<dyn AuthorityResolutionPort>,
    /// Independent source verification.
    pub source_verifier: Box<dyn SourceVerificationPort>,
    /// Conformance/shadow/canary/rollback verification.
    pub promotion_verifier: Box<dyn PromotionVerificationPort>,
}

/// Bounded production evidence sink: retains evidence up to the cap, then
/// fails closed (never drops retained evidence silently).
struct BoundedParentSink {
    retained: Mutex<Vec<ProcessEvidence>>,
}

impl BoundedParentSink {
    const CAP: usize = 1024;

    fn new() -> Self {
        Self {
            retained: Mutex::new(Vec::new()),
        }
    }
}

impl ProcessEvidenceSink for BoundedParentSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        let mut guard = self.retained.lock().map_err(|_| EvidenceSinkError {
            message: "parent sink lock poisoned".to_owned(),
        })?;
        if guard.len() >= Self::CAP {
            return Err(EvidenceSinkError {
                message: "parent sink at capacity".to_owned(),
            });
        }
        guard.push(evidence);
        Ok(())
    }
}

/// Narrow P-03 receipt verifier: re-proves binding/receipt/envelope
/// agreement on real records without minting proof. Start requires the
/// receipt to name the bound operation and digest plus the envelope
/// invocation; cancellation checks the same binding; reconciliation
/// requires a terminal lifecycle on the bound operation.
struct ParentReceiptVerifier;

impl P03ReceiptVerifierPort for ParentReceiptVerifier {
    fn verify_start(
        &mut self,
        binding: &ProcessBinding,
        receipt: &ProcessStartReceipt,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        if receipt.operation_id() != binding.operation_id()
            || receipt.request_digest() != binding.request_digest()
            || envelope.invocation_id.as_str() != binding.operation_id().as_str()
        {
            return Err(PortError::Denied);
        }
        Ok(())
    }

    fn verify_cancellation(
        &mut self,
        binding: &ProcessBinding,
        _receipt: &CancellationReceipt,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        if envelope.invocation_id.as_str() != binding.operation_id().as_str() {
            return Err(PortError::Denied);
        }
        Ok(())
    }

    fn verify_reconciliation(
        &mut self,
        binding: &ProcessBinding,
        evidence: &ProcessEvidence,
        envelope: &ProcessLaunchEnvelope,
    ) -> Result<(), PortError> {
        if envelope.invocation_id.as_str() != binding.operation_id().as_str() {
            return Err(PortError::Denied);
        }
        if !evidence.view().lifecycle().is_terminal() {
            return Err(PortError::UnknownOutcome);
        }
        Ok(())
    }
}

/// Derives the exact immutable `ProcessIntent` for the admitted child.
/// Every identity is admitted material; paths are the OS loader layout.
fn derive_parent_intent(
    material: &ValidatedDispatchMaterial,
    executable: &std::path::Path,
    host_digest: &Sha256Digest,
    working_directory: &std::path::Path,
) -> Result<ProcessIntent, DriveError> {
    let intent_field = |field: &'static str| DriveError::Intent { field };
    let executable_text = executable
        .to_str()
        .ok_or_else(|| intent_field("executable"))?;
    let working_text = working_directory
        .to_str()
        .ok_or_else(|| intent_field("working-directory"))?;
    let short = host_digest
        .as_str()
        .get(..16)
        .ok_or_else(|| intent_field("host-digest"))?;
    let environment =
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
            .map_err(|_| intent_field("environment"))?;
    let ceilings = &material.ceilings;
    let limits = ResourceLimits::new(
        ceilings.wall_deadline_ms,
        None,
        Some(ceilings.max_memory_bytes),
        ceilings.max_output_bytes,
        ceilings.max_output_bytes,
        1,
    )
    .map_err(|_| intent_field("limits"))?;
    let generation =
        Generation::new(material.generation).map_err(|_| intent_field("generation"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| intent_field("executable-dir"))?;
    let argv = guest_exec_argv(
        material.profile,
        &directory.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME),
        &directory.join(WASM_HOST_GUEST_INPUT_FILE_NAME),
        ceilings,
    );
    ProcessIntent::new(
        OperationId::new(material.operation_id.clone()).map_err(|_| intent_field("operation"))?,
        ProcessTreeId::new(material.work.work_scope.clone()).map_err(|_| intent_field("tree"))?,
        JobId::new(material.operation_id.clone()).map_err(|_| intent_field("job"))?,
        ImageId::new(format!("wasm-host-image-{short}")).map_err(|_| intent_field("image"))?,
        SessionId::new(material.claim_id.clone()).map_err(|_| intent_field("session"))?,
        generation,
        executable_text.to_owned(),
        host_digest.as_str().to_owned(),
        argv,
        working_text.to_owned(),
        environment,
        limits,
    )
    .map_err(|_| intent_field("intent"))
}

/// Drives one owner-admitted parent dispatch through a fully assembled
/// runtime to the canonical response.
///
/// Assembles the pure admission (`drive_admission`), the ephemeral permit
/// authority bound to the owner grant, the real executor/sink/adapter, the
/// seated child engine over re-hashed image bytes, and the complete port
/// set (central governor 4-tuple plus drive-built process, receipt
/// verifier, and engine). `now_ms` is composition-edge time, read once by
/// the caller. Any unbound input refuses before any spawn.
pub fn drive_parent_runtime(
    material: &ValidatedDispatchMaterial,
    governor: GovernorPorts,
    now_ms: u64,
) -> Result<DispatchDriveResponse, DriveError> {
    let (request, _admitted) = drive_admission(material)?;
    let grant = &material.grant;
    let epoch: eliot_contracts::EpochId = serde_json::from_str(&grant.authority_epoch_json)
        .map_err(|_| DriveError::Admission {
            field: "authority-epoch",
        })?;
    let executable =
        std::env::current_exe().map_err(|_| DriveError::Execution { stage: "locator" })?;
    let binding = WasmHostBinaryBinding::new(executable, material.host_artifact_digest.clone())
        .map_err(|_| DriveError::Admission {
            field: "image-binding",
        })?;
    let installed = resolve_installed_binary(&binding).map_err(|_| DriveError::Admission {
        field: "image-resolve",
    })?;
    let host_digest = installed.digest().clone();
    let executable_path = installed.path().to_path_buf();
    let working_directory = executable_path
        .parent()
        .ok_or(DriveError::Intent {
            field: "working-directory",
        })?
        .to_path_buf();
    let authority = ParentDispatchAuthority::activate(material, &epoch)?;
    let intent =
        derive_parent_intent(material, &executable_path, &host_digest, &working_directory)?;
    let issued = authority.issue_permit(&intent, now_ms)?;
    let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(authority)));
    let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(BoundedParentSink::new());
    let process = WasmP03ProcessAdapter::new(Arc::clone(&executor), Arc::clone(&sink));
    process
        .stage_admitted_request(issued)
        .map_err(|_| DriveError::Execution { stage: "stage" })?;
    let engine_binding = EngineBinding {
        implementation_id: ISOLATED_CHILD_IMPLEMENTATION_ID.to_owned(),
        exact_version: PINNED_WASMTIME_VERSION.to_owned(),
        engine_artifact_digest: host_digest.clone(),
        engine_configuration_digest: provider_configuration_digest(),
        wit_interface_digest: typed_wit_digest(),
    };
    let engine = IsolatedChildEngine::new(
        Arc::clone(&executor),
        Arc::clone(&sink),
        engine_binding,
        material.ceilings.artifact_digest.clone(),
        provider_configuration_digest(),
    );
    let ports = RuntimePorts::new(
        governor.governor,
        governor.authority,
        governor.source_verifier,
        governor.promotion_verifier,
        Box::new(process),
        Box::new(ParentReceiptVerifier),
        Box::new(engine),
    );
    let mut runtime = WasmRuntime::new(Some(ports));
    let result = runtime.execute(request);
    map_invocation_result(&result, material)
}
