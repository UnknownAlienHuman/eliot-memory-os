//! WASM parent P03 drive (issue #1955, I14.19).
//!
//! The dedicated executable consumer: from owner-published dispatch
//! material this process (the installed image, acting as the P03 parent)
//! derives its in-child authority, issues the one-shot permit for the
//! `--guest-exec` intent, stages/starts/reaps the reaped child through the
//! real [`WindowsProcessExecutor`](eliot_process_executor::WindowsProcessExecutor),
//! and returns the canonical guest output. No stub ports, no
//! request-selected authority, no fake P-07 permission: the permit is
//! issued by [`WasmDispatchAuthority`](crate::dispatch_authority::WasmDispatchAuthority)
//! funded exclusively by the validated dispatch grant, and the executor
//! re-hashes the installed image before any start.
//!
//! THE CANONICAL WASM INTENT RULE (the owner-side publisher runs the
//! identical forward computation; every field is fixed before any join
//! digest exists, so the derivation is acyclic):
//!
//! ```text
//! operation_id  = the admitted claim operation identity
//! process_tree  = the admitted claim identity (distinct type, one value)
//! job_id        = the admitted operation identity (distinct type, one value)
//! image_id      = "wasm-host-image-" + short(owner-measured host digest)
//! session_id    = the admitted claim identity (distinct type, one value)
//! generation    = the claiming generation
//! executable    = the resolved installed image path (current_exe,
//!                 re-hashed against the owner-measured digest)
//! argv          = the exact --guest-exec set: `--profile` plus the
//!                 owner-selected composition first, then colocated
//!                 artifact/input paths, their re-hashed digests, and the
//!                 material ceilings
//! working_dir   = the executable parent directory
//! environment   = empty secret-free projection
//! limits        = wall/fuel/memory/output ceilings from the material;
//!                 exactly one descendant (the reaped child itself — the
//!                 guest runs in-process and spawns no OS processes)
//! ```
//!
//! Nothing comes from CLI transport facts: identities and ceilings come
//! from the validated material, paths from the OS loader layout. The drive
//! ends at the canonical response (guest output bytes plus their digest and
//! the child-observed metering); seating `IsolatedChildEngine::invoke`
//! additionally needs Governor-issued invocation receipts, which stay with
//! the invocation owner lane.
//!
//! Failure discipline: stage-taxonomy [`DriveError`] codes only. No paths,
//! bytes, or digests echoed.

use std::path::Path;
use std::sync::{Arc, Mutex};

use eliot_contracts::{ArtifactId, ContractId, ResourceGeneration, StateFence};
use eliot_governor::{
    ContourAdmission, GovernorWasmAdmission, KernelGenerationSnapshot, PromotionExpectations,
};
use eliot_observation_contracts::ObservationScope;
use eliot_process::{
    EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError, Generation, ImageId, JobId,
    OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessIntent,
    ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_process_executor::{WindowsProcessExecutor, wasm_p03_adapter::WasmP03ProcessAdapter};
use eliot_receipts::WorkScopeId;
use eliot_runtime_contracts::{
    HealthDimension, HealthVector, LeaseState, ModuleGeneration, ModuleGenerationState,
    RuntimeLease,
};
use eliot_security_contracts::{
    CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
    InstructionTaint, IntegrityStatus, PrivacyClass, QuarantineState, SourceAssurance,
};
use eliot_wasm_runtime::{
    ArtifactAccessLimits, AuthorityResolutionPort, CancellationPolicy, CapabilityId,
    ComponentEnginePort, ComponentManifest, EngineBinding, EngineInvocation, EngineTermination,
    EpochPolicy, ExecutionContour, GovernorResolutionPort, InvocationId, InvocationLimits,
    InvocationRequest, OwnerId, P03ProcessPort, ProcessBinding, Revision, Sha256Digest,
    SourceVerificationPort, WorkScopeRef, WorkUnitId,
};

use crate::child_engine::IsolatedChildEngine;
use crate::dispatch_authority::{DispatchAuthorityError, WasmDispatchAuthority};
use crate::dispatch_material::{MaterialError, ValidatedDispatchMaterial, read_dispatch_material};
use crate::installed_binary::{
    InstalledBinaryError, WasmHostBinaryBinding, resolve_installed_binary,
};

/// Exact `--guest-exec` argv assembled for the reaped child. Spellings
/// match the CLI contract; values are material-proven, never ambient.
pub const GUEST_EXEC_ARGV0_HINT: &str = "--guest-exec";

/// Fail-closed drive errors: pipeline stage plus stable detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriveError {
    /// No dispatch material was delivered.
    NoMaterial,
    /// Material validation failed.
    Material(MaterialError),
    /// Installed-image resolution failed.
    Resolve(InstalledBinaryError),
    /// Dispatch authority derivation or issuance failed.
    Authority(DispatchAuthorityError),
    /// Intent derivation failed.
    Intent {
        /// Stable field name.
        field: &'static str,
    },
    /// Admission assembly failed (contour, owner records, factory).
    Admission {
        /// Stable field name.
        field: &'static str,
    },
    /// Invocation assembly or engine invocation failed.
    Invocation {
        /// Stable field name.
        field: &'static str,
    },
    /// Staging, start, reap, or capture failed.
    Execution {
        /// Stable stage name.
        stage: &'static str,
    },
}

impl std::fmt::Display for DriveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMaterial => formatter.write_str("DISPATCH_DRIVE_NO_MATERIAL"),
            Self::Material(error) => write!(formatter, "{error}"),
            Self::Resolve(error) => write!(formatter, "{error}"),
            Self::Authority(error) => write!(formatter, "{error}"),
            Self::Intent { field } => write!(formatter, "DISPATCH_DRIVE_INTENT:{field}"),
            Self::Admission { field } => write!(formatter, "DISPATCH_DRIVE_ADMISSION:{field}"),
            Self::Invocation { field } => write!(formatter, "DISPATCH_DRIVE_INVOCATION:{field}"),
            Self::Execution { stage } => write!(formatter, "DISPATCH_DRIVE_EXECUTION:{stage}"),
        }
    }
}

impl std::error::Error for DriveError {}

/// Canonical dispatch response: the guest output bytes plus the
/// tamper-evident facts binding them to the admitted operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchDriveResponse {
    /// Admitted operation identity.
    pub operation_id: String,
    /// Pinned component identity.
    pub component_id: String,
    /// Proven artifact digest (hex).
    pub artifact_digest: String,
    /// Proven input digest (hex).
    pub input_digest: String,
    /// Owner-measured host digest the child image resolved against (hex).
    pub host_artifact_digest: String,
    /// SHA-256 of the exact guest output bytes (hex).
    pub output_digest: String,
    /// Exact guest output bytes observed through P03 capture.
    pub output: Vec<u8>,
    /// Child-observed fuel consumed.
    pub fuel_consumed: u64,
    /// Child-observed peak memory bytes.
    pub peak_memory_bytes: u64,
    /// Child-observed table elements.
    pub table_elements: u64,
    /// Child-observed epoch ticks.
    pub epoch_ticks: u64,
}

/// Bounded production evidence sink: retains evidence up to the cap, then
/// fails closed (never drops retained evidence silently).
struct BoundedDriveSink {
    retained: Mutex<Vec<ProcessEvidence>>,
}

impl BoundedDriveSink {
    const CAP: usize = 1024;

    fn new() -> Self {
        Self {
            retained: Mutex::new(Vec::new()),
        }
    }
}

impl ProcessEvidenceSink for BoundedDriveSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        let mut guard = self.retained.lock().map_err(|_| EvidenceSinkError {
            message: "drive sink lock poisoned".to_owned(),
        })?;
        if guard.len() >= Self::CAP {
            return Err(EvidenceSinkError {
                message: "drive sink at capacity".to_owned(),
            });
        }
        guard.push(evidence);
        Ok(())
    }
}

/// Resolves the installed child image: this process's own executable path
/// re-hashed against the owner-measured digest from the material. This
/// closes the #1955 loop in the real chain without any CLI descriptor file.
fn resolve_drive_image(
    material: &ValidatedDispatchMaterial,
) -> Result<crate::installed_binary::InstalledBinary, DriveError> {
    let executable =
        std::env::current_exe().map_err(|_| DriveError::Execution { stage: "locator" })?;
    let binding = WasmHostBinaryBinding::new(executable, material.host_artifact_digest.clone())
        .map_err(DriveError::Resolve)?;
    resolve_installed_binary(&binding).map_err(DriveError::Resolve)
}

/// Derives the `--guest-exec` argv for the reaped child from proven
/// material: the owner-selected composition profile first (the child
/// composition must parse — a profile-less child exits before any guest),
/// then colocated files plus their re-hashed digests plus ceilings.
fn guest_exec_argv(
    material: &ValidatedDispatchMaterial,
    directory: &Path,
) -> Result<Vec<String>, DriveError> {
    let artifact = directory.join(crate::dispatch_material::WASM_HOST_GUEST_ARTIFACT_FILE_NAME);
    let input = directory.join(crate::dispatch_material::WASM_HOST_GUEST_INPUT_FILE_NAME);
    let artifact_text = artifact.to_str().ok_or(DriveError::Intent {
        field: "artifact-path",
    })?;
    let input_text = input.to_str().ok_or(DriveError::Intent {
        field: "input-path",
    })?;
    let ceilings = &material.ceilings;
    let argv = vec![
        "--profile".to_owned(),
        material.profile.as_str().to_owned(),
        GUEST_EXEC_ARGV0_HINT.to_owned(),
        "--guest-exec-artifact".to_owned(),
        artifact_text.to_owned(),
        "--guest-exec-input".to_owned(),
        input_text.to_owned(),
        "--guest-exec-artifact-digest".to_owned(),
        ceilings.artifact_digest.as_str().to_owned(),
        "--guest-exec-max-output".to_owned(),
        ceilings.max_output_bytes.to_string(),
        "--guest-exec-max-fuel".to_owned(),
        ceilings.max_fuel.to_string(),
        "--guest-exec-max-memory".to_owned(),
        ceilings.max_memory_bytes.to_string(),
        "--guest-exec-wall-ms".to_owned(),
        ceilings.wall_deadline_ms.to_string(),
        "--guest-exec-epoch-ticks".to_owned(),
        ceilings.epoch_deadline_ticks.to_string(),
    ];
    Ok(argv)
}

/// Derives the exact immutable `ProcessIntent` for the reaped child per the
/// canonical rule above. Every identity is admitted material; the two paths
/// are the OS loader layout.
fn derive_drive_intent(
    material: &ValidatedDispatchMaterial,
    executable: &Path,
    host_digest: &Sha256Digest,
    working_directory: &Path,
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
    let environment = EnvironmentProjection::new(
        std::collections::BTreeMap::new(),
        Vec::new(),
        EnvironmentInheritance::None,
    )
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
    let argv = guest_exec_argv(material, directory)?;
    ProcessIntent::new(
        OperationId::new(material.operation_id.clone()).map_err(|_| intent_field("operation"))?,
        ProcessTreeId::new(material.claim_id.clone()).map_err(|_| intent_field("tree"))?,
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

/// Issues the one-shot permit for the derived intent from the validated
/// grant. Freshness is file-derived through the grant window.
fn issue_drive_permit(
    material: &ValidatedDispatchMaterial,
    authority: &WasmDispatchAuthority,
    intent: &ProcessIntent,
    now_ms: u64,
) -> Result<ProcessRequest, DriveError> {
    authority
        .issue(intent, &material.grant, &material.launch_nonce, now_ms)
        .map_err(DriveError::Authority)
}

/// Current Unix time in milliseconds for issuance freshness.
fn now_unix_ms() -> Result<u64, DriveError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .map_err(|_| DriveError::Execution { stage: "clock" })
}

/// Builds the invocation request from admitted identities: invocation and
/// tree bind the operation and claim, work unit and scope bind the work
/// record, the contour binds the material marker, the input is the proven
/// guest bytes, and the seed is owner-set. Cancellation is never
/// requested by the drive.
fn assemble_request(material: &ValidatedDispatchMaterial) -> Result<InvocationRequest, DriveError> {
    let invoked = |field: &'static str| DriveError::Admission { field };
    let contour = match material.work.contour.as_str() {
        "SHADOW" => ExecutionContour::Shadow,
        "CONFORMANCE" => ExecutionContour::Conformance,
        _ => return Err(invoked("contour")),
    };
    InvocationRequest::new(
        InvocationId::new(material.operation_id.clone()).map_err(|_| invoked("invocation-id"))?,
        CapabilityId::new(material.ceilings.component_id.clone())
            .map_err(|_| invoked("component-id"))?,
        WorkUnitId::new(material.work.work_unit.clone()).map_err(|_| invoked("work-unit"))?,
        WorkScopeRef::new(material.work.work_scope.clone()).map_err(|_| invoked("work-scope"))?,
        contour,
        material.input_bytes.clone(),
        material.work.deterministic_seed,
        false,
    )
    .map_err(|_| invoked("request"))
}

/// Builds the closed-world generation manifest from material records plus
/// recomputed digests, then runs the documented contour admission over
/// real bytes: default WASM decision, digest re-hash, empty actual
/// imports, and request binding. Returns the manifest for owner assembly
/// plus the admitted generation the request must match.
fn contour_admission(
    material: &ValidatedDispatchMaterial,
    request: &InvocationRequest,
) -> Result<
    (
        crate::contour::GenerationManifest,
        crate::contour::AdmittedGeneration,
    ),
    DriveError,
> {
    let denied = |field: &'static str| DriveError::Admission { field };
    let manifest = crate::contour::GenerationManifest {
        component_id: material.manifest.component_id.clone(),
        target: material.manifest.target.clone(),
        artifact_digest: Sha256Digest::of_bytes(&material.artifact_bytes),
        wit_digest: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
        world: material.manifest.world.clone(),
        allowed_imports: Vec::new(),
        allowed_exports: vec!["run".to_owned()],
        capability_grants: Vec::new(),
        limits: assemble_limits(material)?,
        state_class: material.manifest.state_class.clone(),
        migration_contract: material.manifest.migration_contract.clone(),
        privacy_policy: material.manifest.privacy_policy.clone(),
        comparator: material.manifest.comparator.clone(),
        rollback_generation: material.manifest.rollback_generation.clone(),
    };
    if manifest.artifact_digest != material.ceilings.artifact_digest
        || manifest.component_id != material.ceilings.component_id
    {
        return Err(denied("manifest-agreement"));
    }
    let decision = crate::contour::PrototypeContourDecision::default_for_new_prototype();
    let admitted = crate::contour::admit_generation_with_bytes(
        Some(&decision),
        &manifest,
        &[],
        &material.artifact_bytes,
        &crate::wasmtime_provider::guest_wit_bytes(),
    )
    .map_err(|_| denied("contour-admission"))?;
    crate::contour::check_admitted_request(&admitted, request)
        .map_err(|_| denied("request-binding"))?;
    Ok((manifest, admitted))
}

/// Assembles the per-invocation limit envelope from material ceilings plus
/// frozen contour constants. Input ceiling tracks the real input length
/// (ceilings bound, never shrink, reality); host-call ceiling stays at the
/// closed-world minimum; stack and cancellation stay provider-pinned.
fn assemble_limits(material: &ValidatedDispatchMaterial) -> Result<InvocationLimits, DriveError> {
    let ceilings = &material.ceilings;
    let limited = |field: &'static str| DriveError::Admission { field };
    Ok(InvocationLimits {
        max_input_bytes: (material.input_bytes.len() as u64).max(1),
        max_output_bytes: ceilings.max_output_bytes,
        max_host_calls: 1,
        max_fuel: ceilings.max_fuel,
        max_memory_bytes: ceilings.max_memory_bytes,
        max_table_elements: u32::try_from(ceilings.table_elements)
            .map_err(|_| limited("table-elements"))?,
        max_instances: u32::try_from(ceilings.max_instances).map_err(|_| limited("instances"))?,
        max_stack_bytes: crate::wasmtime_provider::PROVIDER_STACK_SIZE as u64,
        wall_deadline_ms: ceilings.wall_deadline_ms,
        epoch: EpochPolicy {
            deadline_ticks: ceilings.epoch_deadline_ticks,
            cancellation: CancellationPolicy::EpochAndFuel,
        },
        artifact_access: ArtifactAccessLimits {
            allowed_digests: [ceilings.artifact_digest.clone()].into_iter().collect(),
            max_reads: u32::try_from(ceilings.artifact_access_reads)
                .map_err(|_| limited("artifact-reads"))?,
            max_bytes: ceilings.artifact_access_bytes,
        },
    })
}

/// Assembles the component manifest from material records plus recomputed
/// digests. The engine binding is the shared grant-derived object, so the
/// engine gate binds the exact authorized digests; interface and
/// configuration digests recompute from the frozen bytes.
fn assemble_component_manifest(
    material: &ValidatedDispatchMaterial,
    engine_binding: &EngineBinding,
) -> Result<ComponentManifest, DriveError> {
    let manifested = |field: &'static str| DriveError::Admission { field };
    let privacy = material
        .manifest
        .privacy_classes
        .iter()
        .map(|class| match class.as_str() {
            "Public" => Ok(PrivacyClass::Public),
            "Internal" => Ok(PrivacyClass::Internal),
            "Private" => Ok(PrivacyClass::Private),
            "Secret" => Ok(PrivacyClass::Secret),
            "Licensed" => Ok(PrivacyClass::Licensed),
            _ => Err(manifested("privacy-class")),
        })
        .collect::<Result<Vec<PrivacyClass>, DriveError>>()?;
    Ok(ComponentManifest {
        component_id: CapabilityId::new(material.manifest.component_id.clone())
            .map_err(|_| manifested("component-id"))?,
        world: CapabilityId::new(material.manifest.world.clone())
            .map_err(|_| manifested("world"))?,
        wit_version: crate::wasmtime_provider::WIT_VERSION.to_owned(),
        guest_target: material.manifest.target.clone(),
        artifact_digest: Sha256Digest::of_bytes(&material.artifact_bytes),
        interface_digest: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
        source_digest: material.manifest.source_digest.clone(),
        configuration_digest: crate::wasmtime_provider::provider_configuration_digest(),
        state_contract_digest: material.manifest.state_contract_digest.clone(),
        imports: Default::default(),
        exports: [CapabilityId::new("run").map_err(|_| manifested("exports"))?]
            .into_iter()
            .collect(),
        admitted_privacy_classes: privacy,
        required_verifier: material.manifest.required_verifier.clone(),
        engine: engine_binding.clone(),
    })
}

/// Maps one owner spelling to its health dimension; unknown spellings fail
/// closed so owner and child can never disagree silently.
fn map_health_dimension(value: &str) -> Result<HealthDimension, DriveError> {
    match value {
        "UNKNOWN" => Ok(HealthDimension::Unknown),
        "HEALTHY" => Ok(HealthDimension::Healthy),
        "DEGRADED" => Ok(HealthDimension::Degraded),
        "FAILED" => Ok(HealthDimension::Failed),
        _ => Err(DriveError::Admission {
            field: "health-dimension",
        }),
    }
}

/// Assembles the owner records for the Governor factory: snapshot,
/// generation, lease, owner, scope, assurance, limits, revisions, caps,
/// promotion. Fences derive from the snapshot (recovery state); the grant
/// fence agrees with it by material validation. Every enum spelling maps
/// strictly; unknown spellings fail closed.
#[allow(clippy::too_many_lines)]
fn assemble_owner_records(
    material: &ValidatedDispatchMaterial,
) -> Result<OwnerRecords, DriveError> {
    let owned = |field: &'static str| DriveError::Admission { field };
    let snapshot = KernelGenerationSnapshot {
        service: material.snapshot.service.clone(),
        protocol: material.snapshot.protocol.clone(),
        generation: ResourceGeneration::new(material.snapshot.generation)
            .map_err(|_| owned("snapshot-generation"))?,
        authority_epoch: material.snapshot.authority_epoch.clone(),
        artifact_digest: material.snapshot.artifact_digest.as_str().to_owned(),
        protected_snapshot_digest: material
            .snapshot
            .protected_snapshot_digest
            .as_str()
            .to_owned(),
        principal: material.snapshot.principal.clone(),
    };
    snapshot
        .validate()
        .map_err(|_| owned("snapshot-validate"))?;
    let fence = snapshot.state_fence();
    let generation = ModuleGeneration {
        module_id: ContractId::new(material.manifest.component_id.clone())
            .map_err(|_| owned("module-id"))?,
        generation: ResourceGeneration::new(material.grant.fence_generation())
            .map_err(|_| owned("fence-generation"))?,
        artifact_id: ArtifactId::new(material.ceilings.artifact_digest.as_str().to_owned())
            .map_err(|_| owned("artifact-id"))?,
        state: match material.work.generation_state.as_str() {
            "ready" => ModuleGenerationState::Ready,
            "active" => ModuleGenerationState::Active,
            _ => return Err(owned("generation-state")),
        },
        health: {
            let dimensions = material
                .work
                .generation_health
                .iter()
                .map(|dimension| map_health_dimension(dimension))
                .collect::<Result<Vec<HealthDimension>, DriveError>>()?;
            let [
                liveness,
                readiness,
                freshness,
                compatibility,
                integrity,
                capacity,
            ] = dimensions.try_into().map_err(|_| owned("health-vector"))?;
            HealthVector {
                liveness,
                readiness,
                freshness,
                compatibility,
                integrity,
                capacity,
            }
        },
        state_fence: fence.clone(),
    };
    let lease = RuntimeLease {
        lease_id: material.work.lease_id.clone(),
        scope_ref: material.work.lease_scope_ref.clone(),
        authority_epoch: material.authority_epoch.clone(),
        state_fence: fence.clone(),
        state: match material.work.lease_state.as_str() {
            "active" => LeaseState::Active,
            _ => return Err(owned("lease-state")),
        },
    };
    let owner = OwnerId::new(material.work.owner.clone()).map_err(|_| owned("owner"))?;
    let work_unit =
        WorkUnitId::new(material.work.work_unit.clone()).map_err(|_| owned("work-unit"))?;
    let work_scope = ObservationScope {
        work_scope: WorkScopeId::new(material.work.work_scope.clone())
            .map_err(|_| owned("work-scope"))?,
        task_ref: material.work.task_ref.clone(),
        attempt_ref: Some(material.work.work_unit.clone()),
        module_or_route_ref: Some(material.ceilings.component_id.clone()),
    };
    let assurance = SourceAssurance {
        source_ref: material.assurance.source_ref.clone(),
        provenance_ref: material.assurance.provenance_ref.clone(),
        integrity: match material.assurance.integrity.as_str() {
            "VERIFIED" => IntegrityStatus::Verified,
            "UNVERIFIED" => IntegrityStatus::Unverified,
            "MODIFIED" => IntegrityStatus::Modified,
            "CONFLICTED" => IntegrityStatus::Conflicted,
            _ => return Err(owned("assurance-integrity")),
        },
        freshness: match material.assurance.freshness.as_str() {
            "CURRENT" => FreshnessStatus::Current,
            "STALE" => FreshnessStatus::Stale,
            "UNKNOWN" => FreshnessStatus::Unknown,
            _ => return Err(owned("assurance-freshness")),
        },
        competence: match material.assurance.competence.as_str() {
            "DOMAIN_VERIFIED" => CompetenceLevel::DomainVerified,
            "ATTRIBUTED" => CompetenceLevel::Attributed,
            "UNKNOWN" => CompetenceLevel::Unknown,
            _ => return Err(owned("assurance-competence")),
        },
        independence: match material.assurance.independence.as_str() {
            "INDEPENDENT" => IndependenceLevel::Independent,
            "RELATED" => IndependenceLevel::Related,
            "COMMON_MODE" => IndependenceLevel::CommonMode,
            "UNKNOWN" => IndependenceLevel::Unknown,
            _ => return Err(owned("assurance-independence")),
        },
        privacy_class: match material.assurance.privacy_class.as_str() {
            "PUBLIC" => PrivacyClass::Public,
            "INTERNAL" => PrivacyClass::Internal,
            "PRIVATE" => PrivacyClass::Private,
            "SECRET" => PrivacyClass::Secret,
            "LICENSED" => PrivacyClass::Licensed,
            _ => return Err(owned("assurance-privacy")),
        },
        instruction_taint: match material.assurance.instruction_taint.as_str() {
            "CLEARED" => InstructionTaint::Cleared,
            "DATA_ONLY" => InstructionTaint::DataOnly,
            "UNTRUSTED" => InstructionTaint::Untrusted,
            "COMMAND_LIKE" => InstructionTaint::CommandLike,
            _ => return Err(owned("assurance-taint")),
        },
        allowed_epistemic_use: material
            .assurance
            .epistemic_use
            .iter()
            .map(|use_verb| match use_verb.as_str() {
                "OBSERVATION" => Ok(EpistemicUse::Observation),
                "ATTRIBUTED_INPUT" => Ok(EpistemicUse::AttributedInput),
                "CANDIDATE_EVIDENCE" => Ok(EpistemicUse::CandidateEvidence),
                "VERIFICATION_INPUT" => Ok(EpistemicUse::VerificationInput),
                _ => Err(owned("assurance-epistemic")),
            })
            .collect::<Result<Vec<EpistemicUse>, DriveError>>()?,
        allowed_effects: material
            .assurance
            .effect_ceilings
            .iter()
            .map(|ceiling| match ceiling.as_str() {
                "READ_ONLY" => Ok(EffectCeiling::ReadOnly),
                "CANDIDATE_ONLY" => Ok(EffectCeiling::CandidateOnly),
                "NO_EXTERNAL_EFFECT" => Ok(EffectCeiling::NoExternalEffect),
                _ => Err(owned("assurance-effects")),
            })
            .collect::<Result<Vec<EffectCeiling>, DriveError>>()?,
        required_verifier: Some(material.assurance.required_verifier.clone()),
        quarantine: match material.assurance.quarantine.as_str() {
            "NONE" => QuarantineState::None,
            "REVIEW_REQUIRED" => QuarantineState::ReviewRequired,
            "QUARANTINED" => QuarantineState::Quarantined,
            "RELEASED" => QuarantineState::Released,
            _ => return Err(owned("assurance-quarantine")),
        },
        state_fence: fence,
    };
    Ok(OwnerRecords {
        snapshot,
        generation,
        lease,
        owner,
        work_unit,
        work_scope,
        assurance,
    })
}

/// Owner records assembled for one Governor factory call.
struct OwnerRecords {
    snapshot: KernelGenerationSnapshot,
    generation: ModuleGeneration,
    lease: RuntimeLease,
    owner: OwnerId,
    work_unit: WorkUnitId,
    work_scope: ObservationScope,
    assurance: SourceAssurance,
}

/// Acquires admission from the existing Governor factory over owner
/// records: contour observations re-hash real bytes, coherence re-proves
/// generation/lease/assurance/scope/verifier agreement, and every receipt
/// digest recomputes from retained content. Nothing here mints authority;
/// the factory denies incoherence fail-closed.
fn acquire_admission(
    material: &ValidatedDispatchMaterial,
    engine_binding: &EngineBinding,
    admitted: &crate::contour::AdmittedGeneration,
) -> Result<GovernorWasmAdmission, DriveError> {
    let owners = assemble_owner_records(material)?;
    let manifest = assemble_component_manifest(material, engine_binding)?;
    let contour = ContourAdmission {
        artifact_bytes: material.artifact_bytes.clone(),
        wit_bytes: crate::wasmtime_provider::guest_wit_bytes().to_vec(),
        configuration_bytes: crate::wasmtime_provider::provider_configuration_bytes().to_vec(),
        admitted_artifact: material.ceilings.artifact_digest.clone(),
        admitted_wit: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
        admitted_world: admitted.world().to_owned(),
        admitted_target: admitted.target().to_owned(),
    };
    let promotion = PromotionExpectations {
        corpus_digest: material.promotion.corpus_digest.clone(),
        expected_result_digest: material.promotion.expected_result_digest.clone(),
        expected_effect_digest: material.promotion.expected_effect_digest.clone(),
        expected_state_delta_digest: material.promotion.expected_state_delta_digest.clone(),
    };
    let limits = assemble_limits(material)?;
    GovernorWasmAdmission::from_owners(
        &owners.snapshot,
        manifest,
        &contour,
        owners.generation,
        owners.lease,
        owners.owner,
        owners.work_unit,
        owners.work_scope,
        owners.assurance,
        limits,
        Revision::new(material.work.authority_revision).map_err(|_| DriveError::Admission {
            field: "authority-revision",
        })?,
        Revision::new(material.work.lifecycle_revision).map_err(|_| DriveError::Admission {
            field: "lifecycle-revision",
        })?,
        Revision::new(material.work.verification_revision).map_err(|_| DriveError::Admission {
            field: "verification-revision",
        })?,
        Default::default(),
        Default::default(),
        promotion,
    )
    .map_err(|_| DriveError::Admission {
        field: "from-owners",
    })
}

/// Builds the shared grant-derived engine binding. Called once per drive;
/// the same object feeds manifest assembly and engine seating so the
/// engine gate binds the exact authorized digests.
fn engine_binding_for(installed: &crate::installed_binary::InstalledBinary) -> EngineBinding {
    crate::grant_launch::grant_engine_binding(installed)
}

/// Runs the promotion port check: the query binds the request digest,
/// component, generation, contour, and digests; the oracle expectations
/// come from the owner record. Verdicts stay unevaluated until lifecycle
/// evidence is threaded, so only Conformance admits downstream.
fn promotion_verification(
    admission: &mut GovernorWasmAdmission,
    request: &InvocationRequest,
    governor: &eliot_wasm_runtime::GovernorResolution,
) -> Result<eliot_wasm_runtime::PromotionVerification, DriveError> {
    use eliot_wasm_runtime::PromotionVerificationPort;
    let query = eliot_wasm_runtime::PromotionQuery {
        request_digest: request.request_digest().clone(),
        component_id: request.component_id.clone(),
        generation: governor.generation.clone(),
        contour: request.requested_contour,
        artifact_digest: governor.manifest.artifact_digest.clone(),
        interface_digest: governor.manifest.interface_digest.clone(),
        state_contract_digest: governor.manifest.state_contract_digest.clone(),
    };
    PromotionVerificationPort::verify(admission, &query).map_err(|_| DriveError::Admission {
        field: "promotion-verify",
    })
}

/// Derives the snapshot fence the accepted grant carries: the snapshot
/// epoch plus the snapshot generation, both enforced equal to the grant
/// fence at material validation.
fn snapshot_fence(material: &ValidatedDispatchMaterial) -> Result<StateFence, DriveError> {
    let generation = ResourceGeneration::new(material.snapshot.generation).map_err(|_| {
        DriveError::Admission {
            field: "snapshot-generation",
        }
    })?;
    Ok(StateFence::new(
        material.snapshot.authority_epoch.clone(),
        generation,
    ))
}

/// Assembles the engine invocation mirroring the runtime mapping field
/// for field: identities from the request, manifest/limits/generation/
/// lease/revisions from the Governor resolution, owner/scope from the
/// authority resolution, assurance revisions from source, corpus and
/// receipt digests from promotion, and the real process binding plus
/// start receipt from the issued request.
fn assemble_invocation(
    request: &InvocationRequest,
    governor: &eliot_wasm_runtime::GovernorResolution,
    authority: &eliot_wasm_runtime::AuthorityResolution,
    source: &eliot_wasm_runtime::SourceVerification,
    promotion: &eliot_wasm_runtime::PromotionVerification,
    process_binding: ProcessBinding,
    process_start_receipt: eliot_process::ProcessStartReceipt,
) -> Result<EngineInvocation, DriveError> {
    // Mirrors the runtime mapping field for field; every value threads a
    // live resolution or the request, and every digest recomputed upstream.
    Ok(EngineInvocation {
        invocation_id: request.invocation_id.clone(),
        request_digest: request.request_digest().clone(),
        component_id: request.component_id.clone(),
        contour: request.requested_contour,
        manifest: governor.manifest.clone(),
        imports: governor.manifest.imports.clone(),
        exports: governor.manifest.exports.clone(),
        allowed_host_calls: authority.allowed_host_calls.clone(),
        allowed_effect_proposals: authority.allowed_effect_proposals.clone(),
        generation: governor.generation.clone(),
        lease: governor.lease.clone(),
        owner: authority.owner.clone(),
        work_unit: authority.work_unit.clone(),
        work_scope: authority.work_scope.clone(),
        authority_revision: governor.authority_revision,
        lifecycle_revision: governor.lifecycle_revision,
        source_assurance: source.assurance.clone(),
        source_verification_revision: source.verification_revision,
        promotion_verification_revision: promotion.verification_revision,
        conformance_corpus_digest: promotion.corpus_digest.clone(),
        governor_resolution_receipt_digest: governor.resolution_receipt_digest.clone(),
        authority_resolution_receipt_digest: authority.resolution_receipt_digest.clone(),
        source_verification_receipt_digest: source.verification_receipt_digest.clone(),
        promotion_verification_receipt_digest: promotion.verification_receipt_digest.clone(),
        state_contract_digest: governor.manifest.state_contract_digest.clone(),
        limits: governor.limits.clone(),
        input: request.input.clone(),
        deterministic_seed: request.deterministic_seed,
        process_binding,
        process_start_receipt,
    })
}

/// Conformance-only direct invocation gate: Shadow without lifecycle
/// verdicts would bypass the runtime promotion gate, so it stays denied
/// here until verdict evidence is threaded (A13.3 residual).
fn ensure_conformance_direct(contour: &ExecutionContour) -> Result<(), DriveError> {
    if !matches!(contour, ExecutionContour::Conformance) {
        return Err(DriveError::Admission {
            field: "contour-direct",
        });
    }
    Ok(())
}

/// Seated engine invocation over the reaped child: authorizes the grant,
/// seats the engine on the shared binding, assembles the invocation, and
/// invokes. Returns the canonical engine report with real guest output.
fn invoke_admitted(
    material: &ValidatedDispatchMaterial,
    executable: &Path,
    host_digest: &Sha256Digest,
    engine_binding: &EngineBinding,
    executor: &Arc<WindowsProcessExecutor>,
    sink: &Arc<dyn ProcessEvidenceSink>,
    governor: &eliot_wasm_runtime::GovernorResolution,
    authority: &eliot_wasm_runtime::AuthorityResolution,
    source: &eliot_wasm_runtime::SourceVerification,
    promotion: &eliot_wasm_runtime::PromotionVerification,
    request: &InvocationRequest,
    binding: ProcessBinding,
    start_receipt: eliot_process::ProcessStartReceipt,
    now_ms: u64,
) -> Result<DispatchDriveResponse, DriveError> {
    let invoked = |field: &'static str| DriveError::Invocation { field };
    if material.grant.expires_at() <= now_ms {
        return Err(DriveError::Authority(DispatchAuthorityError::Unavailable {
            field: "grant-window",
        }));
    }
    if governor.manifest.engine != *engine_binding {
        return Err(invoked("engine-binding"));
    }
    let executable_text = executable.to_str().ok_or(DriveError::Invocation {
        field: "executable",
    })?;
    let accepted = crate::grant_client::AcceptedGrant {
        component_id: material.ceilings.component_id.clone(),
        artifact_digest: Sha256Digest::of_bytes(&material.artifact_bytes),
        interface_digest: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
        fence: snapshot_fence(material)?,
        epoch: material.authority_epoch.clone(),
        nonce: material.launch_nonce.clone(),
        deadline_unix_ms: material.grant.expires_at(),
        host_executable_path: executable_text.to_owned(),
        host_artifact_digest: host_digest.clone(),
    };
    let authorized = crate::grant_authorization::authorize_grant(
        &accepted,
        executable_text,
        host_digest,
        &material.artifact_bytes,
        &crate::wasmtime_provider::guest_wit_bytes(),
    )
    .map_err(|_| invoked("authorize"))?;
    let mut engine = IsolatedChildEngine::for_authorized_grant(
        Arc::clone(executor),
        Arc::clone(sink),
        engine_binding.clone(),
        &authorized,
        crate::wasmtime_provider::provider_configuration_digest(),
    );
    ensure_conformance_direct(&request.requested_contour)?;
    let invocation = assemble_invocation(
        request,
        governor,
        authority,
        source,
        promotion,
        binding,
        start_receipt,
    )?;
    let report = engine.invoke(&invocation).map_err(|_| invoked("invoke"))?;
    if !matches!(report.termination, EngineTermination::Completed) {
        return Err(DriveError::Execution {
            stage: "termination",
        });
    }
    let peak = report
        .usage
        .peak_memory_bytes
        .ok_or(DriveError::Execution { stage: "metering" })?;
    let tables = report
        .usage
        .table_elements
        .ok_or(DriveError::Execution { stage: "metering" })?;
    let ticks = report
        .usage
        .epoch_ticks
        .ok_or(DriveError::Execution { stage: "metering" })?;
    Ok(DispatchDriveResponse {
        operation_id: material.operation_id.clone(),
        component_id: material.ceilings.component_id.clone(),
        artifact_digest: material.ceilings.artifact_digest.as_str().to_owned(),
        input_digest: material.ceilings.input_digest.as_str().to_owned(),
        host_artifact_digest: host_digest.as_str().to_owned(),
        output_digest: Sha256Digest::of_bytes(&report.output).as_str().to_owned(),
        output: report.output,
        fuel_consumed: report.usage.fuel_consumed,
        peak_memory_bytes: peak,
        table_elements: u64::from(tables),
        epoch_ticks: ticks,
    })
}

/// Drives one admitted dispatch to the canonical response through the
/// documented admission path and the existing isolated child engine:
/// contour admission over real bytes, owner-record assembly, Governor
/// factory admission, invocation request, one-shot issue, real start,
/// engine invocation over the reaped child, canonical response. The child
/// execution is real; every boundary fails closed (never a fabricated
/// byte, never minted authority).
pub fn drive_dispatch() -> Result<DispatchDriveResponse, DriveError> {
    let material = read_dispatch_material()
        .map_err(DriveError::Material)?
        .ok_or(DriveError::NoMaterial)?;
    drive_material(&material)
}

/// Drives one already-validated material to the canonical response.
/// Separated so the validation boundary stays independently testable.
fn drive_material(
    material: &ValidatedDispatchMaterial,
) -> Result<DispatchDriveResponse, DriveError> {
    // Installed image first: the engine binding, intent executable, and
    // installation records all flow from this single resolution.
    let installed = resolve_drive_image(material)?;
    let executable = installed.path().to_path_buf();
    let host_digest = installed.digest().clone();
    // Shared grant-derived engine binding: the same object feeds manifest
    // assembly and engine seating so the engine gate binds the exact
    // authorized digests.
    let engine_binding = engine_binding_for(&installed);
    // Invocation request from admitted identities: invocation and tree
    // bind the operation and claim so the runtime coherence rules close
    // over admitted values, never minted ones.
    let request = assemble_request(material)?;
    // Contour admission over real bytes: manifest assembly, default WASM
    // decision, byte re-hash, request binding. A divergent fixture is
    // denied before any authority, permit, or child exists.
    let (_, admitted) = contour_admission(material, &request)?;
    // Owner records + Governor factory: snapshot, generation, lease,
    // owner, scope, assurance, limits, revisions, caps, promotion. The
    // factory re-proves coherence and re-hashes digests; its receipts are
    // recomputed from retained content, never minted.
    let mut admission = acquire_admission(material, &engine_binding, &admitted)?;
    // Live resolutions from the retained admission: each port re-checks
    // the request binding and returns receipt-bound records.
    let governor = GovernorResolutionPort::resolve(&mut admission, &request).map_err(|_| {
        DriveError::Admission {
            field: "governor-resolve",
        }
    })?;
    let authority_res =
        AuthorityResolutionPort::resolve(&mut admission, &request).map_err(|_| {
            DriveError::Admission {
                field: "authority-resolve",
            }
        })?;
    let source = SourceVerificationPort::verify(&mut admission, &request).map_err(|_| {
        DriveError::Admission {
            field: "source-verify",
        }
    })?;
    let promotion = promotion_verification(&mut admission, &request, &governor)?;
    // One-shot issue over the derived authority, then the real start. The
    // issued request binds the runtime envelope the owner join closes.
    let working_directory = executable
        .parent()
        .ok_or(DriveError::Intent {
            field: "working-directory",
        })?
        .to_path_buf();
    let epoch_json = serde_json::to_value(&material.authority_epoch).map_err(|_| {
        DriveError::Authority(DispatchAuthorityError::InvalidMaterial {
            field: "epoch-shape",
        })
    })?;
    let dispatch_authority = WasmDispatchAuthority::new(
        &material.claim_id,
        &material.operation_id,
        material.generation,
        &epoch_json,
        &material.launch_nonce,
    )
    .map_err(DriveError::Authority)?;
    let intent = derive_drive_intent(material, &executable, &host_digest, &working_directory)?;
    let now_ms = now_unix_ms()?;
    let issued = issue_drive_permit(material, &dispatch_authority, &intent, now_ms)?;
    let binding = ProcessBinding::from_request(&issued);
    let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(
        DriveAuthorityPort::new(dispatch_authority),
    )));
    let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(BoundedDriveSink::new());
    let mut process = WasmP03ProcessAdapter::new(Arc::clone(&executor), Arc::clone(&sink));
    // Single ownership of the request value: the adapter's staged slot
    // serves the runtime `prepare` path (which needs P-02 launch
    // evidence); the parent drive moves the issued request straight into
    // `start`, then the engine reaps the same operation. No second
    // invocation, no retry of the effect.
    let start_receipt = process
        .start(issued)
        .map_err(|_| DriveError::Execution { stage: "start" })?;
    invoke_admitted(
        material,
        &executable,
        &host_digest,
        &engine_binding,
        &executor,
        &sink,
        &governor,
        &authority_res,
        &source,
        &promotion,
        &request,
        binding,
        start_receipt,
        now_ms,
    )
}

/// `Arc`-shared dispatch authority fronting the executor. The authority is
/// constructed by value in [`drive_material`]; this thin shared wrapper
/// lets the executor hold it without borrowing the drive frame.
struct DriveAuthorityPort {
    authority: WasmDispatchAuthority,
}

impl DriveAuthorityPort {
    fn new(authority: WasmDispatchAuthority) -> Self {
        Self { authority }
    }
}

impl eliot_process_executor::DispatchValidationPort for DriveAuthorityPort {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: eliot_process::SuspendedProcessIdentity,
    ) -> Result<eliot_process::ValidatedDispatch, ProcessExecutionError> {
        self.authority.validate_and_consume(request, observed)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn no_material_stays_denied() {
        // No dispatch file beside the test binary: the drive reports
        // absence without touching process authority. (The test binary
        // directory carries no material file.)
        match drive_dispatch() {
            Err(DriveError::NoMaterial | DriveError::Material(_)) => {}
            other => panic!("drive without material must stay denied, got {other:?}"),
        }
    }

    #[test]
    fn drive_error_codes_are_stable() {
        assert_eq!(
            DriveError::NoMaterial.to_string(),
            "DISPATCH_DRIVE_NO_MATERIAL"
        );
        assert_eq!(
            DriveError::Intent { field: "limits" }.to_string(),
            "DISPATCH_DRIVE_INTENT:limits"
        );
        assert_eq!(
            DriveError::Execution { stage: "start" }.to_string(),
            "DISPATCH_DRIVE_EXECUTION:start"
        );
        assert_eq!(
            DriveError::Admission {
                field: "contour-admission"
            }
            .to_string(),
            "DISPATCH_DRIVE_ADMISSION:contour-admission"
        );
        assert_eq!(
            DriveError::Invocation { field: "invoke" }.to_string(),
            "DISPATCH_DRIVE_INVOCATION:invoke"
        );
    }

    /// Canonical intent pin: the derived intent carries exactly the
    /// admitted identities, the resolved image, the `--guest-exec` argv
    /// spellings, and the material ceilings. The owner publisher derives
    /// the identical intent for its join gate; any drift here fails there,
    /// never silently. Pure derivation — no filesystem, no spawn.
    #[test]
    fn derived_intent_binds_admitted_material() {
        use crate::dispatch_authority::ValidatedDispatchGrant;
        use eliot_contracts::EpochId;
        use eliot_process::{ActionLeaseRef, FencingToken, Generation};

        let epoch: EpochId = serde_json::from_value(serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3
        }))
        .expect("test epoch parses");
        let fence = FencingToken::new(
            epoch,
            Generation::new(7).expect("generation"),
            "wasm-host-launch-fence-aaaaaaaaaaaaaaaa".to_owned(),
        )
        .expect("test fence builds");
        let grant = ValidatedDispatchGrant::new(
            fence,
            ActionLeaseRef::new("wasm-host-launch-lease-aaaaaaaaaaaaaaaa".to_owned())
                .expect("lease"),
            "e".repeat(64),
            4_000_000_000_000,
            4_000_000_060_000,
        )
        .expect("test grant validates");
        let material = ValidatedDispatchMaterial {
            claim_id: "claim-intent-001".to_owned(),
            operation_id: "operation-intent-001".to_owned(),
            generation: 7,
            authority_epoch: serde_json::from_value(serde_json::json!({
                "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                "sequence": 3
            }))
            .expect("epoch parses"),
            launch_nonce: "launch-nonce-intent-0001".to_owned(),
            admitted_at_unix_ms: 4_000_000_000_000,
            grant,
            host_artifact_digest: Sha256Digest::of_bytes(b"intent-host-image"),
            profile: crate::cli_contract::Profile::D2Operational,
            manifest: crate::dispatch_material::ValidatedManifestRecord {
                component_id: "component-intent".to_owned(),
                world: "eliot:wasm/guest".to_owned(),
                target: "wasm32-wasip2".to_owned(),
                source_digest: Sha256Digest::of_bytes(b"intent-artifact"),
                state_contract_digest: Sha256Digest::of_bytes(b"intent-state"),
                required_verifier: "verifier:intent".to_owned(),
                privacy_classes: vec!["Internal".to_owned()],
                state_class: "stateless".to_owned(),
                migration_contract: "none".to_owned(),
                privacy_policy: "project_code".to_owned(),
                comparator: "shadow-exact".to_owned(),
                rollback_generation: None,
            },
            work: crate::dispatch_material::ValidatedWorkRecord {
                owner: "owner-intent".to_owned(),
                work_unit: "work-intent".to_owned(),
                work_scope: "scope-intent".to_owned(),
                task_ref: None,
                lease_id: "lease-intent".to_owned(),
                lease_scope_ref: "scope-intent".to_owned(),
                lease_state: "active".to_owned(),
                generation_state: "ready".to_owned(),
                authority_revision: 1,
                lifecycle_revision: 1,
                verification_revision: 1,
                deterministic_seed: 7,
                contour: "CONFORMANCE".to_owned(),
                generation_health: vec!["HEALTHY".to_owned(); 6],
            },
            assurance: crate::dispatch_material::ValidatedAssuranceRecord {
                source_ref: "source-intent".to_owned(),
                provenance_ref: "provenance-intent".to_owned(),
                integrity: "VERIFIED".to_owned(),
                freshness: "CURRENT".to_owned(),
                competence: "DOMAIN_VERIFIED".to_owned(),
                independence: "INDEPENDENT".to_owned(),
                privacy_class: "INTERNAL".to_owned(),
                instruction_taint: "DATA_ONLY".to_owned(),
                epistemic_use: vec!["VERIFICATION_INPUT".to_owned()],
                effect_ceilings: vec!["NO_EXTERNAL_EFFECT".to_owned()],
                required_verifier: "verifier:intent".to_owned(),
                quarantine: "NONE".to_owned(),
            },
            promotion: crate::dispatch_material::ValidatedPromotionRecord {
                corpus_digest: Sha256Digest::of_bytes(b"intent-corpus"),
                expected_result_digest: Sha256Digest::of_bytes(b"intent-result"),
                expected_effect_digest: Sha256Digest::of_bytes(b"intent-effects"),
                expected_state_delta_digest: Sha256Digest::of_bytes(b"intent-delta"),
            },
            snapshot: crate::dispatch_material::ValidatedSnapshotRecord {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                generation: 7,
                authority_epoch: serde_json::from_value(serde_json::json!({
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 3
                }))
                .expect("epoch parses"),
                artifact_digest: Sha256Digest::of_bytes(b"intent-kernel"),
                protected_snapshot_digest: Sha256Digest::of_bytes(b"intent-snapshot"),
                principal: "S-1-5-18".to_owned(),
            },
            ceilings: crate::dispatch_material::ValidatedGuestCeilings {
                component_id: "component-intent".to_owned(),
                artifact_digest: Sha256Digest::of_bytes(b"intent-artifact"),
                input_digest: Sha256Digest::of_bytes(b"intent-input"),
                max_output_bytes: 2048,
                max_fuel: 50_000,
                max_memory_bytes: 131_072,
                wall_deadline_ms: 5_000,
                epoch_deadline_ticks: 50,
                table_elements: 64,
                max_instances: 2,
                artifact_access_reads: 2,
                artifact_access_bytes: 131_072,
            },
            artifact_bytes: b"intent-artifact".to_vec(),
            input_bytes: b"intent-input".to_vec(),
        };
        let executable = Path::new("C:\\Kernel\\eliot-wasm-host.exe");
        let working = Path::new("C:\\Kernel");
        let host_digest = Sha256Digest::of_bytes(b"intent-host-image");
        let intent = derive_drive_intent(&material, executable, &host_digest, working)
            .expect("intent derives");
        // Private fields assert through the canonical JSON shape.
        let shape = serde_json::to_value(&intent).expect("intent serializes");
        assert_eq!(shape["operation_id"], "operation-intent-001");
        assert_eq!(shape["executable"], "C:\\Kernel\\eliot-wasm-host.exe");
        assert_eq!(shape["executable_sha256"], host_digest.as_str());
        let argv = shape["argv"].as_array().expect("argv array");
        let has = |flag: &str| argv.iter().any(|entry| entry == flag);
        assert_eq!(argv[0], "--profile");
        assert_eq!(argv[1], "D2_OPERATIONAL");
        assert_eq!(argv[2], "--guest-exec");
        assert!(has("--guest-exec-artifact-digest"));
        assert!(has(material.ceilings.artifact_digest.as_str()));
        assert!(has("--guest-exec-max-fuel"));
        assert!(has("50000"));
        assert!(has("--guest-exec-epoch-ticks"));
        assert!(has("50"));
    }

    /// Full admission fixture from real bytes: the checked-in guest
    /// component compiled through the existing `wat` conversion path plus
    /// a live input, with owner-consistent records throughout.
    fn admission_material(artifact: &[u8], input: &[u8]) -> ValidatedDispatchMaterial {
        use crate::dispatch_authority::ValidatedDispatchGrant;
        use eliot_contracts::EpochId;
        use eliot_process::{ActionLeaseRef, FencingToken, Generation};

        let epoch: EpochId = serde_json::from_value(serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3
        }))
        .expect("test epoch parses");
        let fence = FencingToken::new(
            epoch.clone(),
            Generation::new(7).expect("generation"),
            "wasm-host-launch-fence-aaaaaaaaaaaaaaaa".to_owned(),
        )
        .expect("test fence builds");
        let grant = ValidatedDispatchGrant::new(
            fence,
            ActionLeaseRef::new("wasm-host-launch-lease-aaaaaaaaaaaaaaaa".to_owned())
                .expect("lease"),
            "e".repeat(64),
            4_000_000_000_000,
            4_000_000_060_000,
        )
        .expect("test grant validates");
        ValidatedDispatchMaterial {
            claim_id: "claim-admit-001".to_owned(),
            operation_id: "operation-admit-001".to_owned(),
            generation: 7,
            authority_epoch: epoch,
            launch_nonce: "launch-nonce-admit-0001".to_owned(),
            admitted_at_unix_ms: 4_000_000_000_000,
            grant,
            host_artifact_digest: Sha256Digest::of_bytes(b"admit-host-image"),
            profile: crate::cli_contract::Profile::D2Operational,
            manifest: crate::dispatch_material::ValidatedManifestRecord {
                component_id: "component-admit".to_owned(),
                world: "eliot:wasm/guest".to_owned(),
                target: "wasm32-wasip2".to_owned(),
                source_digest: Sha256Digest::of_bytes(artifact),
                state_contract_digest: Sha256Digest::of_bytes(b"admit-state"),
                required_verifier: "verifier:admit".to_owned(),
                privacy_classes: vec!["Internal".to_owned()],
                state_class: "stateless".to_owned(),
                migration_contract: "none".to_owned(),
                privacy_policy: "project_code".to_owned(),
                comparator: "shadow-exact".to_owned(),
                rollback_generation: None,
            },
            work: crate::dispatch_material::ValidatedWorkRecord {
                owner: "owner-admit".to_owned(),
                work_unit: "work-admit".to_owned(),
                work_scope: "scope-admit".to_owned(),
                task_ref: None,
                lease_id: "lease-admit".to_owned(),
                lease_scope_ref: "scope-admit".to_owned(),
                lease_state: "active".to_owned(),
                generation_state: "ready".to_owned(),
                authority_revision: 1,
                lifecycle_revision: 1,
                verification_revision: 1,
                deterministic_seed: 7,
                contour: "CONFORMANCE".to_owned(),
                generation_health: vec!["HEALTHY".to_owned(); 6],
            },
            assurance: crate::dispatch_material::ValidatedAssuranceRecord {
                source_ref: "source-admit".to_owned(),
                provenance_ref: "provenance-admit".to_owned(),
                integrity: "VERIFIED".to_owned(),
                freshness: "CURRENT".to_owned(),
                competence: "DOMAIN_VERIFIED".to_owned(),
                independence: "INDEPENDENT".to_owned(),
                privacy_class: "INTERNAL".to_owned(),
                instruction_taint: "DATA_ONLY".to_owned(),
                epistemic_use: vec!["VERIFICATION_INPUT".to_owned()],
                effect_ceilings: vec!["NO_EXTERNAL_EFFECT".to_owned()],
                required_verifier: "verifier:admit".to_owned(),
                quarantine: "NONE".to_owned(),
            },
            promotion: crate::dispatch_material::ValidatedPromotionRecord {
                corpus_digest: Sha256Digest::of_bytes(b"admit-corpus"),
                expected_result_digest: Sha256Digest::of_bytes(b"admit-result"),
                expected_effect_digest: Sha256Digest::of_bytes(b"admit-effects"),
                expected_state_delta_digest: Sha256Digest::of_bytes(b"admit-delta"),
            },
            snapshot: crate::dispatch_material::ValidatedSnapshotRecord {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                generation: 7,
                authority_epoch: serde_json::from_value(serde_json::json!({
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 3
                }))
                .expect("epoch parses"),
                artifact_digest: Sha256Digest::of_bytes(b"admit-kernel"),
                protected_snapshot_digest: Sha256Digest::of_bytes(b"admit-snapshot"),
                principal: "S-1-5-18".to_owned(),
            },
            ceilings: crate::dispatch_material::ValidatedGuestCeilings {
                component_id: "component-admit".to_owned(),
                artifact_digest: Sha256Digest::of_bytes(artifact),
                input_digest: Sha256Digest::of_bytes(input),
                max_output_bytes: 4096,
                max_fuel: 100_000,
                max_memory_bytes: 536_870_912,
                wall_deadline_ms: 30_000,
                epoch_deadline_ticks: 100,
                table_elements: 64,
                max_instances: 2,
                artifact_access_reads: 2,
                artifact_access_bytes: 131_072,
            },
            artifact_bytes: artifact.to_vec(),
            input_bytes: input.to_vec(),
        }
    }

    fn real_component() -> Vec<u8> {
        wat::parse_file("tests/fixtures/guest.wat").expect("guest component compiles")
    }

    /// Documented admission over real bytes: request, contour admission
    /// with byte re-hash, owner factory coherence, and live port
    /// resolutions — all green on owner-consistent material, with receipts
    /// bound to the recomputed records.
    #[test]
    fn admission_path_binds_real_bytes() {
        let artifact = real_component();
        let input = b"admission-live-input".to_vec();
        let material = admission_material(&artifact, &input);
        let request = assemble_request(&material).expect("request assembles");
        assert_eq!(request.component_id.as_str(), "component-admit");
        let (_, admitted) = contour_admission(&material, &request).expect("contour admits");
        assert_eq!(admitted.component_id(), "component-admit");
        assert_eq!(
            admitted.artifact_digest().as_str(),
            Sha256Digest::of_bytes(&artifact).as_str()
        );
        let mut admission = acquire_admission(&material, &engine_binding_for_test(), &admitted)
            .expect("factory admits");
        let governor =
            eliot_wasm_runtime::GovernorResolutionPort::resolve(&mut admission, &request)
                .expect("governor resolves");
        assert_eq!(
            governor.manifest.artifact_digest.as_str(),
            Sha256Digest::of_bytes(&artifact).as_str()
        );
        let authority =
            eliot_wasm_runtime::AuthorityResolutionPort::resolve(&mut admission, &request)
                .expect("authority resolves");
        assert_eq!(authority.work_unit.as_str(), "work-admit");
        let source = eliot_wasm_runtime::SourceVerificationPort::verify(&mut admission, &request)
            .expect("source verifies");
        let _ = source;
        let promotion = promotion_verification(&mut admission, &request, &governor)
            .expect("promotion verifies");
        assert_eq!(
            promotion.corpus_digest.as_str(),
            Sha256Digest::of_bytes(b"admit-corpus").as_str()
        );
    }

    /// Confused-deputy negative: a request naming another component is
    /// denied at the Governor gate even with valid material.
    #[test]
    fn foreign_component_request_denied() {
        let artifact = real_component();
        let input = b"admission-live-input".to_vec();
        let material = admission_material(&artifact, &input);
        let mut request = assemble_request(&material).expect("request assembles");
        request.component_id =
            eliot_wasm_runtime::CapabilityId::new("other-component").expect("component");
        let (_, admitted) =
            contour_admission(&material, &assemble_request(&material).expect("request"))
                .expect("contour admits");
        let mut admission = acquire_admission(&material, &engine_binding_for_test(), &admitted)
            .expect("factory admits");
        assert!(matches!(
            eliot_wasm_runtime::GovernorResolutionPort::resolve(&mut admission, &request),
            Err(eliot_wasm_runtime::PortError::Denied)
        ));
    }

    /// Conformance-only direct invocation: Shadow stays denied until
    /// lifecycle verdicts are threaded.
    #[test]
    fn shadow_direct_invocation_denied() {
        assert_eq!(
            ensure_conformance_direct(&eliot_wasm_runtime::ExecutionContour::Shadow),
            Err(DriveError::Admission {
                field: "contour-direct"
            })
        );
        assert!(
            ensure_conformance_direct(&eliot_wasm_runtime::ExecutionContour::Conformance).is_ok()
        );
    }

    fn engine_binding_for_test() -> eliot_wasm_runtime::EngineBinding {
        eliot_wasm_runtime::EngineBinding {
            implementation_id: crate::child_engine::ISOLATED_CHILD_IMPLEMENTATION_ID.to_owned(),
            exact_version: crate::contour::PINNED_WASMTIME_VERSION.to_owned(),
            engine_artifact_digest: Sha256Digest::of_bytes(b"test-engine-image"),
            engine_configuration_digest: crate::wasmtime_provider::provider_configuration_digest(),
            wit_interface_digest: Sha256Digest::of_bytes(
                crate::wasmtime_provider::guest_wit_bytes(),
            ),
        }
    }
}
