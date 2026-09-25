//! B-12's authenticated Kernel grant → local admitted-port resolution.
//!
//! The component host performs a governed call only through a complete
//! Kernel-admitted port grant. This module is the receiving half of that
//! handshake, bound to the owner-published delivery set:
//!
//! ```text
//! owner-published dispatch material (closed envelope + colocated bytes)
//!   → bind_dispatch_material: record shapes, byte re-hash, grant window
//!   → resolve_kernel_port_grant: installation image re-hash, live
//!     epoch/fence, closed-world admitted manifest, one-shot P-03 permit
//!   → local owner adapters: governor / authority / source / promotion
//!   → process port + receipt verifier + one admitted engine mode
//! ```
//!
//! `RuntimePorts` is a set of local Rust trait objects, never a value that
//! crosses a process boundary. Nothing here interprets a serialized trait
//! name, a transport address, a nonce, or an attestation digest as a
//! capability: the only inputs are owner-published records plus the
//! installed image bytes, and every port binds its resolution to the
//! retained records it recomputes digests from, so a substituted record
//! fails the neutral facade's binding checks.
//!
//! The four central owner ports are LOCAL PROXIES over the admitted
//! records, not re-implementations of Governor policy. Content and shape
//! validation stays with the neutral runtime validators, and the lifecycle
//! promotion verdicts stay `Rejected` because the delivery set carries no
//! owner lifecycle evidence — so only the Conformance contour (which ignores
//! verdicts) admits, the same stance the Governor's own resolution port
//! documents. Every port re-checks [`LiveAuthority`] on each call: a
//! successful start never authorizes later work forever.
//!
//! Nearest in-tree anchors for the boundary this closes: the Kernel grant
//! handler `KernelComposition::dispatch_wasm_port_grant_frame`
//! (`bins/eliot-kernel/src/frame_dispatch.rs`), which issues
//! `handle_wasm_port_grant` over the authenticated front-door session, and
//! the owner publisher `eliot_kernel_service::wasm_dispatch`
//! (`publish_wasm_dispatch_bundle`), which stages this delivery set beside
//! the installation-approved image.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use eliot_contracts::{
    ArtifactId, ContractId, EpochId, ResourceGeneration, StateFence, canonical_json_bytes,
};
use eliot_process::ProcessEvidenceSink;
use eliot_process_executor::{WindowsProcessExecutor, wasm_p03_adapter::WasmP03ProcessAdapter};
use eliot_runtime_contracts::{LeaseState, ModuleGeneration, ModuleGenerationState, RuntimeLease};
use eliot_security_contracts::{
    CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
    InstructionTaint, IntegrityStatus, PrivacyClass, QuarantineState, SourceAssurance,
};
use eliot_wasm_runtime::{
    AuthorityResolution, AuthorityResolutionPort, CapabilityId, ComponentManifest,
    DerivedExecutionEvidence, EngineBinding, EngineInvocation, EngineReport, GovernorResolution,
    GovernorResolutionPort, InvocationLimits, InvocationRequest, OwnerId, PortError,
    PromotionQuery, PromotionVerification, PromotionVerificationPort, Revision, RuntimePorts,
    Sha256Digest, SourceVerification, SourceVerificationPort, VerificationVerdict, WorkUnitId,
};
use serde::Serialize;

use crate::child_engine::{ISOLATED_CHILD_IMPLEMENTATION_ID, IsolatedChildEngine};
use crate::contour::PINNED_WASMTIME_VERSION;
use crate::dispatch_drive::{DriveError, OwnerRecords, assemble_owner_records};
use crate::dispatch_material::ValidatedDispatchMaterial;
use crate::installed_binary::{WasmHostBinaryBinding, resolve_installed_binary};
use crate::parent_authority::ParentDispatchAuthority;
use crate::parent_runtime::{BoundedParentSink, derive_parent_intent};
use crate::typed_bindings::typed_wit_digest;
use crate::wasmtime_provider::{WIT_VERSION, WIT_WORLD, provider_configuration_digest};

/// Closed-world `run` export the admitted generation and the isolated child
/// engine both require. One literal, never a second spelling.
const RUN_EXPORT: &str = "run";

/// Lifecycle verdicts stay unevaluated until owner lifecycle evidence is
/// threaded through the delivery set. Encoding them once keeps the
/// promotion receipt digest bound to the verdicts actually returned.
const UNEVALUATED_VERDICTS: (bool, bool, bool, bool) = (false, false, false, false);

/// Live authority cell shared by the request loop's control thread and the
/// local owner adapters executing inside the engine worker.
///
/// The admitted grant is a bounded window, not a permanent capability: the
/// control loop refreshes the observed clock and closes admission on
/// revocation, and every port consults this cell before it resolves
/// anything.
pub struct LiveAuthority {
    /// Grant expiry in Unix milliseconds (the window closes here).
    expires_at_unix_ms: u64,
    /// Latest composition-edge clock the control loop observed.
    now_unix_ms: AtomicU64,
    /// Set when the loop revokes the binding (drain or replacement).
    revoked: AtomicBool,
}

impl LiveAuthority {
    /// Binds one admitted grant window at the composition-edge clock.
    #[must_use]
    pub fn bind(expires_at_unix_ms: u64, now_unix_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            expires_at_unix_ms,
            now_unix_ms: AtomicU64::new(now_unix_ms),
            revoked: AtomicBool::new(false),
        })
    }

    /// Records a newly observed composition-edge clock. Monotonic within a
    /// process: a clock that moves backwards never reopens a window.
    pub fn observe(&self, now_unix_ms: u64) {
        self.now_unix_ms.fetch_max(now_unix_ms, Ordering::SeqCst);
    }

    /// Closes admission for this binding. Idempotent; never reopens.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    /// Returns the grant expiry the window closes at.
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// Returns whether the binding is still inside its live window.
    #[must_use]
    pub fn is_live(&self) -> bool {
        !self.revoked.load(Ordering::SeqCst)
            && self.now_unix_ms.load(Ordering::SeqCst) < self.expires_at_unix_ms
    }
}

/// Fail-closed grant-resolution errors. Stable codes plus one stable field
/// name; no paths, digests, or payloads are echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortGrantError {
    /// The installation-approved host image could not be re-proven against
    /// the owner-measured digest, so no launch is staged.
    InstallationBinding,
    /// The admitted grant did not carry its own typed authority epoch.
    AuthorityEpoch,
    /// A retained owner record failed its shape or spelling check.
    OwnerRecord {
        /// Stable field name.
        field: &'static str,
    },
    /// The closed-world admitted manifest could not be assembled from the
    /// admitted records.
    AdmittedWorld {
        /// Stable field name.
        field: &'static str,
    },
    /// The one-shot P-03 permit could not be issued for the derived child
    /// intent, so no process authority exists.
    Permit,
}

impl PortGrantError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InstallationBinding => "PORT_GRANT_INSTALLATION_BINDING",
            Self::AuthorityEpoch => "PORT_GRANT_AUTHORITY_EPOCH",
            Self::OwnerRecord { .. } => "PORT_GRANT_OWNER_RECORD",
            Self::AdmittedWorld { .. } => "PORT_GRANT_ADMITTED_WORLD",
            Self::Permit => "PORT_GRANT_PERMIT",
        }
    }
}

impl fmt::Display for PortGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerRecord { field } | Self::AdmittedWorld { field } => {
                write!(formatter, "{}:{field}", self.code())
            }
            other => formatter.write_str(other.code()),
        }
    }
}

impl std::error::Error for PortGrantError {}

/// The complete local port set resolved for one admitted grant, plus the
/// live authority cell the request loop keeps current and the exact engine
/// binding that was seated.
///
/// Exactly one engine mode is seated here — the isolated parent/child owner
/// this admitted P-03 profile requires. The in-process Wasmtime provider is
/// never paired with it, because pairing both would execute the guest twice.
pub struct ResolvedPortGrant {
    /// Local governor / authority / source / promotion / process /
    /// receipt-verifier ports resolved from the admitted records, with the
    /// single admitted engine mode seated.
    pub ports: RuntimePorts,
    /// The engine binding actually seated, echoed for the loop's receipt.
    pub engine_binding: EngineBinding,
    /// Shared live authority cell for the resolved window.
    pub live: Arc<LiveAuthority>,
}

/// Canonical digest helper: deterministic JSON bytes hashed with SHA-256,
/// the same scheme the receipt family uses. Fail-closed mapping.
fn digest_canonical<T: Serialize>(value: &T) -> Result<Sha256Digest, PortGrantError> {
    canonical_json_bytes(value)
        .map(|bytes| Sha256Digest::of_bytes(&bytes))
        .map_err(|_| PortGrantError::OwnerRecord {
            field: "canonical-bytes",
        })
}

/// Decodes the owner scope the neutral A-12 `AuthorityResolution` contract
/// fixes for the authority port.
///
/// The neutral contract names the observation contract's `ObservationScope`
/// (built on the receipt contract's `WorkScopeId`) as the authority-scope
/// type. This package deliberately holds no dependency on those two contract
/// crates, so the admitted scope travels as the canonical JSON of its own
/// fields and is decoded here through the contract's own strict `serde`
/// surface, with the concrete type inferred from the neutral contract at
/// the construction site. Decoding runs on EVERY resolution, so the scope is
/// re-validated per call instead of being trusted from a cached struct, and
/// the field values are shape-checked before they are encoded.
fn decode_owner_scope<T: serde::de::DeserializeOwned>(
    value: &serde_json::Value,
) -> Result<T, PortError> {
    serde_json::from_value(value.clone()).map_err(|_| PortError::Denied)
}

/// Rejects a blank, oversized, or control-character owner text field using
/// the same rule the contract `text()` validators apply.
fn owner_text(value: &str, field: &'static str) -> Result<(), PortGrantError> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(PortGrantError::OwnerRecord { field });
    }
    Ok(())
}

fn owner_record(field: &'static str) -> PortGrantError {
    PortGrantError::OwnerRecord { field }
}

fn map_integrity(value: &str) -> Result<IntegrityStatus, PortGrantError> {
    match value {
        "VERIFIED" => Ok(IntegrityStatus::Verified),
        "UNVERIFIED" => Ok(IntegrityStatus::Unverified),
        "MODIFIED" => Ok(IntegrityStatus::Modified),
        "CONFLICTED" => Ok(IntegrityStatus::Conflicted),
        _ => Err(owner_record("assurance-integrity")),
    }
}

fn map_freshness(value: &str) -> Result<FreshnessStatus, PortGrantError> {
    match value {
        "CURRENT" => Ok(FreshnessStatus::Current),
        "STALE" => Ok(FreshnessStatus::Stale),
        "UNKNOWN" => Ok(FreshnessStatus::Unknown),
        _ => Err(owner_record("assurance-freshness")),
    }
}

fn map_competence(value: &str) -> Result<CompetenceLevel, PortGrantError> {
    match value {
        "DOMAIN_VERIFIED" => Ok(CompetenceLevel::DomainVerified),
        "ATTRIBUTED" => Ok(CompetenceLevel::Attributed),
        "UNKNOWN" => Ok(CompetenceLevel::Unknown),
        _ => Err(owner_record("assurance-competence")),
    }
}

fn map_independence(value: &str) -> Result<IndependenceLevel, PortGrantError> {
    match value {
        "INDEPENDENT" => Ok(IndependenceLevel::Independent),
        "RELATED" => Ok(IndependenceLevel::Related),
        "COMMON_MODE" => Ok(IndependenceLevel::CommonMode),
        "UNKNOWN" => Ok(IndependenceLevel::Unknown),
        _ => Err(owner_record("assurance-independence")),
    }
}

fn map_privacy(value: &str) -> Result<PrivacyClass, PortGrantError> {
    match value {
        "PUBLIC" => Ok(PrivacyClass::Public),
        "INTERNAL" => Ok(PrivacyClass::Internal),
        "PRIVATE" => Ok(PrivacyClass::Private),
        "SECRET" => Ok(PrivacyClass::Secret),
        "LICENSED" => Ok(PrivacyClass::Licensed),
        _ => Err(owner_record("assurance-privacy")),
    }
}

fn map_taint(value: &str) -> Result<InstructionTaint, PortGrantError> {
    match value {
        "CLEARED" => Ok(InstructionTaint::Cleared),
        "DATA_ONLY" => Ok(InstructionTaint::DataOnly),
        "UNTRUSTED" => Ok(InstructionTaint::Untrusted),
        "COMMAND_LIKE" => Ok(InstructionTaint::CommandLike),
        _ => Err(owner_record("assurance-taint")),
    }
}

fn map_quarantine(value: &str) -> Result<QuarantineState, PortGrantError> {
    match value {
        "NONE" => Ok(QuarantineState::None),
        "REVIEW_REQUIRED" => Ok(QuarantineState::ReviewRequired),
        "QUARANTINED" => Ok(QuarantineState::Quarantined),
        "RELEASED" => Ok(QuarantineState::Released),
        _ => Err(owner_record("assurance-quarantine")),
    }
}

fn map_epistemic_use(value: &str) -> Result<EpistemicUse, PortGrantError> {
    match value {
        "OBSERVATION" => Ok(EpistemicUse::Observation),
        "ATTRIBUTED_INPUT" => Ok(EpistemicUse::AttributedInput),
        "CANDIDATE_EVIDENCE" => Ok(EpistemicUse::CandidateEvidence),
        "VERIFICATION_INPUT" => Ok(EpistemicUse::VerificationInput),
        _ => Err(owner_record("assurance-epistemic")),
    }
}

fn map_effect_ceiling(value: &str) -> Result<EffectCeiling, PortGrantError> {
    match value {
        "READ_ONLY" => Ok(EffectCeiling::ReadOnly),
        "CANDIDATE_ONLY" => Ok(EffectCeiling::CandidateOnly),
        "NO_EXTERNAL_EFFECT" => Ok(EffectCeiling::NoExternalEffect),
        _ => Err(owner_record("assurance-effects")),
    }
}

fn map_generation_state(value: &str) -> Result<ModuleGenerationState, PortGrantError> {
    match value {
        "ready" => Ok(ModuleGenerationState::Ready),
        "active" => Ok(ModuleGenerationState::Active),
        _ => Err(owner_record("work-generation-state")),
    }
}

/// Assembles the closed-world admitted manifest from the owner records and
/// the re-hashed staged bytes. The declared import set is empty, so an
/// undeclared filesystem, network, process, or credential import can never
/// resolve to ambient host access.
fn admitted_manifest(
    material: &ValidatedDispatchMaterial,
    records: &OwnerRecords,
    engine: EngineBinding,
    artifact_digest: Sha256Digest,
) -> Result<ComponentManifest, PortGrantError> {
    let world = |field: &'static str| PortGrantError::AdmittedWorld { field };
    Ok(ComponentManifest {
        component_id: records.component.clone(),
        world: CapabilityId::new(WIT_WORLD).map_err(|_| world("world"))?,
        wit_version: WIT_VERSION.to_owned(),
        guest_target: material.manifest.target.clone(),
        // Re-hashed from the bytes the owner staged, never from the ceiling
        // record's claim.
        artifact_digest,
        interface_digest: typed_wit_digest(),
        source_digest: material.manifest.source_digest.clone(),
        configuration_digest: provider_configuration_digest(),
        state_contract_digest: material.manifest.state_contract_digest.clone(),
        imports: BTreeSet::new(),
        exports: BTreeSet::from([CapabilityId::new(RUN_EXPORT).map_err(|_| world("export"))?]),
        admitted_privacy_classes: records.privacy.clone(),
        required_verifier: records.required_verifier.clone(),
        engine,
    })
}

/// Assembles the admitted module generation from the owner work record.
fn admitted_generation(
    material: &ValidatedDispatchMaterial,
    records: &OwnerRecords,
    fence: &StateFence,
    manifest: &ComponentManifest,
) -> Result<ModuleGeneration, PortGrantError> {
    Ok(ModuleGeneration {
        module_id: ContractId::new(records.component.as_str())
            .map_err(|_| owner_record("component-id"))?,
        generation: ResourceGeneration::new(material.generation)
            .map_err(|_| owner_record("generation"))?,
        artifact_id: ArtifactId::new(manifest.artifact_digest.as_str())
            .map_err(|_| owner_record("artifact-id"))?,
        state: map_generation_state(&material.work.generation_state)?,
        health: records.generation_health,
        state_fence: fence.clone(),
    })
}

/// Assembles the admitted runtime lease from the owner work record.
fn admitted_lease(
    material: &ValidatedDispatchMaterial,
    epoch: &EpochId,
    fence: &StateFence,
) -> RuntimeLease {
    RuntimeLease {
        lease_id: material.work.lease_id.clone(),
        scope_ref: material.work.lease_scope_ref.clone(),
        authority_epoch: epoch.clone(),
        state_fence: fence.clone(),
        // The material binder already refuses every spelling but "active".
        state: LeaseState::Active,
    }
}

/// Assembles the admitted source assurance from the owner assurance record.
fn admitted_assurance(
    material: &ValidatedDispatchMaterial,
    fence: &StateFence,
) -> Result<SourceAssurance, PortGrantError> {
    Ok(SourceAssurance {
        source_ref: material.assurance.source_ref.clone(),
        provenance_ref: material.assurance.provenance_ref.clone(),
        integrity: map_integrity(&material.assurance.integrity)?,
        freshness: map_freshness(&material.assurance.freshness)?,
        competence: map_competence(&material.assurance.competence)?,
        independence: map_independence(&material.assurance.independence)?,
        privacy_class: map_privacy(&material.assurance.privacy_class)?,
        instruction_taint: map_taint(&material.assurance.instruction_taint)?,
        allowed_epistemic_use: material
            .assurance
            .epistemic_use
            .iter()
            .map(|value| map_epistemic_use(value))
            .collect::<Result<Vec<EpistemicUse>, PortGrantError>>()?,
        allowed_effects: material
            .assurance
            .effect_ceilings
            .iter()
            .map(|value| map_effect_ceiling(value))
            .collect::<Result<Vec<EffectCeiling>, PortGrantError>>()?,
        required_verifier: Some(material.assurance.required_verifier.clone()),
        quarantine: map_quarantine(&material.assurance.quarantine)?,
        state_fence: fence.clone(),
    })
}

/// Encodes the admitted owner scope as the canonical JSON of its own fields.
/// The field values are shape-checked first, and the neutral contract
/// re-validates the decoded scope on every resolution.
fn admitted_scope_json(
    material: &ValidatedDispatchMaterial,
) -> Result<serde_json::Value, PortGrantError> {
    owner_text(&material.work.owner, "work-owner")?;
    owner_text(&material.work.work_unit, "work-unit")?;
    owner_text(&material.work.work_scope, "work-scope")?;
    if let Some(task) = material.work.task_ref.as_deref() {
        owner_text(task, "work-task")?;
    }
    Ok(serde_json::json!({
        "work_scope": material.work.work_scope,
        "task_ref": material.work.task_ref,
        "attempt_ref": material.work.work_unit,
        "module_or_route_ref": material.manifest.component_id,
    }))
}

/// Local proxy adapters over the four central owner ports.
///
/// Every retained value is an owner-published record. Each port re-checks
/// the live authority window, re-derives its own receipt digest from the
/// records it retains, and binds the resolution to the exact sealed
/// request. None of them re-decides policy: the neutral runtime validators
/// own content and shape checks.
#[derive(Clone)]
struct AdmittedOwnerPorts {
    live: Arc<LiveAuthority>,
    manifest: ComponentManifest,
    generation: ModuleGeneration,
    lease: RuntimeLease,
    owner: OwnerId,
    work_unit: WorkUnitId,
    /// Canonical JSON of the admitted owner scope; decoded per resolution.
    scope_json: serde_json::Value,
    /// Admitted work-scope identity the scope JSON binds.
    scope_work_scope: String,
    assurance: SourceAssurance,
    limits: InvocationLimits,
    authority_revision: Revision,
    lifecycle_revision: Revision,
    verification_revision: Revision,
    allowed_host_calls: BTreeSet<CapabilityId>,
    allowed_effect_proposals: BTreeSet<CapabilityId>,
    corpus_digest: Sha256Digest,
    expected_result_digest: Sha256Digest,
    expected_effect_digest: Sha256Digest,
    expected_state_delta_digest: Sha256Digest,
    governor_receipt: Sha256Digest,
    authority_receipt: Sha256Digest,
    source_receipt: Sha256Digest,
    promotion_receipt: Sha256Digest,
}

impl AdmittedOwnerPorts {
    /// Assembles the four local proxies from validated owner records.
    fn resolve(
        material: &ValidatedDispatchMaterial,
        records: &OwnerRecords,
        live: Arc<LiveAuthority>,
        fence: &StateFence,
        epoch: &EpochId,
        engine: EngineBinding,
        artifact_digest: Sha256Digest,
    ) -> Result<Self, PortGrantError> {
        let manifest = admitted_manifest(material, records, engine, artifact_digest)?;
        let generation = admitted_generation(material, records, fence, &manifest)?;
        let lease = admitted_lease(material, epoch, fence);
        let assurance = admitted_assurance(material, fence)?;
        let scope_json = admitted_scope_json(material)?;
        let allowed_host_calls = BTreeSet::new();
        let allowed_effect_proposals = BTreeSet::new();
        let governor_receipt = digest_canonical(&(
            &manifest,
            &generation,
            &lease,
            &records.limits,
            records.authority_revision,
            records.lifecycle_revision,
        ))?;
        let authority_receipt = digest_canonical(&(
            &records.owner,
            &records.work_unit,
            &scope_json,
            &allowed_host_calls,
            &allowed_effect_proposals,
        ))?;
        let source_receipt = digest_canonical(&assurance)?;
        let promotion_receipt = digest_canonical(&(
            &records.corpus_digest,
            &records.expected_result_digest,
            &records.expected_effect_digest,
            &records.expected_state_delta_digest,
            UNEVALUATED_VERDICTS,
        ))?;
        Ok(Self {
            live,
            manifest,
            generation,
            lease,
            owner: records.owner.clone(),
            work_unit: records.work_unit.clone(),
            scope_work_scope: material.work.work_scope.clone(),
            scope_json,
            assurance,
            limits: records.limits.clone(),
            authority_revision: records.authority_revision,
            lifecycle_revision: records.lifecycle_revision,
            verification_revision: records.verification_revision,
            allowed_host_calls,
            allowed_effect_proposals,
            corpus_digest: records.corpus_digest.clone(),
            expected_result_digest: records.expected_result_digest.clone(),
            expected_effect_digest: records.expected_effect_digest.clone(),
            expected_state_delta_digest: records.expected_state_delta_digest.clone(),
            governor_receipt,
            authority_receipt,
            source_receipt,
            promotion_receipt,
        })
    }

    /// Closes admission when the grant window ended or the binding was
    /// revoked, so no port can resolve against dead authority.
    fn check_live(&self) -> Result<(), PortError> {
        if self.live.is_live() {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }
}

impl GovernorResolutionPort for AdmittedOwnerPorts {
    fn resolve(&mut self, request: &InvocationRequest) -> Result<GovernorResolution, PortError> {
        self.check_live()?;
        request.validate().map_err(|_| PortError::Denied)?;
        if request.component_id != self.manifest.component_id {
            return Err(PortError::Denied);
        }
        Ok(GovernorResolution {
            manifest: self.manifest.clone(),
            generation: self.generation.clone(),
            lease: self.lease.clone(),
            authority_revision: self.authority_revision,
            lifecycle_revision: self.lifecycle_revision,
            limits: self.limits.clone(),
            resolution_receipt_digest: self.governor_receipt.clone(),
        })
    }
}

impl AuthorityResolutionPort for AdmittedOwnerPorts {
    fn resolve(&mut self, request: &InvocationRequest) -> Result<AuthorityResolution, PortError> {
        self.check_live()?;
        request.validate().map_err(|_| PortError::Denied)?;
        let work_scope = decode_owner_scope(&self.scope_json)?;
        if request.component_id != self.manifest.component_id
            || request.work_unit != self.work_unit
            || request.work_scope_ref.as_str() != self.scope_work_scope
        {
            return Err(PortError::Denied);
        }
        Ok(AuthorityResolution {
            owner: self.owner.clone(),
            work_unit: self.work_unit.clone(),
            work_scope,
            allowed_host_calls: self.allowed_host_calls.clone(),
            allowed_effect_proposals: self.allowed_effect_proposals.clone(),
            resolution_receipt_digest: self.authority_receipt.clone(),
        })
    }
}

impl SourceVerificationPort for AdmittedOwnerPorts {
    fn verify(&mut self, request: &InvocationRequest) -> Result<SourceVerification, PortError> {
        self.check_live()?;
        request.validate().map_err(|_| PortError::Denied)?;
        Ok(SourceVerification {
            assurance: self.assurance.clone(),
            verification_revision: self.verification_revision,
            verification_receipt_digest: self.source_receipt.clone(),
        })
    }
}

impl PromotionVerificationPort for AdmittedOwnerPorts {
    fn verify(&mut self, query: &PromotionQuery) -> Result<PromotionVerification, PortError> {
        self.check_live()?;
        if query.component_id != self.manifest.component_id
            || query.artifact_digest != self.manifest.artifact_digest
            || query.interface_digest != self.manifest.interface_digest
            || query.state_contract_digest != self.manifest.state_contract_digest
            || query.generation != self.generation
        {
            return Err(PortError::Denied);
        }
        Ok(PromotionVerification {
            corpus_digest: self.corpus_digest.clone(),
            expected_result_digest: self.expected_result_digest.clone(),
            expected_effect_digest: self.expected_effect_digest.clone(),
            expected_state_delta_digest: self.expected_state_delta_digest.clone(),
            verification_revision: self.verification_revision,
            shadow: VerificationVerdict::Rejected,
            canary: VerificationVerdict::Rejected,
            rollback: VerificationVerdict::Rejected,
            cutover: VerificationVerdict::Rejected,
            verification_receipt_digest: self.promotion_receipt.clone(),
        })
    }

    /// Revalidates the sealed execution against the retained resolutions and
    /// the actual engine report. P-03 receipts and usage metering stay the
    /// process and engine owners' to verify; this compares only the digests
    /// the neutral facade derives and the admitted oracle values.
    fn verify_execution(
        &mut self,
        invocation: &EngineInvocation,
        report: &EngineReport,
        derived: &DerivedExecutionEvidence,
    ) -> Result<(), PortError> {
        self.check_live()?;
        let work_scope = decode_owner_scope(&self.scope_json)?;
        let exact = invocation.manifest == self.manifest
            && invocation.imports == self.manifest.imports
            && invocation.exports == self.manifest.exports
            && invocation.generation == self.generation
            && invocation.lease == self.lease
            && invocation.owner == self.owner
            && invocation.work_unit == self.work_unit
            && invocation.work_scope == work_scope
            && invocation.authority_revision == self.authority_revision
            && invocation.lifecycle_revision == self.lifecycle_revision
            && invocation.source_assurance == self.assurance
            && invocation.source_verification_revision == self.verification_revision
            && invocation.promotion_verification_revision == self.verification_revision
            && invocation.allowed_host_calls == self.allowed_host_calls
            && invocation.allowed_effect_proposals == self.allowed_effect_proposals
            && invocation.limits == self.limits
            && invocation.conformance_corpus_digest == self.corpus_digest
            && invocation.governor_resolution_receipt_digest == self.governor_receipt
            && invocation.authority_resolution_receipt_digest == self.authority_receipt
            && invocation.source_verification_receipt_digest == self.source_receipt
            && invocation.promotion_verification_receipt_digest == self.promotion_receipt
            && invocation.state_contract_digest == self.manifest.state_contract_digest
            && derived.result_digest == Sha256Digest::of_bytes(&report.output)
            && derived.effect_digest
                == Sha256Digest::of_bytes(
                    &canonical_json_bytes(&report.proposed_effects)
                        .map_err(|_| PortError::Denied)?,
                )
            && derived.state_delta_digest == Sha256Digest::of_bytes(&report.observed_state_delta);
        if exact {
            Ok(())
        } else {
            Err(PortError::Denied)
        }
    }
}

/// Resolves the local admitted port set for one owner-published grant.
///
/// The closed authenticated authorization message is the validated delivery
/// set. This validates it against current installation state (the installed
/// image is re-hashed against the owner-measured digest before any launch is
/// staged) and against the grant's own live epoch and window, then
/// constructs local proxy adapters to the authority, source, promotion, and
/// process owners and seats exactly one admitted engine mode.
///
/// # Errors
///
/// Returns [`PortGrantError`] when the installation binding, the grant
/// epoch, an owner record spelling, the closed-world manifest, or the
/// one-shot process permit fails closed.
pub fn resolve_kernel_port_grant(
    material: &ValidatedDispatchMaterial,
    binding: &WasmHostBinaryBinding,
    now_ms: u64,
) -> Result<ResolvedPortGrant, PortGrantError> {
    // Installation state: the owner-measured host digest is proven against
    // the bytes actually on disk before anything is staged.
    let installed =
        resolve_installed_binary(binding).map_err(|_| PortGrantError::InstallationBinding)?;
    let host_digest = installed.digest().clone();
    let working_directory = installed
        .path()
        .parent()
        .ok_or(PortGrantError::InstallationBinding)?
        .to_path_buf();
    let epoch: EpochId = serde_json::from_str(&material.grant.authority_epoch_json)
        .map_err(|_| PortGrantError::AuthorityEpoch)?;
    let generation =
        ResourceGeneration::new(material.generation).map_err(|_| owner_record("generation"))?;
    let fence = StateFence::new(epoch.clone(), generation);
    let records = assemble_owner_records(material).map_err(|error: DriveError| match error {
        DriveError::Admission { field } => owner_record(field),
        _ => owner_record("owner-records"),
    })?;
    let live = LiveAuthority::bind(material.grant.expires_at, now_ms);
    let engine_binding = EngineBinding {
        implementation_id: ISOLATED_CHILD_IMPLEMENTATION_ID.to_owned(),
        exact_version: PINNED_WASMTIME_VERSION.to_owned(),
        engine_artifact_digest: host_digest.clone(),
        engine_configuration_digest: provider_configuration_digest(),
        wit_interface_digest: typed_wit_digest(),
    };
    // P-03 process authority over the real executor, gated by the
    // owner-derived one-shot permit for exactly the derived child intent.
    let authority =
        ParentDispatchAuthority::activate(material, &epoch).map_err(|_| PortGrantError::Permit)?;
    let intent = derive_parent_intent(material, installed.path(), &host_digest, &working_directory)
        .map_err(|_| PortGrantError::Permit)?;
    let issued = authority
        .issue_permit(&intent, now_ms)
        .map_err(|_| PortGrantError::Permit)?;
    let executor = Arc::new(WindowsProcessExecutor::new(Arc::new(authority)));
    let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(BoundedParentSink::new());
    let artifact_digest = Sha256Digest::of_bytes(&material.artifact_bytes);
    let owners = AdmittedOwnerPorts::resolve(
        material,
        &records,
        Arc::clone(&live),
        &fence,
        &epoch,
        engine_binding.clone(),
        artifact_digest.clone(),
    )?;
    let process = WasmP03ProcessAdapter::new(Arc::clone(&executor), Arc::clone(&sink));
    process
        .stage_admitted_request(issued)
        .map_err(|_| PortGrantError::Permit)?;
    // The verifier-side adapter never stages: its slot stays empty, so it
    // observes receipts and evidence but can never launch a second child.
    let verifier = WasmP03ProcessAdapter::new(Arc::clone(&executor), Arc::clone(&sink));
    let engine = IsolatedChildEngine::new(
        executor,
        sink,
        engine_binding.clone(),
        artifact_digest,
        provider_configuration_digest(),
    );
    // One retained admission, four local proxies: the slots are separate
    // trait objects over the same owner records, each with its own mutable
    // resolution state, and all four share the one live authority cell.
    let ports = RuntimePorts::new(
        Box::new(owners.clone()),
        Box::new(owners.clone()),
        Box::new(owners.clone()),
        Box::new(owners),
        Box::new(process),
        Box::new(verifier),
        Box::new(engine),
    );
    Ok(ResolvedPortGrant {
        ports,
        engine_binding,
        live,
    })
}
