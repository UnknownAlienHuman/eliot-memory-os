//! I1.9: the immutable `KernelExecutionManifest` copied into the Generation
//! Registry, and the sealed authorization that binds process launch, replay,
//! route cutover, readiness evaluation, resource limits and the bounded restart
//! budget to that manifest's identity.
//!
//! I1.9 splits "Module Registry" into three owners. The Module Catalog and its
//! lifecycle/admission receipts belong to the Governor; this module owns only
//! the Generation Registry copy, which is a technical execution projection and
//! never desired-state policy. That lets Kernel restart the exact previously
//! admitted generation while the daemon is unavailable, within the recorded
//! restart class only.
//!
//! Two properties are load bearing and both are enforced by code rather than
//! by a comment:
//!
//! * `KernelExecutionManifest::admit` is the only validating construction
//!   path. It takes a Governor-issued [`AdmittedModuleGeneration`] and refuses
//!   a projection whose effect ceiling exceeds the admitted ceiling or whose
//!   allowed scopes are not a subset of the admitted ones. The type declares no
//!   update, widen or re-authorize method, and `validate` recomputes
//!   `manifest_sha256` over the recorded schema version, admission and
//!   projection, so a hand-built record with any changed field is reported as a
//!   durable integrity problem instead of being accepted.
//! * [`BoundKernelExecutionManifest`] is sealed: private fields, no
//!   `Deserialize`, and one private constructor called only by
//!   `verify_kernel_execution_restart` after the manifest identity, the exact
//!   candidate launch binding, the Authority Epoch, the I1.12 compatibility
//!   evidence and the recorded restart budget have all been checked. It is the
//!   only value a launch, replay or cutover consumer may treat as
//!   manifest-bound authority.
//!
//! `eliot-ors` has no dependency on `eliot-module-registry`, so the
//! `restart_authorization_class` vocabulary is declared here rather than
//! imported.
//!
//! This module is pure domain logic: it owns no process, store handle, or
//! canonical memory, and it issues no admission of its own.

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, canonical_json_bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::cutover_ownership::{CapabilityRouteScope, StateMigrationDecision};
use crate::model::{
    OpaqueLabel, OperationIdentity, OrsError, sha256_hex, validate_digest, validate_text,
};
use crate::versioned_artifact::CompatibilityEvidence;

/// Durable schema version of the Generation Registry manifest record (I1.9).
pub const KERNEL_EXECUTION_MANIFEST_SCHEMA_VERSION: u16 = 1;

/// Restart authorization class recorded on the manifest (I1.9).
///
/// The three values are the I1.9 vocabulary and they are not interchangeable:
/// `read_rebuild` is never effect capable, `effect_exact_lease` is effect
/// capable without needing a fresh Catalog view for the restart itself, and
/// `current_catalog_required` refuses whenever the current view is not current.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RestartAuthorizationClass {
    /// Read-only/rebuildable generation. It may restart from the exact
    /// recorded manifest under the recorded bounded restart budget and never
    /// carries effect authority.
    ReadRebuild,
    /// Effect-capable generation. It may resume only exact already-authorized
    /// operations covered by an unexpired operation lease, and new effect
    /// admission requires a current Module Catalog/Policy view.
    EffectExactLease,
    /// Effect-capable generation whose normal-effect restart authorization
    /// itself requires a current Module Catalog/Policy view.
    CurrentCatalogRequired,
}

impl RestartAuthorizationClass {
    /// The I1.9 wire spelling of the class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadRebuild => "read_rebuild",
            Self::EffectExactLease => "effect_exact_lease",
            Self::CurrentCatalogRequired => "current_catalog_required",
        }
    }

    /// Whether the class can ever run normal-effect service.
    #[must_use]
    pub const fn is_effect_capable(self) -> bool {
        !matches!(self, Self::ReadRebuild)
    }

    /// Whether the class admits normal-effect service for the observed current
    /// Module Catalog/Policy view.
    #[must_use]
    pub const fn admits_normal_effect_service(self, catalog_view: CatalogPolicyView) -> bool {
        match self {
            Self::ReadRebuild => false,
            Self::EffectExactLease => true,
            Self::CurrentCatalogRequired => matches!(catalog_view, CatalogPolicyView::Current),
        }
    }
}

/// Availability of the Kernel's current Module Catalog/Policy view (I1.9).
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CatalogPolicyView {
    /// The view is present and current.
    Current,
    /// The view is present but no longer current.
    Stale,
    /// The view is unavailable.
    Unavailable,
}

/// Acknowledgement state of a revocation event (I1.9).
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RevocationAcknowledgement {
    /// No revocation event is outstanding.
    None,
    /// A revocation event was delivered and acknowledged, so the affected
    /// authority is revoked and cannot be restored.
    Acknowledged,
    /// A revocation event is outstanding and unacknowledged, so the affected
    /// authority is unusable until the event is delivered.
    Unacknowledged,
}

/// Acknowledgement state of the delivery path for an authorized effect (I1.9).
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EffectDeliveryAcknowledgement {
    /// Delivery is fully acknowledged.
    Acknowledged,
    /// A delivery gap is open, so the outcome of the affected effect is not
    /// proven.
    GapOpen,
}

/// Authority/effect ceiling of one generation (I1.9).
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ManifestEffectCeiling {
    /// Read/rebuild only: no external effect and no canonical write admission.
    ReadRebuild,
    /// Candidate/diagnostic only: effect-free.
    CandidateNoEffect,
    /// External effect only through an unexpired effect operation lease.
    EffectExactLease,
}

impl ManifestEffectCeiling {
    const fn rank(self) -> u8 {
        match self {
            Self::ReadRebuild => 0,
            Self::CandidateNoEffect => 1,
            Self::EffectExactLease => 2,
        }
    }

    /// Whether this ceiling admits a request that needs `requested`.
    #[must_use]
    pub const fn admits(self, requested: Self) -> bool {
        requested.rank() <= self.rank()
    }
}

/// One start-order coordinate of the manifest's dependency order (I1.9).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestDependencyEntry {
    /// Owning module identity that must be started.
    pub module_id: String,
    /// Position in the start order. Two dependencies never share a position.
    pub startup_order: u32,
}

impl ManifestDependencyEntry {
    /// Validates the module identity text.
    fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            &self.module_id,
            "kernel_execution_manifest_dependency_module_id",
        )
    }
}

/// Job Object and resource limits of one generation (I1.6, I1.9).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestResourceLimits {
    /// Declared Job Object policy token for this generation.
    pub job_object_policy: String,
    /// Hard process-count ceiling for the generation's Job Object.
    pub max_processes: u32,
    /// Hard working-set byte ceiling.
    pub max_working_set_bytes: u64,
    /// CPU rate-control percentage in `1..=100`.
    pub cpu_rate_control_percent: u16,
}

impl ManifestResourceLimits {
    /// Validates the Job Object policy token and the three numeric ceilings.
    fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            &self.job_object_policy,
            "kernel_execution_manifest_job_object_policy",
        )?;
        if self.max_processes == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_manifest_max_processes",
                reason: "must be greater than zero",
            });
        }
        if self.max_working_set_bytes == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_manifest_max_working_set_bytes",
                reason: "must be greater than zero",
            });
        }
        if !(1..=100).contains(&self.cpu_rate_control_percent) {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_manifest_cpu_rate_control_percent",
                reason: "must be between 1 and 100",
            });
        }
        Ok(())
    }
}

/// Bounded restart budget and quarantine rule of one generation (I1.4, I1.9).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRestartBudget {
    /// Restarts the recorded generation is permitted.
    pub max_restarts: u32,
    /// Quarantine rule applied once the recorded budget is spent.
    pub quarantine_rule: String,
}

impl ManifestRestartBudget {
    /// Validates a non-zero budget and a declared quarantine rule.
    fn validate(&self) -> Result<(), OrsError> {
        if self.max_restarts == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_manifest_max_restarts",
                reason: "must be greater than zero",
            });
        }
        validate_text(
            &self.quarantine_rule,
            "kernel_execution_manifest_quarantine_rule",
        )
    }
}

/// The exact recorded launch binding of one generation (I1.9).
///
/// A consumer must launch exactly this. The values are copied out of the
/// immutable manifest by `verify_kernel_execution_restart`, so a consumer
/// cannot substitute its own artifact, config or protocol hash, or its own
/// start command, for the recorded ones.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelLaunchBinding {
    /// Recorded artifact digest.
    pub artifact_sha256: String,
    /// Recorded config digest.
    pub config_sha256: String,
    /// Recorded protocol digest.
    pub protocol_sha256: String,
    /// Recorded start command.
    pub start_command: String,
}

impl KernelLaunchBinding {
    /// Validates the three digests and the start command.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.artifact_sha256, "kernel_launch_artifact_sha256")?;
        validate_digest(&self.config_sha256, "kernel_launch_config_sha256")?;
        validate_digest(&self.protocol_sha256, "kernel_launch_protocol_sha256")?;
        validate_text(&self.start_command, "kernel_launch_start_command")
    }
}

/// The Governor-issued Module Catalog admission that authorizes one manifest.
///
/// This is the only input `KernelExecutionManifest::admit` accepts. The
/// accepted Module Catalog revision, the Policy revision, the
/// lifecycle/admission receipt identity, the admitted effect ceiling and the
/// admitted route scopes are recorded here, so a manifest cannot claim a
/// ceiling or a scope the Catalog did not admit for it.
///
/// `admission_receipt` is a plain `String` rather than an `OpaqueLabel` on
/// purpose: a receipt-less manifest has to stay representable so that
/// `verify_kernel_execution_restart` can detect it and mark the affected
/// generation degraded, instead of the record simply failing to decode.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedModuleGeneration {
    /// Admitted module identity.
    pub module_id: String,
    /// Admitted generation identity.
    pub generation: ResourceGeneration,
    /// Authority Epoch the admission was issued under.
    pub authority_epoch: AuthorityEpoch,
    /// Accepted Module Catalog revision. Must be non-zero.
    pub catalog_revision: u64,
    /// Policy revision that was current at admission. Must be non-zero.
    pub policy_revision: u64,
    /// Governor-issued lifecycle/admission receipt identity.
    pub admission_receipt: String,
    /// Restart authorization class the Catalog admitted.
    pub restart_authorization_class: RestartAuthorizationClass,
    /// Effect ceiling the Catalog admitted. The manifest may not exceed it.
    pub admitted_effect_ceiling: ManifestEffectCeiling,
    /// Route scopes the Catalog admitted. The manifest's allowed scopes must be
    /// a subset of this set.
    pub admitted_allowed_scopes: Vec<CapabilityRouteScope>,
}

impl AdmittedModuleGeneration {
    /// Validates the admitted identity, revisions, receipt and route scopes.
    fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "kernel_execution_manifest_module_id")?;
        if self.catalog_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_manifest_catalog_revision",
                reason: "must be greater than zero",
            });
        }
        if self.policy_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_manifest_policy_revision",
                reason: "must be greater than zero",
            });
        }
        validate_text(
            &self.admission_receipt,
            "kernel_execution_manifest_admission_receipt",
        )?;
        validate_unique_scopes(
            &self.admitted_allowed_scopes,
            "kernel_execution_manifest_admitted_allowed_scopes",
        )
    }
}

/// The technical execution projection of one admitted generation (I1.9).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelExecutionProjection {
    /// Artifact digest of the immutable bytes to run.
    pub artifact_sha256: String,
    /// Config digest of the exact configuration to run with.
    pub config_sha256: String,
    /// Protocol digest of the versioned protocol the generation speaks.
    pub protocol_sha256: String,
    /// Exact start command.
    pub start_command: String,
    /// Dependency start order.
    pub dependency_order: Vec<ManifestDependencyEntry>,
    /// Job Object and resource limits.
    pub resource_limits: ManifestResourceLimits,
    /// Health/readiness contract reference used for readiness evaluation.
    pub health_readiness_contract_ref: String,
    /// Bounded restart budget and quarantine rule.
    pub restart_budget: ManifestRestartBudget,
    /// Authority/effect ceiling applied to this generation.
    pub effect_ceiling: ManifestEffectCeiling,
    /// Route scopes this generation may act in.
    pub allowed_scopes: Vec<CapabilityRouteScope>,
    /// Checkpoint/state-class behavior across a cutover.
    pub state_class_behavior: StateMigrationDecision,
}

impl KernelExecutionProjection {
    /// Validates the recorded hashes, command, order, limits, budget, scopes
    /// and state-class behavior.
    fn validate(&self) -> Result<(), OrsError> {
        validate_digest(&self.artifact_sha256, "kernel_execution_artifact_sha256")?;
        validate_digest(&self.config_sha256, "kernel_execution_config_sha256")?;
        validate_digest(&self.protocol_sha256, "kernel_execution_protocol_sha256")?;
        validate_text(&self.start_command, "kernel_execution_start_command")?;
        let mut modules = BTreeSet::new();
        let mut positions = BTreeSet::new();
        for dependency in &self.dependency_order {
            dependency.validate()?;
            if !modules.insert(dependency.module_id.as_str()) {
                return Err(OrsError::InvalidField {
                    field: "kernel_execution_dependency_order",
                    reason: "a module may appear at most once in the start order",
                });
            }
            if !positions.insert(dependency.startup_order) {
                return Err(OrsError::InvalidField {
                    field: "kernel_execution_dependency_order",
                    reason: "two dependencies may not share a start position",
                });
            }
        }
        self.resource_limits.validate()?;
        validate_text(
            &self.health_readiness_contract_ref,
            "kernel_execution_health_readiness_contract_ref",
        )?;
        self.restart_budget.validate()?;
        validate_unique_scopes(
            &self.allowed_scopes,
            "kernel_execution_manifest_allowed_scopes",
        )
    }
}

#[derive(Serialize)]
struct KernelExecutionManifestCore<'a> {
    schema_version: u16,
    admission: &'a AdmittedModuleGeneration,
    projection: &'a KernelExecutionProjection,
}

/// Versioned immutable `KernelExecutionManifest` owned by the Generation
/// Registry (I1.9).
///
/// Carries every field I1.9 requires: the artifact/config/protocol hashes, the
/// start command and dependency order, the Job Object/resource limits, the
/// health/readiness contract, the restart budget and quarantine rule, the
/// `restart_authorization_class`, the authority/effect ceiling and allowed
/// scopes, the checkpoint/state-class behavior, and the accepted Module
/// Catalog revision with its lifecycle/admission receipt.
///
/// `admit` is the only validating construction path, and a hand-built record
/// is refused by `validate` unless `manifest_sha256` recomputes over the
/// recorded schema version, admission and projection. The type declares no
/// update, widen or re-authorize method, so a changed field cannot be accepted
/// silently.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelExecutionManifest {
    /// Durable schema version of this record.
    pub schema_version: u16,
    /// The Governor-issued admission this manifest was copied from.
    pub admission: AdmittedModuleGeneration,
    /// The technical execution projection.
    pub projection: KernelExecutionProjection,
    /// Digest binding the schema version, admission and projection.
    pub manifest_sha256: String,
}

impl KernelExecutionManifest {
    /// Copies one Governor-admitted generation into the Generation Registry.
    ///
    /// This is the only validating construction path. It refuses a projection
    /// whose effect ceiling exceeds
    /// `admission.admitted_effect_ceiling`, a projection whose allowed scopes
    /// are not a subset of `admission.admitted_allowed_scopes`, and an
    /// effect-capable class with no allowed scope at all, so neither creation
    /// nor scope widening can be performed from the Kernel side alone.
    pub fn admit(
        admission: AdmittedModuleGeneration,
        projection: KernelExecutionProjection,
    ) -> Result<Self, OrsError> {
        let manifest = Self {
            schema_version: KERNEL_EXECUTION_MANIFEST_SCHEMA_VERSION,
            admission,
            projection,
            manifest_sha256: String::new(),
        };
        manifest.admission.validate()?;
        manifest.projection.validate()?;
        manifest.check_admitted_bounds()?;
        let mut bound = manifest;
        bound.manifest_sha256 = bound.identity_sha256()?;
        bound.validate()?;
        Ok(bound)
    }

    /// Whether the recorded manifest carries a Governor admission receipt, a
    /// non-zero accepted Module Catalog revision and a non-zero Policy revision.
    ///
    /// A manifest that does not is receipt-less: it was never admitted, so it
    /// cannot authorize a restart.
    #[must_use]
    pub fn has_governor_admission(&self) -> bool {
        !self.admission.admission_receipt.trim().is_empty()
            && self.admission.catalog_revision != 0
            && self.admission.policy_revision != 0
    }

    /// The exact recorded launch binding of this manifest.
    pub fn launch_binding(&self) -> KernelLaunchBinding {
        KernelLaunchBinding {
            artifact_sha256: self.projection.artifact_sha256.clone(),
            config_sha256: self.projection.config_sha256.clone(),
            protocol_sha256: self.projection.protocol_sha256.clone(),
            start_command: self.projection.start_command.clone(),
        }
    }

    /// The recorded restart authorization class.
    #[must_use]
    pub fn restart_authorization_class(&self) -> RestartAuthorizationClass {
        self.admission.restart_authorization_class
    }

    /// The route scopes this generation is allowed to act in.
    #[must_use]
    pub fn allowed_scopes(&self) -> &[CapabilityRouteScope] {
        &self.projection.allowed_scopes
    }

    /// Validates the record shape, the admitted bounds and the bound digest.
    pub fn validate(&self) -> Result<(), OrsError> {
        if self.schema_version != KERNEL_EXECUTION_MANIFEST_SCHEMA_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.schema_version));
        }
        self.admission.validate()?;
        self.projection.validate()?;
        self.check_admitted_bounds()?;
        validate_digest(&self.manifest_sha256, "kernel_execution_manifest_sha256")?;
        if self.identity_sha256()? != self.manifest_sha256 {
            return Err(OrsError::IntegrityProblem {
                record_type: "kernel_execution_manifest",
                reason: "manifest hash does not bind the recorded admission and projection"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Refuses an effect ceiling or an allowed scope the Catalog did not admit.
    fn check_admitted_bounds(&self) -> Result<(), OrsError> {
        if !self
            .admission
            .admitted_effect_ceiling
            .admits(self.projection.effect_ceiling)
        {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_manifest_effect_ceiling",
                reason: "must not exceed the admitted effect ceiling",
            });
        }
        for scope in &self.projection.allowed_scopes {
            let admitted = self
                .admission
                .admitted_allowed_scopes
                .iter()
                .any(|candidate| candidate.route_scope_hash == scope.route_scope_hash);
            if !admitted {
                return Err(OrsError::InvalidField {
                    field: "kernel_execution_manifest_allowed_scopes",
                    reason: "must be a subset of the admitted route scopes",
                });
            }
        }
        if self
            .admission
            .restart_authorization_class
            .is_effect_capable()
            && self.projection.allowed_scopes.is_empty()
        {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_manifest_allowed_scopes",
                reason: "an effect-capable generation must record at least one allowed scope",
            });
        }
        Ok(())
    }

    /// Digest over the schema version, the admission and the projection.
    fn identity_sha256(&self) -> Result<String, OrsError> {
        let core = KernelExecutionManifestCore {
            schema_version: self.schema_version,
            admission: &self.admission,
            projection: &self.projection,
        };
        let bytes =
            canonical_json_bytes(&core).map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

fn validate_unique_scopes(
    scopes: &[CapabilityRouteScope],
    field: &'static str,
) -> Result<(), OrsError> {
    let mut seen = BTreeSet::new();
    for scope in scopes {
        scope.validate()?;
        if !seen.insert(scope.route_scope_hash.as_str()) {
            return Err(OrsError::InvalidField {
                field,
                reason: "a route scope may be recorded at most once",
            });
        }
    }
    Ok(())
}

/// The exact request whose authorization must be bound to one manifest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelExecutionRestartRequest {
    /// Affected module identity.
    pub module_id: String,
    /// Affected generation identity.
    pub generation: ResourceGeneration,
    /// The manifest digest this request is bound to.
    pub bound_manifest_sha256: String,
    /// The exact candidate the caller intends to run. It must equal the
    /// recorded launch binding.
    pub candidate: KernelLaunchBinding,
    /// The caller's current Authority Epoch.
    pub current_authority_epoch: AuthorityEpoch,
    /// The caller's current accepted Module Catalog revision.
    pub current_catalog_revision: u64,
    /// The caller's current Policy revision.
    pub current_policy_revision: u64,
    /// Availability of the current Module Catalog/Policy view.
    pub catalog_view: CatalogPolicyView,
    /// Acknowledgement state of the latest revocation event.
    pub revocation: RevocationAcknowledgement,
    /// Acknowledgement state of the delivery path.
    pub delivery: EffectDeliveryAcknowledgement,
    /// I1.12 compatibility evidence observed for the candidate.
    pub compatibility: CompatibilityEvidence,
    /// Restarts already spent against the recorded bounded restart budget.
    pub restarts_spent: u32,
    /// Observation time of the decision in Unix milliseconds.
    pub observed_at_ms: i64,
}

impl KernelExecutionRestartRequest {
    /// Validates the request's own identity, binding, revisions and clock.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "kernel_execution_restart_module_id")?;
        validate_digest(
            &self.bound_manifest_sha256,
            "kernel_execution_restart_bound_manifest_sha256",
        )?;
        self.candidate.validate()?;
        if self.current_catalog_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_restart_current_catalog_revision",
                reason: "must be greater than zero",
            });
        }
        if self.current_policy_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_restart_current_policy_revision",
                reason: "must be greater than zero",
            });
        }
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_restart_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Preserved evidence for one restart decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRestartEvidence {
    /// Affected module identity.
    pub module_id: String,
    /// Affected generation identity.
    pub generation: ResourceGeneration,
    /// The manifest digest the request was bound to.
    pub bound_manifest_sha256: String,
    /// The recorded manifest digest, when a manifest was found.
    pub recorded_manifest_sha256: Option<String>,
    /// The recorded restart authorization class, when a structurally valid
    /// manifest was found.
    pub restart_authorization_class: Option<RestartAuthorizationClass>,
}

/// Sealed manifest-bound execution authorization.
///
/// This is the only value a launch, replay, route-cutover, readiness,
/// resource-limit or restart-budget consumer may treat as manifest-bound
/// authority. It is produced exclusively by
/// `verify_kernel_execution_restart`: its manifest field is private, it has no
/// public constructor, and it deliberately has no `Deserialize`
/// implementation, so an ordinary caller can neither assemble an accepted
/// typestate from public fields nor recover one from serialized bytes. The
/// verifier issues one only after the manifest identity, the exact candidate
/// launch binding, the Authority Epoch, the I1.12 compatibility evidence and
/// the recorded restart budget have all been checked.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundKernelExecutionManifest {
    manifest: KernelExecutionManifest,
}

impl BoundKernelExecutionManifest {
    /// Issues the sealed binding. Only the module's verifier may call it.
    const fn verified(manifest: KernelExecutionManifest) -> Self {
        Self { manifest }
    }

    /// The exact immutable manifest the verifier accepted.
    pub const fn manifest(&self) -> &KernelExecutionManifest {
        &self.manifest
    }

    /// The recorded manifest digest this binding is bound to.
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest.manifest_sha256
    }

    /// The exact recorded launch binding the consumer must use.
    pub fn launch_binding(&self) -> KernelLaunchBinding {
        self.manifest.launch_binding()
    }

    /// The recorded Job Object and resource limits the consumer must apply.
    pub const fn resource_limits(&self) -> &ManifestResourceLimits {
        &self.manifest.projection.resource_limits
    }

    /// The recorded bounded restart budget and quarantine rule.
    pub const fn restart_budget(&self) -> &ManifestRestartBudget {
        &self.manifest.projection.restart_budget
    }

    /// The recorded health/readiness contract reference.
    pub fn health_readiness_contract_ref(&self) -> &str {
        &self.manifest.projection.health_readiness_contract_ref
    }

    /// The recorded checkpoint/state-class behavior.
    pub const fn state_class_behavior(&self) -> StateMigrationDecision {
        self.manifest.projection.state_class_behavior
    }

    /// The recorded restart authorization class.
    pub const fn restart_authorization_class(&self) -> RestartAuthorizationClass {
        self.manifest.admission.restart_authorization_class
    }
}

/// The service one restart decision may run as.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum KernelServiceAdmission {
    /// Nothing is started. The affected generation is marked degraded and the
    /// defect is escalated; it is not restarted into normal-effect service.
    None,
    /// Shadow/no-effect diagnostics only. The candidate may be observed and may
    /// report diagnostics, but it holds no external effect and no canonical
    /// write admission.
    ShadowDiagnosticsOnly(BoundKernelExecutionManifest),
    /// Normal read/rebuild service under the exact recorded binding. This
    /// variant is only ever produced for a `read_rebuild` manifest, so a
    /// read/rebuild manifest and an effect-capable one are not interchangeable.
    ReadRebuildService(BoundKernelExecutionManifest),
    /// Normal effect-capable service under the exact recorded binding. Effect
    /// dispatch stays gated on an unexpired
    /// [`crate::EffectOperationLease`](crate::EffectOperationLease); the binding
    /// itself authorizes no effect.
    EffectService(BoundKernelExecutionManifest),
}

/// Why one generation was not restarted into normal-effect service.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum KernelReconciliationKind {
    /// No manifest is recorded for the affected generation.
    ManifestAbsent,
    /// The recorded manifest does not bind the presented identity or digest.
    ManifestIdentityMismatch,
    /// The candidate's launch binding is not the exact recorded one.
    ManifestCandidateBindingMismatch,
    /// The candidate failed the I1.12 durable-format or epoch-lineage evidence.
    ManifestIncompatible,
    /// A revocation event was acknowledged, so the recorded manifest is revoked.
    ManifestRevoked,
    /// The recorded manifest carries no accepted Catalog/Policy revision or no
    /// lifecycle/admission receipt.
    ManifestReceiptless,
    /// The recorded manifest belongs to a different Authority Epoch.
    ManifestForeignEpoch,
    /// The recorded bounded restart budget is spent.
    ManifestRestartBudgetExhausted,
    /// The recorded manifest does not satisfy its own shape.
    ManifestInvalid,
    /// The Module Catalog/Policy view is not current, so the effect-capable
    /// generation is limited to shadow/no-effect diagnostics.
    ManifestCatalogPolicyStale,
    /// A revocation event is outstanding and unacknowledged.
    ManifestRevocationUnacknowledged,
    /// A delivery gap is open for the affected generation.
    ManifestDeliveryGapOpen,
    /// The recorded manifest is not effect capable, so it can admit no effect
    /// operation lease.
    ManifestNotEffectCapable,
    /// No effect operation lease is recorded for the replayed effect.
    EffectLeaseAbsent,
    /// The lease does not satisfy its own shape.
    EffectLeaseInvalid,
    /// The lease covers a different operation identity.
    EffectOperationIdentityMismatch,
    /// The lease covers a different effect receipt.
    EffectReceiptMismatch,
    /// The lease covers a different route scope.
    EffectScopeMismatch,
    /// The lease was admitted under a different manifest identity or digest.
    EffectManifestMismatch,
    /// The lease belongs to a different Authority Epoch.
    EffectEpochMismatch,
    /// The admitting Catalog or Policy revision is no longer current.
    EffectCatalogPolicyStale,
    /// The lease is expired at the observation time.
    EffectLeaseExpired,
    /// The lease was revoked.
    EffectLeaseRevoked,
    /// A revocation event for the lease is outstanding and unacknowledged.
    EffectLeaseRevocationUnacknowledged,
    /// The lease is not in a state that authorizes an effect.
    EffectLeaseNotActive,
    /// A delivery gap is open for the replayed effect.
    EffectDeliveryGapOpen,
}

/// One durable operational item to persist rather than discard.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReconciliationItem {
    /// Why the affected generation is degraded, shadowed or denied.
    pub kind: KernelReconciliationKind,
    /// Affected module identity.
    pub module_id: String,
    /// Affected generation identity.
    pub generation: ResourceGeneration,
    /// The manifest digest the request was bound to.
    pub bound_manifest_sha256: Option<String>,
    /// The recorded manifest digest, when a manifest was found.
    pub recorded_manifest_sha256: Option<String>,
    /// The effect operation lease identity, when a lease was found.
    pub lease_id: Option<OpaqueLabel>,
    /// The operation identity the attempt claimed.
    pub operation_id: Option<OperationIdentity>,
    /// Observation time of the item in Unix milliseconds.
    pub observed_at_ms: i64,
}

/// One restart/replay/launch decision over the immutable manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KernelRestartDecision {
    /// Which service, if any, the request may run as.
    pub admission: KernelServiceAdmission,
    /// Preserved evidence for the decision.
    pub evidence: KernelRestartEvidence,
    /// Operational items to persist. Empty only for a clean
    /// `ReadRebuildService` or `EffectService` admission; a missing, stale,
    /// incompatible, revoked or receipt-less manifest, an exhausted restart
    /// budget and a shadowed effect-capable candidate all produce at least one
    /// item, so degradation is always visible and always escalated.
    pub reconciliation: Vec<KernelReconciliationItem>,
}

impl KernelRestartDecision {
    /// Builds a decision that starts nothing and escalates one defect.
    fn escalated(
        admission: KernelServiceAdmission,
        evidence: KernelRestartEvidence,
        item: KernelReconciliationItem,
    ) -> Self {
        Self {
            admission,
            evidence,
            reconciliation: vec![item],
        }
    }

    /// Builds a decision that admits normal service without escalation.
    fn admitted(admission: KernelServiceAdmission, evidence: KernelRestartEvidence) -> Self {
        Self {
            admission,
            evidence,
            reconciliation: Vec::new(),
        }
    }

    /// Whether the decision starts nothing at all.
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        matches!(self.admission, KernelServiceAdmission::None)
    }
}

/// Verifies one restart, replay, cutover, readiness, resource-limit or
/// restart-budget request against the immutable manifest bound to the affected
/// generation.
///
/// The check is a pure read: it mutates no durable state, starts nothing and
/// re-derives the current disposition of the manifest it is given. The
/// caller's current Authority Epoch, Catalog/Policy revisions and view,
/// revocation and delivery acknowledgement state, I1.12 compatibility
/// evidence and restart spend are the authority being checked against.
///
/// The order of the checks is load bearing and produces these dispositions:
///
/// * No manifest, a receipt-less manifest, a manifest that fails its own
///   shape, one bound to a different identity, digest or Authority Epoch, a
///   candidate that is not the exact recorded launch binding, a candidate that
///   fails I1.12 compatibility evidence, an acknowledged revocation, or an
///   exhausted recorded restart budget all return
///   [`KernelServiceAdmission::None`] with one reconciliation item. The
///   affected generation is therefore never restarted into normal-effect
///   service on a missing, stale, incompatible, revoked or receipt-less
///   manifest.
/// * An effect-capable class whose current Module Catalog/Policy view is not
///   current, whose revocation event is unacknowledged, or whose delivery path
///   has an open gap returns
///   [`KernelServiceAdmission::ShadowDiagnosticsOnly`]: the candidate may expose
///   diagnostics but holds no external effect and no canonical write admission.
///   A `read_rebuild` manifest is unaffected, because I1.9 admits it straight
///   from the exact recorded manifest under the recorded bounded restart
///   budget.
/// * Everything else returns [`KernelServiceAdmission::ReadRebuildService`] for
///   a `read_rebuild` manifest and [`KernelServiceAdmission::EffectService`] for
///   an effect-capable one, carrying the sealed exact recorded binding. A
///   `current_catalog_required` manifest only reaches
///   `EffectService` while the view is current, so it refuses whenever the view
///   is stale or unavailable.
///
/// Both admitted variants carry a sealed [`BoundKernelExecutionManifest`], whose
/// `launch_binding`, `resource_limits`, `restart_budget`,
/// `health_readiness_contract_ref` and `state_class_behavior` are read from the
/// immutable manifest. A read/rebuild restart therefore uses exactly the
/// recorded artifact, config and protocol hashes and start command, and process
/// launch, replay, route cutover, readiness evaluation, resource limits and the
/// restart budget are all bound to the manifest digest the request named.
///
/// `request.restarts_spent` is compared against the recorded budget ceiling.
/// This function neither accounts restarts nor persists them; the recorded
/// ceiling and quarantine rule are read from the immutable manifest.
pub fn verify_kernel_execution_restart(
    manifest: Option<&KernelExecutionManifest>,
    request: &KernelExecutionRestartRequest,
) -> Result<KernelRestartDecision, OrsError> {
    request.validate()?;
    let recorded = manifest.map(|value| value.manifest_sha256.clone());
    let mut evidence = KernelRestartEvidence {
        module_id: request.module_id.clone(),
        generation: request.generation,
        bound_manifest_sha256: request.bound_manifest_sha256.clone(),
        recorded_manifest_sha256: recorded.clone(),
        restart_authorization_class: None,
    };
    let Some(manifest) = manifest else {
        return Ok(escalate(
            &evidence,
            manifest_reconciliation_item(KernelReconciliationKind::ManifestAbsent, request, None),
        ));
    };
    if let Some(kind) = manifest_structural_defect(manifest) {
        return Ok(escalate(
            &evidence,
            manifest_reconciliation_item(kind, request, recorded.as_deref()),
        ));
    }
    evidence.restart_authorization_class = Some(manifest.restart_authorization_class());
    if let Some(kind) = manifest_blocking_defect(manifest, request) {
        return Ok(escalate(
            &evidence,
            manifest_reconciliation_item(kind, request, recorded.as_deref()),
        ));
    }
    let bound = BoundKernelExecutionManifest::verified(manifest.clone());
    let class = manifest.restart_authorization_class();
    if !class.is_effect_capable() {
        return Ok(KernelRestartDecision::admitted(
            KernelServiceAdmission::ReadRebuildService(bound),
            evidence,
        ));
    }
    let view = effect_admission_defect(
        class,
        request.catalog_view,
        request.revocation,
        request.delivery,
    );
    match view {
        Some(kind) => Ok(KernelRestartDecision::escalated(
            KernelServiceAdmission::ShadowDiagnosticsOnly(bound),
            evidence,
            manifest_reconciliation_item(kind, request, recorded.as_deref()),
        )),
        None => Ok(KernelRestartDecision::admitted(
            KernelServiceAdmission::EffectService(bound),
            evidence,
        )),
    }
}

/// The first defect that makes the recorded manifest unusable at all.
fn manifest_structural_defect(
    manifest: &KernelExecutionManifest,
) -> Option<KernelReconciliationKind> {
    if !manifest.has_governor_admission() {
        return Some(KernelReconciliationKind::ManifestReceiptless);
    }
    if manifest.validate().is_err() {
        return Some(KernelReconciliationKind::ManifestInvalid);
    }
    None
}

/// The first defect that stops an otherwise sound manifest from authorizing
/// this request.
fn manifest_blocking_defect(
    manifest: &KernelExecutionManifest,
    request: &KernelExecutionRestartRequest,
) -> Option<KernelReconciliationKind> {
    let identity_matches = manifest.admission.module_id == request.module_id
        && manifest.admission.generation == request.generation
        && manifest.manifest_sha256 == request.bound_manifest_sha256;
    if !identity_matches {
        return Some(KernelReconciliationKind::ManifestIdentityMismatch);
    }
    if manifest.admission.authority_epoch != request.current_authority_epoch {
        return Some(KernelReconciliationKind::ManifestForeignEpoch);
    }
    if manifest.launch_binding() != request.candidate {
        return Some(KernelReconciliationKind::ManifestCandidateBindingMismatch);
    }
    if !request.compatibility.durable_format_compatible
        || !request.compatibility.epoch_lineage_compatible
    {
        return Some(KernelReconciliationKind::ManifestIncompatible);
    }
    if request.revocation == RevocationAcknowledgement::Acknowledged {
        return Some(KernelReconciliationKind::ManifestRevoked);
    }
    if request.restarts_spent >= manifest.projection.restart_budget.max_restarts {
        return Some(KernelReconciliationKind::ManifestRestartBudgetExhausted);
    }
    None
}

/// The first I1.9 effect-authorization defect, if any, for an effect-capable
/// class in the observed view.
///
/// `RestartAuthorizationClass::admits_normal_effect_service` is the single
/// place the class distinction is applied: a `current_catalog_required` class
/// fails it whenever the view is not current, while an `effect_exact_lease`
/// class passes it. This function is only reached for an effect-capable class,
/// so a `read_rebuild` class never sees a Catalog/Policy freshness condition.
const fn effect_admission_defect(
    class: RestartAuthorizationClass,
    catalog_view: CatalogPolicyView,
    revocation: RevocationAcknowledgement,
    delivery: EffectDeliveryAcknowledgement,
) -> Option<KernelReconciliationKind> {
    if !class.admits_normal_effect_service(catalog_view) {
        Some(KernelReconciliationKind::ManifestCatalogPolicyStale)
    } else if matches!(revocation, RevocationAcknowledgement::Unacknowledged) {
        Some(KernelReconciliationKind::ManifestRevocationUnacknowledged)
    } else if matches!(delivery, EffectDeliveryAcknowledgement::GapOpen) {
        Some(KernelReconciliationKind::ManifestDeliveryGapOpen)
    } else {
        None
    }
}

/// Builds the degraded decision that starts nothing and escalates one defect.
fn escalate(
    evidence: &KernelRestartEvidence,
    item: KernelReconciliationItem,
) -> KernelRestartDecision {
    KernelRestartDecision::escalated(KernelServiceAdmission::None, evidence.clone(), item)
}

/// Builds the reconciliation item for one manifest-side defect.
fn manifest_reconciliation_item(
    kind: KernelReconciliationKind,
    request: &KernelExecutionRestartRequest,
    recorded_manifest_sha256: Option<&str>,
) -> KernelReconciliationItem {
    KernelReconciliationItem {
        kind,
        module_id: request.module_id.clone(),
        generation: request.generation,
        bound_manifest_sha256: Some(request.bound_manifest_sha256.clone()),
        recorded_manifest_sha256: recorded_manifest_sha256.map(str::to_owned),
        lease_id: None,
        operation_id: None,
        observed_at_ms: request.observed_at_ms,
    }
}
