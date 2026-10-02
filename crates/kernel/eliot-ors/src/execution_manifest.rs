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
//! * [`GovernorGenerationAdmissionSeal`] replaces free-text admission receipt
//!   evidence. It is a typed, versioned projection of one Governor Module
//!   Catalog admission: canonical operation/idempotency identity, module and
//!   generation, the exact accepted Catalog revision, the exact Policy revision,
//!   the owner's recorded accepted-manifest digest, the State Fence identity,
//!   the lifecycle admission disposition and the Governor's canonical digest
//!   over exactly those fields. Receipt text, non-zero revisions and
//!   caller-supplied scopes are not authority, so `AdmittedModuleGeneration::validate`
//!   and `KernelExecutionManifest::validate` refuse a manifest whose seal is
//!   absent, belongs to another module/generation, was issued for another
//!   Catalog/Policy revision, carries no State Fence or no admission
//!   disposition, or whose canonical digest does not recompute. The recorded
//!   accepted-manifest digest is provenance bound by that canonical owner
//!   digest; it is not compared against this record's own `manifest_sha256`,
//!   which covers the seal itself. The immutable row is where that digest is
//!   compared (see `governor_admission_seal_defect`).
//!
//!   What the seal still does not establish is that the Governor issued it: the
//!   canonical digest is `pub` because the owner adapter lives in another crate,
//!   so a dependent crate can seal fields it chose itself. The seal binds the
//!   admission and makes any later edit of it a refusal; proving the issuer needs
//!   the Governor accept path and a canonical owner readback of the receipt,
//!   which do not exist on this branch.
//! * Normal-effect service is never opened by a general restart alone.
//!   `RestartAuthorizationClass::admits_normal_effect_service` requires a
//!   current Module Catalog/Policy view for *both* effect-capable classes, so a
//!   stale or unavailable view caps a general restart at
//!   [`KernelServiceAdmission::ShadowDiagnosticsOnly`]. The only remaining
//!   effect authority is `verify_exact_effect_replay`, which requires an
//!   unexpired active [`crate::EffectOperationLease`] identity supplied by the
//!   caller and authorizes that one exact leased operation only.
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
use crate::effect_operation_lease::{
    ActiveEffectOperationLease, EffectAuthorizationView, EffectOperationLease, EffectReplayRequest,
    authorize_effect_replay,
};
use crate::model::{
    OpaqueLabel, OperationIdentity, OrsError, StateFenceSnapshot, sha256_hex, validate_digest,
    validate_text,
};
use crate::versioned_artifact::CompatibilityEvidence;

/// Durable schema version of the Generation Registry manifest record (I1.9).
pub const KERNEL_EXECUTION_MANIFEST_SCHEMA_VERSION: u16 = 1;

/// Restart authorization class recorded on the manifest (I1.9).
///
/// The three values are the I1.9 vocabulary and they are not interchangeable:
/// `read_rebuild` is never effect capable, `effect_exact_lease` is effect
/// capable but may resume only exact already-authorized operations covered by
/// an unexpired operation lease, and `current_catalog_required` names a
/// generation whose restart authorization itself is conditioned on a current
/// Module Catalog/Policy view. Neither effect-capable value lets a *general*
/// restart open normal-effect service without that view; the difference between
/// them is what the view is required for, not whether it is required.
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
    ///
    /// Both effect-capable classes require a current view here, so a stale or
    /// unavailable view can never open a general `EffectService`. An
    /// `effect_exact_lease` generation keeps its exact leased operations
    /// replayable without a general restart, but only through
    /// [`verify_exact_effect_replay`], which demands an unexpired active
    /// operation lease identity; that path is not reachable from this
    /// predicate.
    #[must_use]
    pub const fn admits_normal_effect_service(self, catalog_view: CatalogPolicyView) -> bool {
        match self {
            Self::ReadRebuild => false,
            Self::EffectExactLease | Self::CurrentCatalogRequired => {
                matches!(catalog_view, CatalogPolicyView::Current)
            }
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

/// Durable schema version of the sealed Governor generation admission
/// projection (I1.9).
pub const GOVERNOR_GENERATION_ADMISSION_SEAL_VERSION: u16 = 1;

/// Lifecycle disposition the Governor Module Catalog recorded for one
/// generation admission (I1.9).
///
/// Only `Admitted` is an admission. Anything else is a recorded refusal, so a
/// manifest cannot be built from a generation the Catalog declined.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAdmissionDisposition {
    /// The Catalog admitted this generation for this module at the sealed
    /// Catalog revision.
    Admitted,
    /// The Catalog recorded this generation without admitting it.
    Withheld,
}

/// The owner-provided admission facts one seal is computed from.
///
/// The Governor Module Catalog owner fills this in from its own
/// `GenerationAdmission`, computes the canonical digest over exactly these
/// fields with [`GovernorGenerationAdmissionSeal::canonical_sha256`], and passes
/// the result as `owner_canonical_sha256`. Nothing here is optional and nothing
/// is defaulted: a value the owner cannot state is not admitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorGenerationAdmissionSealParts {
    /// Canonical operation identity the Catalog admission was issued under.
    pub operation_id: OperationIdentity,
    /// Canonical idempotency key of that same admission operation.
    pub idempotency_key: String,
    /// Admitted module identity.
    pub module_id: String,
    /// Admitted generation identity.
    pub generation: ResourceGeneration,
    /// Exact accepted Module Catalog revision.
    pub catalog_revision: u64,
    /// Exact Policy revision that was current at admission.
    pub policy_revision: u64,
    /// The Module Catalog owner's recorded accepted-execution-manifest digest.
    ///
    /// It is copied here by the owner adapter and never recomputed on the ORS
    /// side. It is provenance, and it is part of the seal's canonical owner
    /// digest; it is not compared against a Generation Registry manifest's own
    /// `manifest_sha256`, because that digest covers this very seal.
    pub accepted_manifest_sha256: String,
    /// Exact canonical State Fence identity the admission was issued under.
    pub state_fence: StateFenceSnapshot,
    /// Lifecycle disposition the Catalog recorded.
    pub lifecycle_disposition: LifecycleAdmissionDisposition,
    /// Canonical versioned digest the Governor computed over the fields above.
    pub owner_canonical_sha256: String,
}

#[derive(Serialize)]
struct GovernorGenerationAdmissionSealCore<'a> {
    seal_version: u16,
    operation_id: &'a OperationIdentity,
    idempotency_key: &'a str,
    module_id: &'a str,
    generation: ResourceGeneration,
    catalog_revision: u64,
    policy_revision: u64,
    accepted_manifest_sha256: &'a str,
    state_fence: &'a StateFenceSnapshot,
    lifecycle_disposition: LifecycleAdmissionDisposition,
}

/// Typed, sealed and versioned Governor Module Catalog admission.
///
/// This is the only evidence `AdmittedModuleGeneration` accepts in place of
/// receipt text. Every field is one fact the Governor Module Catalog owner
/// states, and `seal_version` plus `owner_canonical_sha256` bind the whole set
/// to one canonical versioned digest, so a Kernel/ORS caller cannot assemble an
/// admission out of a non-blank string, a non-zero revision and a scope it
/// picked itself.
///
/// The fields are private and the only constructor is [`Self::seal`], which
/// recomputes the canonical digest over the seal's own fields and refuses
/// anything whose recorded `owner_canonical_sha256` differs from it. A seal that
/// arrives through `Deserialize` is checked the same way before use, because
/// `AdmittedModuleGeneration::validate` and
/// `KernelExecutionManifest::validate` both verify the recorded
/// `owner_canonical_sha256` instead of trusting it.
///
/// The seal binds the admission; it does not prove who issued it.
/// [`Self::seal`] and [`Self::canonical_sha256`] are `pub` because the owner
/// adapter that issues a seal lives in another crate, so the constructor cannot
/// be closed to the Governor alone. Proving the issuer needs the Governor accept
/// path and a canonical owner readback of the receipt, neither of which exists
/// on this branch; see [`Self::defect`] for exactly what is and is not
/// established.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorGenerationAdmissionSeal {
    /// Durable schema version of this sealed projection.
    seal_version: u16,
    /// Canonical operation identity the admission was issued under.
    operation_id: OperationIdentity,
    /// Canonical idempotency key of that same admission operation.
    idempotency_key: String,
    /// Admitted module identity.
    module_id: String,
    /// Admitted generation identity.
    generation: ResourceGeneration,
    /// Exact accepted Module Catalog revision.
    catalog_revision: u64,
    /// Exact Policy revision that was current at admission.
    policy_revision: u64,
    /// The Module Catalog owner's recorded accepted-execution-manifest digest.
    accepted_manifest_sha256: String,
    /// Exact canonical State Fence identity the admission was issued under.
    state_fence: StateFenceSnapshot,
    /// Lifecycle disposition the Catalog recorded.
    lifecycle_disposition: LifecycleAdmissionDisposition,
    /// Canonical versioned digest the Governor computed over the fields above.
    owner_canonical_sha256: String,
}

impl GovernorGenerationAdmissionSeal {
    /// The one canonical digest both sides compute over the sealed fields.
    ///
    /// The Governor owner adapter computes it before sealing and this module
    /// recomputes it on every validation, so a seal whose fields no longer hash
    /// to its own recorded digest is refused. This is a BINDING of the sealed
    /// values, not an issuer proof: the function is `pub` because the owner
    /// adapter lives in another crate, so any dependent crate can compute the
    /// same digest over fields it chose. See [`Self::defect`].
    pub fn canonical_sha256(
        parts: &GovernorGenerationAdmissionSealParts,
    ) -> Result<String, OrsError> {
        let core = GovernorGenerationAdmissionSealCore {
            seal_version: GOVERNOR_GENERATION_ADMISSION_SEAL_VERSION,
            operation_id: &parts.operation_id,
            idempotency_key: &parts.idempotency_key,
            module_id: &parts.module_id,
            generation: parts.generation,
            catalog_revision: parts.catalog_revision,
            policy_revision: parts.policy_revision,
            accepted_manifest_sha256: &parts.accepted_manifest_sha256,
            state_fence: &parts.state_fence,
            lifecycle_disposition: parts.lifecycle_disposition,
        };
        let bytes =
            canonical_json_bytes(&core).map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Seals one Governor-issued admission.
    ///
    /// The seal is refused unless every typed field is well formed and the
    /// supplied owner digest equals the canonical digest recomputed here, so a
    /// caller that invents a receipt text, reuses another generation's identity
    /// or restates any sealed field without the owner's digest is rejected
    /// before any ORS mutation can observe the record.
    pub fn seal(parts: GovernorGenerationAdmissionSealParts) -> Result<Self, OrsError> {
        let seal = Self {
            seal_version: GOVERNOR_GENERATION_ADMISSION_SEAL_VERSION,
            operation_id: parts.operation_id,
            idempotency_key: parts.idempotency_key,
            module_id: parts.module_id,
            generation: parts.generation,
            catalog_revision: parts.catalog_revision,
            policy_revision: parts.policy_revision,
            accepted_manifest_sha256: parts.accepted_manifest_sha256,
            state_fence: parts.state_fence,
            lifecycle_disposition: parts.lifecycle_disposition,
            owner_canonical_sha256: parts.owner_canonical_sha256,
        };
        if let Some(kind) = seal.defect() {
            return Err(seal_refusal(kind));
        }
        Ok(seal)
    }

    /// The canonical operation identity the admission was issued under.
    pub const fn operation_id(&self) -> &OperationIdentity {
        &self.operation_id
    }

    /// The admitted module identity.
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// The admitted generation identity.
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// The exact accepted Module Catalog revision.
    pub const fn catalog_revision(&self) -> u64 {
        self.catalog_revision
    }

    /// The exact Policy revision that was current at admission.
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    /// The Module Catalog owner's recorded accepted-execution-manifest digest,
    /// copied in by the owner adapter and never recomputed here.
    pub fn accepted_manifest_sha256(&self) -> &str {
        &self.accepted_manifest_sha256
    }

    /// The exact canonical State Fence identity of the admission.
    pub const fn state_fence(&self) -> &StateFenceSnapshot {
        &self.state_fence
    }

    /// The lifecycle disposition the Catalog recorded.
    pub const fn lifecycle_disposition(&self) -> LifecycleAdmissionDisposition {
        self.lifecycle_disposition
    }

    /// The first defect that makes this seal unusable as authority, if any.
    ///
    /// Every check reads this seal's own recorded fields, and the last one
    /// compares the recorded `owner_canonical_sha256` against the canonical
    /// digest recomputed over those same fields, so a seal whose fields were
    /// edited after sealing is refused.
    ///
    /// What this does NOT establish is that the Governor issued the seal.
    /// `canonical_sha256` and `seal` are `pub` because the Governor owner
    /// adapter lives in another crate
    /// (`eliot_module_registry::seal_generation_admission`), so any crate that
    /// depends on `eliot-ors` can compute a matching digest over fields it
    /// chose itself. The seal therefore BINDS an admission to exact module,
    /// generation, Catalog/Policy revisions, State Fence, lifecycle disposition
    /// and owner-recorded accepted-manifest digest, and makes any edit of those
    /// fields a refusal; it is not a proof of issuer. Issuer proof requires the
    /// Governor accept path and the canonical owner readback, which do not exist
    /// yet: `GenerationAdmission` and `CatalogMutation::AcceptGeneration` have no
    /// producers and `ModuleCatalog::apply_mutation` refuses every admission.
    fn defect(&self) -> Option<KernelReconciliationKind> {
        if self.seal_version != GOVERNOR_GENERATION_ADMISSION_SEAL_VERSION
            || self.owner_canonical_sha256.trim().is_empty()
            || self.catalog_revision == 0
            || self.policy_revision == 0
        {
            return Some(KernelReconciliationKind::GovernorAdmissionSealAbsent);
        }
        if !matches!(
            self.lifecycle_disposition,
            LifecycleAdmissionDisposition::Admitted
        ) {
            return Some(KernelReconciliationKind::GovernorAdmissionSealWithheld);
        }
        if validate_text(&self.module_id, "governor_admission_seal_module_id").is_err()
            || validate_text(
                &self.idempotency_key,
                "governor_admission_seal_idempotency_key",
            )
            .is_err()
            || validate_text(
                self.operation_id.as_str(),
                "governor_admission_seal_operation_id",
            )
            .is_err()
            || validate_digest(
                &self.accepted_manifest_sha256,
                "governor_admission_seal_accepted_manifest_sha256",
            )
            .is_err()
        {
            return Some(KernelReconciliationKind::GovernorAdmissionSealMalformed);
        }
        if self.state_fence.validate().is_err() {
            return Some(KernelReconciliationKind::GovernorAdmissionSealStateFenceAbsent);
        }
        match self.canonical_sha256_over_recorded_fields() {
            Ok(recomputed) if recomputed == self.owner_canonical_sha256 => {}
            Ok(_) => {
                return Some(KernelReconciliationKind::GovernorAdmissionSealOwnerDigestMismatch);
            }
            Err(_) => return Some(KernelReconciliationKind::GovernorAdmissionSealMalformed),
        }
        None
    }

    /// The first defect that makes this seal unusable for the record it is
    /// carried on, if any.
    fn record_binding_defect(
        &self,
        module_id: &str,
        generation: ResourceGeneration,
        catalog_revision: u64,
        policy_revision: u64,
    ) -> Option<KernelReconciliationKind> {
        if let Some(kind) = self.defect() {
            return Some(kind);
        }
        if self.module_id != module_id || self.generation != generation {
            return Some(KernelReconciliationKind::GovernorAdmissionSealIdentityMismatch);
        }
        if self.catalog_revision != catalog_revision || self.policy_revision != policy_revision {
            return Some(KernelReconciliationKind::GovernorAdmissionSealRevisionMismatch);
        }
        None
    }

    /// Recomputes the canonical digest over this seal's own recorded fields.
    fn canonical_sha256_over_recorded_fields(&self) -> Result<String, OrsError> {
        let core = GovernorGenerationAdmissionSealCore {
            seal_version: self.seal_version,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            module_id: &self.module_id,
            generation: self.generation,
            catalog_revision: self.catalog_revision,
            policy_revision: self.policy_revision,
            accepted_manifest_sha256: &self.accepted_manifest_sha256,
            state_fence: &self.state_fence,
            lifecycle_disposition: self.lifecycle_disposition,
        };
        let bytes =
            canonical_json_bytes(&core).map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// The Governor-issued Module Catalog admission that authorizes one manifest.
///
/// This is the only input `KernelExecutionManifest::admit` accepts. The
/// accepted Module Catalog revision, the Policy revision and the sealed
/// lifecycle/admission projection are recorded here and are bound to each other
/// by [`Self::validate`].
///
/// Scope truth, stated exactly: `admitted_allowed_scopes` and
/// `admitted_effect_ceiling` are `pub` fields of this struct and are NOT covered
/// by `governor_admission_seal`, which carries no scope and no ceiling. They are
/// therefore bounds this record states, not bounds the seal proves; a caller that
/// supplies them states its own. [`crate::KernelExecutionManifest::check_admitted_bounds`]
/// is what refuses a projection whose ceiling or scopes exceed them, so the two
/// are consistent with each other and neither is proof against the caller. Binding
/// the admitted ceiling and scopes to the Governor's own record is part of the
/// same open item as issuer proof (see [`GovernorGenerationAdmissionSeal::defect`]).
///
/// `governor_admission_seal` is a typed, sealed, versioned projection rather
/// than receipt text: receipt text and non-zero revisions are not authority.
/// `validate` refuses a seal that is absent, belongs to another module or
/// generation, was issued for other Catalog/Policy revisions, carries no State
/// Fence identity or no admission disposition, or whose recorded owner digest
/// does not equal the canonical digest recomputed over its own fields.
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
    /// Sealed Governor Module Catalog lifecycle/admission projection for this
    /// exact module, generation, revision pair and manifest digest.
    pub governor_admission_seal: GovernorGenerationAdmissionSeal,
    /// Restart authorization class the Catalog admitted.
    pub restart_authorization_class: RestartAuthorizationClass,
    /// Effect ceiling the Catalog admitted. The manifest may not exceed it.
    pub admitted_effect_ceiling: ManifestEffectCeiling,
    /// Route scopes the Catalog admitted. The manifest's allowed scopes must be
    /// a subset of this set.
    pub admitted_allowed_scopes: Vec<CapabilityRouteScope>,
}

impl AdmittedModuleGeneration {
    /// Validates the admitted identity, revisions, sealed admission projection
    /// and route scopes.
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
        if let Some(kind) = self.governor_admission_seal.record_binding_defect(
            &self.module_id,
            self.generation,
            self.catalog_revision,
            self.policy_revision,
        ) {
            return Err(seal_refusal(kind));
        }
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
/// Catalog revision with its sealed lifecycle/admission projection.
///
/// `admit` is the only validating construction path, and a hand-built record
/// is refused by `validate` unless `manifest_sha256` recomputes over the
/// recorded schema version, admission and projection and the sealed Governor
/// admission names exactly this manifest. The type declares no update, widen or
/// re-authorize method, so a changed field cannot be accepted silently.
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
    /// This is the only validating construction path. It refuses an admission
    /// whose sealed Governor projection does not stand for exactly this module,
    /// generation and Catalog/Policy revision pair and whose recorded canonical
    /// owner digest does not recompute over its own fields (see
    /// [`GovernorGenerationAdmissionSeal`]), a projection whose effect ceiling
    /// exceeds `admission.admitted_effect_ceiling`, a projection whose allowed
    /// scopes are not a subset of `admission.admitted_allowed_scopes`, and an
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

    /// Whether the recorded manifest carries an intact sealed Governor admission
    /// projection, a non-zero accepted Module Catalog revision and a non-zero
    /// Policy revision.
    ///
    /// A manifest that does not is receipt-less: it was never admitted, so it
    /// cannot authorize a restart.
    #[must_use]
    pub fn has_governor_admission(&self) -> bool {
        self.admission.governor_admission_seal.defect().is_none()
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

    /// Validates the record shape, the admitted bounds, the sealed Governor
    /// admission and the bound digest.
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

/// The typed refusal one sealed Governor admission defect produces.
///
/// The disposition stays a [`KernelReconciliationKind`] so the same defect is
/// visible as a durable reconciliation item, and the failure stays an
/// [`OrsError::IntegrityProblem`] rather than an untyped string.
fn seal_refusal(kind: KernelReconciliationKind) -> OrsError {
    OrsError::IntegrityProblem {
        record_type: "kernel_execution_manifest_governor_admission_seal",
        reason: seal_refusal_reason(kind).to_owned(),
    }
}

/// The durable reason recorded for one sealed Governor admission defect.
const fn seal_refusal_reason(kind: KernelReconciliationKind) -> &'static str {
    match kind {
        KernelReconciliationKind::GovernorAdmissionSealAbsent => {
            "no sealed Governor admission projection is recorded"
        }
        KernelReconciliationKind::GovernorAdmissionSealWithheld => {
            "the recorded lifecycle disposition is not an admission"
        }
        KernelReconciliationKind::GovernorAdmissionSealMalformed => {
            "the recorded sealed admission does not satisfy its own typed shape"
        }
        KernelReconciliationKind::GovernorAdmissionSealIdentityMismatch => {
            "the sealed admission names a different module or generation"
        }
        KernelReconciliationKind::GovernorAdmissionSealRevisionMismatch => {
            "the sealed admission was issued for a different Catalog or Policy revision"
        }
        KernelReconciliationKind::GovernorAdmissionSealStateFenceAbsent => {
            "the sealed admission carries no State Fence identity"
        }
        KernelReconciliationKind::GovernorAdmissionSealOwnerDigestMismatch => {
            "the sealed admission carries a Governor canonical digest that does not recompute"
        }
        _ => "the recorded manifest is not admitted by the Governor Module Catalog",
    }
}

/// The first defect that makes the manifest's sealed Governor admission
/// unusable as authority, if any.
///
/// `accepted_manifest_sha256` is deliberately not compared here. It is the
/// Module Catalog owner's recorded accepted-execution-manifest digest, copied
/// into the seal by the owner adapter and never recomputed on this side, and it
/// is already covered by the seal's own canonical owner digest. This record's
/// `manifest_sha256` covers the seal itself, so an in-record equality between
/// the two would require a digest to equal itself and could never hold. The
/// digest comparison happens at the immutable row instead: a re-persist of the
/// same `{module_id, generation}` whose recorded accepted digest differs is
/// refused as an identity conflict and writes nothing
/// (`RedbRecoveryStore::persist_admitted_kernel_execution_manifest`).
fn governor_admission_seal_defect(
    manifest: &KernelExecutionManifest,
) -> Option<KernelReconciliationKind> {
    let seal = &manifest.admission.governor_admission_seal;
    seal.record_binding_defect(
        &manifest.admission.module_id,
        manifest.admission.generation,
        manifest.admission.catalog_revision,
        manifest.admission.policy_revision,
    )
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
        // The recorded I1.12 verdict must satisfy its own storage shape and be
        // bound to this request's generation, so a restart can never be decided
        // against evidence that names a different candidate.
        self.compatibility.validate()?;
        if self.compatibility.module_generation() != self.generation.value() {
            return Err(OrsError::InvalidField {
                field: "kernel_execution_restart_compatibility_generation",
                reason: "the recorded compatibility verdict must name the request's own generation",
            });
        }
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
    /// [`crate::EffectOperationLease`](crate::EffectOperationLease) verified by
    /// [`verify_exact_effect_replay`]; the binding itself authorizes no effect.
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
    /// sealed lifecycle/admission projection.
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
    /// The recorded manifest carries no sealed Governor admission projection,
    /// so no Governor-issued admission exists for it at all.
    GovernorAdmissionSealAbsent,
    /// The recorded seal's lifecycle disposition is not an admission.
    GovernorAdmissionSealWithheld,
    /// The recorded seal does not satisfy its own typed shape.
    GovernorAdmissionSealMalformed,
    /// The recorded seal names a different module or generation than the
    /// manifest it is carried on.
    GovernorAdmissionSealIdentityMismatch,
    /// The recorded seal was issued for a different accepted Module Catalog
    /// revision or Policy revision than the manifest records.
    GovernorAdmissionSealRevisionMismatch,
    /// The recorded seal carries no State Fence identity.
    GovernorAdmissionSealStateFenceAbsent,
    /// The recorded seal's Governor canonical digest does not equal the digest
    /// recomputed over the seal's own fields.
    GovernorAdmissionSealOwnerDigestMismatch,
    /// The exact-effect replay supplied no effect operation lease identity, so
    /// it names no unexpired active lease and is a new operation.
    EffectLeaseIdentityAbsent,
    /// The supplied effect operation lease record is not the lease the replay
    /// claims.
    EffectLeaseIdentityMismatch,
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

impl KernelReconciliationItem {
    /// Validates the affected identity, the recorded digests and the observed
    /// clock of one durable reconciliation intent.
    ///
    /// A durable row is re-validated on every readback, so an absent operation
    /// identity, a malformed digest or a non-positive observation time fails
    /// closed as corruption rather than surviving as escalation evidence.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(&self.module_id, "kernel_reconciliation_item_module_id")?;
        if let Some(bound) = &self.bound_manifest_sha256 {
            validate_digest(bound, "kernel_reconciliation_item_bound_manifest_sha256")?;
        }
        if let Some(recorded) = &self.recorded_manifest_sha256 {
            validate_digest(
                recorded,
                "kernel_reconciliation_item_recorded_manifest_sha256",
            )?;
        }
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_reconciliation_item_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
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
/// * No manifest, a manifest whose sealed Governor admission is unusable (an
///   absent, withheld, malformed, foreign-identity, foreign-revision,
///   fence-less, foreign-digest or non-recomputing seal), a receipt-less
///   manifest, a manifest
///   that fails its own shape, one bound to a different identity, digest or
///   Authority Epoch, a candidate that is not the exact recorded launch
///   binding, a candidate that fails I1.12 compatibility evidence, an
///   acknowledged revocation, or an exhausted recorded restart budget all
///   return [`KernelServiceAdmission::None`] with one reconciliation item. The
///   affected generation is therefore never restarted into normal-effect
///   service on a missing, stale, incompatible, revoked or unadmitted
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
///   an effect-capable one, carrying the sealed exact recorded binding. Both
///   effect-capable classes reach `EffectService` only while the view is
///   current, so a stale or unavailable Module Catalog/Policy view caps a
///   general restart at `ShadowDiagnosticsOnly` for either of them. An
///   `effect_exact_lease` generation under such a view keeps only its exact
///   already-authorized operations, and only through
///   [`verify_exact_effect_replay`].
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
///
/// A sealed Governor admission defect is reported under its own typed kind, so
/// an invented receipt and a receipt issued for another module, generation or
/// Catalog/Policy revision are each visible as the defect they are rather than
/// as one undifferentiated invalid record.
fn manifest_structural_defect(
    manifest: &KernelExecutionManifest,
) -> Option<KernelReconciliationKind> {
    if let Some(kind) = governor_admission_seal_defect(manifest) {
        return Some(kind);
    }
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
    if request.compatibility.is_refused() {
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
/// place the class distinction is applied: both effect-capable classes fail it
/// whenever the view is not current, so a stale or unavailable Module
/// Catalog/Policy view can never open a general `EffectService`. This function
/// is only reached for an effect-capable class, so a `read_rebuild` class never
/// sees a Catalog/Policy freshness condition.
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

/// The exact already-authorized effect operation one replay may resume.
///
/// It is a separate request from [`KernelExecutionRestartRequest`] because a
/// general restart carries no operation identity, no effect receipt, no route
/// scope and no lease identity: it can only ever start a whole generation. An
/// effect-capable generation whose Module Catalog/Policy freshness is lost may
/// therefore not resume a *new* operation through it, and resumes only through
/// this request, which names the one exact operation and the one exact
/// unexpired active lease that already authorized it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelExactEffectReplayRequest {
    /// The one exact operation identity the replay claims.
    pub operation_id: OperationIdentity,
    /// The effect operation lease identity the caller supplies as the unexpired
    /// active lease that authorized it.
    pub lease_id: OperationIdentity,
    /// Module identity the replay is bound to.
    pub module_id: String,
    /// Generation identity the replay is bound to.
    pub generation: ResourceGeneration,
    /// The manifest digest the replay is bound to.
    pub bound_manifest_sha256: String,
    /// Digest of the exact already-authorized effect being replayed.
    pub effect_receipt_sha256: String,
    /// The exact route scope the replay claims. It cannot exceed the lease's.
    pub allowed_scope: CapabilityRouteScope,
    /// Authority Epoch the replay is claimed under.
    pub authority_epoch: AuthorityEpoch,
    /// Current accepted Module Catalog revision.
    pub current_catalog_revision: u64,
    /// Current Policy revision.
    pub current_policy_revision: u64,
    /// Availability of the current Module Catalog/Policy view.
    pub catalog_view: CatalogPolicyView,
    /// Acknowledgement state of the latest revocation event.
    pub revocation: RevocationAcknowledgement,
    /// Acknowledgement state of the delivery path.
    pub delivery: EffectDeliveryAcknowledgement,
    /// Observation time of the decision in Unix milliseconds.
    pub observed_at_ms: i64,
}

impl KernelExactEffectReplayRequest {
    /// Validates the request's own identities, digest, scope, revisions and
    /// clock.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            self.operation_id.as_str(),
            "kernel_exact_effect_replay_operation_id",
        )?;
        validate_text(
            self.lease_id.as_str(),
            "kernel_exact_effect_replay_lease_id",
        )?;
        validate_text(&self.module_id, "kernel_exact_effect_replay_module_id")?;
        validate_digest(
            &self.bound_manifest_sha256,
            "kernel_exact_effect_replay_bound_manifest_sha256",
        )?;
        validate_digest(
            &self.effect_receipt_sha256,
            "kernel_exact_effect_replay_effect_receipt_sha256",
        )?;
        self.allowed_scope.validate()?;
        if self.current_catalog_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_exact_effect_replay_current_catalog_revision",
                reason: "must be greater than zero",
            });
        }
        if self.current_policy_revision == 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_exact_effect_replay_current_policy_revision",
                reason: "must be greater than zero",
            });
        }
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "kernel_exact_effect_replay_observed_at_ms",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// One exact-effect replay decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct KernelExactEffectReplayDecision {
    /// The bounded replay authority the caller may act on. It is present only
    /// for the one exact leased operation, and it is the sealed
    /// [`ActiveEffectOperationLease`] itself, so no caller can assemble it.
    pub authorized_lease: Option<ActiveEffectOperationLease>,
    /// Preserved evidence for the decision.
    pub evidence: KernelRestartEvidence,
    /// Operational items to persist. Empty only for the one admitted exact
    /// replay; every refusal carries at least one item, so a denied attempt
    /// cannot be discarded.
    pub reconciliation: Vec<KernelReconciliationItem>,
}

/// Authorizes one exact already-authorized effect operation against its lease.
///
/// This is the one path an effect-capable generation uses after a general
/// restart could not open normal-effect service. It mutates no durable state,
/// dispatches nothing, and authorizes exactly one operation or nothing at all.
///
/// The caller must supply the lease identity together with the durable
/// [`EffectOperationLease`] record it read. That record is not rebuilt,
/// defaulted or recomputed here: its expiry, lifecycle state, revocation
/// acknowledgement and delivery acknowledgement are read from the record
/// itself, and no lease store or lease clock is introduced on this side. Every
/// refusal below is durable and typed:
///
/// * no lease record at all is
///   [`KernelReconciliationKind::EffectLeaseIdentityAbsent`], so the replay
///   names no unexpired active lease and is a new operation;
/// * a lease record that is not the claimed one is
///   [`KernelReconciliationKind::EffectLeaseIdentityMismatch`];
/// * a lease that fails its own shape is
///   [`KernelReconciliationKind::EffectLeaseInvalid`];
/// * a lease bound to another manifest module, generation or manifest digest
///   is [`KernelReconciliationKind::EffectManifestMismatch`], and a lease
///   issued under another Authority Epoch is
///   [`KernelReconciliationKind::EffectEpochMismatch`];
/// * the request-side operation identity, effect receipt, route scope,
///   manifest binding and current revocation/delivery state, the lease's own
///   expiry, active state, revocation and delivery state, and the currency of
///   the Module Catalog/Policy view are all verified by
///   [`authorize_effect_replay`], the single canonical lease gate, and its
///   typed refusal — including
///   [`KernelReconciliationKind::EffectLeaseExpired`] and
///   [`KernelReconciliationKind::EffectCatalogPolicyStale`] — is carried
///   through unchanged rather than re-implemented here.
///
/// An admitted decision carries the sealed lease of that one operation and no
/// general-effect authority, so a stale or unavailable Module Catalog/Policy
/// view can never open a new operation.
pub fn verify_exact_effect_replay(
    manifest: Option<&KernelExecutionManifest>,
    lease: Option<&EffectOperationLease>,
    request: &KernelExactEffectReplayRequest,
) -> Result<KernelExactEffectReplayDecision, OrsError> {
    request.validate()?;
    let evidence = KernelRestartEvidence {
        module_id: request.module_id.clone(),
        generation: request.generation,
        bound_manifest_sha256: request.bound_manifest_sha256.clone(),
        recorded_manifest_sha256: manifest.map(|value| value.manifest_sha256.clone()),
        restart_authorization_class: manifest
            .map(KernelExecutionManifest::restart_authorization_class),
    };
    let Some(lease) = lease else {
        return Ok(deny_exact_effect_replay(
            evidence,
            KernelReconciliationKind::EffectLeaseIdentityAbsent,
            request,
            None,
        ));
    };
    if lease.lease_id != request.lease_id {
        return Ok(deny_exact_effect_replay(
            evidence,
            KernelReconciliationKind::EffectLeaseIdentityMismatch,
            request,
            Some(lease),
        ));
    }
    if lease.validate().is_err() {
        return Ok(deny_exact_effect_replay(
            evidence,
            KernelReconciliationKind::EffectLeaseInvalid,
            request,
            Some(lease),
        ));
    }
    let Some(manifest) = manifest else {
        return Ok(deny_exact_effect_replay(
            evidence,
            KernelReconciliationKind::ManifestAbsent,
            request,
            Some(lease),
        ));
    };
    if manifest.validate().is_err() {
        return Ok(deny_exact_effect_replay(
            evidence,
            KernelReconciliationKind::ManifestInvalid,
            request,
            Some(lease),
        ));
    }
    if lease.manifest_module_id != manifest.admission.module_id
        || lease.manifest_generation != manifest.admission.generation
        || lease.bound_manifest_sha256 != manifest.manifest_sha256
    {
        return Ok(deny_exact_effect_replay(
            evidence,
            KernelReconciliationKind::EffectManifestMismatch,
            request,
            Some(lease),
        ));
    }
    if lease.authority_epoch != manifest.admission.authority_epoch {
        return Ok(deny_exact_effect_replay(
            evidence,
            KernelReconciliationKind::EffectEpochMismatch,
            request,
            Some(lease),
        ));
    }
    // Every request-side value the canonical gate compares is the caller's own
    // observation, never a copy of the lease's own field.
    let decision = authorize_effect_replay(
        Some(lease),
        Some(manifest),
        &EffectReplayRequest {
            operation_id: request.operation_id.clone(),
            manifest_module_id: request.module_id.clone(),
            manifest_generation: request.generation,
            bound_manifest_sha256: request.bound_manifest_sha256.clone(),
            effect_receipt_sha256: request.effect_receipt_sha256.clone(),
            allowed_scope: request.allowed_scope.clone(),
            current: EffectAuthorizationView {
                authority_epoch: request.authority_epoch,
                catalog_revision: request.current_catalog_revision,
                policy_revision: request.current_policy_revision,
                catalog_view: request.catalog_view,
                revocation: request.revocation,
                delivery: request.delivery,
            },
            observed_at_ms: request.observed_at_ms,
        },
    )?;
    let authorized_lease = decision.authority.authorized_lease().cloned();
    // The gate always pairs a denial with exactly one durable reconciliation
    // item and an admission with none, so the decision is carried through
    // without adding or dropping evidence here.
    let reconciliation = decision.reconciliation.into_iter().collect();
    Ok(KernelExactEffectReplayDecision {
        authorized_lease,
        evidence,
        reconciliation,
    })
}

/// Builds the denied exact-effect replay decision, which authorizes nothing.
fn deny_exact_effect_replay(
    evidence: KernelRestartEvidence,
    kind: KernelReconciliationKind,
    request: &KernelExactEffectReplayRequest,
    lease: Option<&EffectOperationLease>,
) -> KernelExactEffectReplayDecision {
    KernelExactEffectReplayDecision {
        authorized_lease: None,
        evidence,
        reconciliation: vec![exact_effect_replay_reconciliation_item(
            kind, request, lease,
        )],
    }
}

/// Builds the reconciliation item for one exact-effect replay refusal.
fn exact_effect_replay_reconciliation_item(
    kind: KernelReconciliationKind,
    request: &KernelExactEffectReplayRequest,
    lease: Option<&EffectOperationLease>,
) -> KernelReconciliationItem {
    KernelReconciliationItem {
        kind,
        module_id: request.module_id.clone(),
        generation: request.generation,
        bound_manifest_sha256: Some(request.bound_manifest_sha256.clone()),
        recorded_manifest_sha256: lease.map(|value| value.bound_manifest_sha256.clone()),
        lease_id: Some(request.lease_id.clone()),
        operation_id: Some(request.operation_id.clone()),
        observed_at_ms: request.observed_at_ms,
    }
}
