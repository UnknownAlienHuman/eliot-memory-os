//! Governed canary removal contract and coordinator.
//!
//! Architecture `I3.15` owns the installation/remove transaction: removal is a
//! new durable operation under the same installation/Host authority, so this
//! module never rewrites a completed installation into a rollback and never
//! opens a second installation database. `I14.23` owns the drain ordering a
//! dependent stop/delete must follow, `I14.24`/`A13.2` own local containment
//! and the failure-domain split, `I5.19` owns the stable operation identity and
//! the `unknown_outcome`/`reconciling` discipline, `I7.20` owns the typed
//! disposition plus next permitted action, and `I15.4` owns the secret
//! boundary: no secret value, credential ciphertext or provider output crosses
//! a plan, an effect row, a durable progress entry or a status projection.
//!
//! Planning is strictly read-only. `plan_canary_removal` resolves the target
//! from the accepted installation registry and the original transaction's own
//! effect receipts and creates no file, secret, service, reservation or
//! transaction row. Admission records one durable removal operation together
//! with the one absolute deadline of its bounded reconcile wait, and execution
//! revalidates the retained resource identity immediately before each mutation,
//! persists the exact intent before the call and the observed result before
//! advancing.
//!
//! The reconcile wait is bounded by that single recorded deadline rather than by
//! a caller-chosen or per-attempt budget. A resumed or retried reconcile reads
//! the same recorded deadline back, so a restart cannot hand the same removal a
//! second unbounded wait. Once the deadline is reached, both entry points refuse
//! to drive any further effect and return the untouched durable projection: the
//! non-terminal stage, the blocking effect and the unresolved
//! `CanaryRemovalEffectState::Unknown { pending_ref }` row all stay exactly as
//! observed. Expiry therefore produces visible incomplete recovery state and
//! can never author a green `Completed`; only a per-row authoritative readback
//! can.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    ApprovedGenerationRegistry, ContractVersion, InstallationCoordinator, InstallationEffectAction,
    InstallationEffectObservation, InstallationEffectPort, InstallationEffectRequest,
    InstallationEpoch, InstallationError, InstallationStage, InstallationTransaction,
    InstallationTransactionStore, InstallerEffectPlan, ManagedEnvironmentAction,
    ManagedEnvironmentChangeRequest, PlatformHandle, PortOutcome, RedbInstallationRegistry,
    RedbInstallationTransactionStore, candidate_manifest_digest, effect_request, handle, handles,
    platform_error, port_pending, sha256_handle, sha256_hex, wall_clock_millis,
};

/// Wire discriminator for the canary-removal plan, its frozen effect graph and
/// the durable removal operation bound to the original installed transaction.
///
/// This revision is independent from the installation-transaction wire version,
/// so an existing installation transaction keeps its exact identity: a removal
/// is a separate durable record, not a rewritten install.
///
/// Version 2 makes the absolute reconcile deadline of the bounded reconcile
/// wait a mandatory durable member. A version 1 record cannot supply it and
/// requires explicit migration; a deadline is never synthesized as a default,
/// because a defaulted budget would silently grant an unbounded second wait.
pub const CANARY_REMOVAL_WIRE_VERSION: ContractVersion = ContractVersion::new(2, 0, 0);

/// Canonical prefix of every derived canary-removal operation identity.
const CANARY_REMOVAL_OPERATION_PREFIX: &str = "canary-removal/v1:";

/// Attempts admitted for one removal row under one removal operation identity.
///
/// One first attempt plus exactly one retry is the whole bound: a reconcile
/// that proves the previous mutating call was not applied may re-issue the same
/// attempt under the same identity, and any further attempt requires a new,
/// separately admitted removal operation rather than a silent extra mutation.
const CANARY_REMOVAL_ROW_MAX_ATTEMPTS: u32 = 2;

/// Bounded wall-clock window in which one admitted canary-removal operation may
/// keep driving and reconciling its own removal rows.
///
/// This is the same absolute injected-clock shape the crate already uses for
/// one bounded SCM start convergence window. The deadline is computed once from
/// the observed clock when the operation is admitted, persisted with the
/// operation and never recomputed, so a resumed reconcile re-derives its
/// remaining window from that recorded deadline instead of restarting the
/// budget. Expiry is not a resolution: it only refuses to drive further, which
/// preserves the durable incomplete recovery and its blocking effect exactly as
/// observed.
const CANARY_REMOVAL_RECONCILE_TIMEOUT_MS: u64 = 30_000;

/// Closed set of resource categories one governed canary removal must account
/// for.
///
/// The set is closed on purpose. Every category the accepted registry or the
/// original transaction's effect receipts can describe has exactly one variant,
/// so a shared, preexisting or foreign category cannot silently leave the
/// removal denominator.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalResource {
    /// Exact staged generation tree below the shared packages staging root.
    GenerationPackageRoot,
    /// The `LocalService` Store credential provisioned for this generation.
    StoreCredential,
    /// One canonical SCM service registration admitted for this generation.
    ServiceRegistration,
    /// One canonical SCM service start admitted for this generation.
    ServiceStart,
    /// One installer-owned root created below the installation root.
    InstallationRoot,
    /// One protected ACL applied by the original transaction.
    InstallationAcl,
    /// Host-owned Phase-B live overlay materialized for this generation.
    PhaseBLiveOverlay,
    /// Per-installation canary evidence root derived from the runtime roots.
    CanaryEvidenceRoot,
    /// Canonical Store and Blob objects written by this generation.
    StoreObjects,
    /// The approved-generation registry record for this generation.
    GenerationRegistryRecord,
}

/// Proven ownership of one planned removal resource.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalResourceOrigin {
    /// The original install transaction durably created this exact object.
    CreatedByInstallTransaction,
    /// The original install transaction adopted an already existing object.
    PreexistingAtInstall,
    /// Another durable owner, contour or generation owns this resource.
    ForeignToThisRemoval,
}

/// Intended action for one planned removal resource.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalAction {
    /// This owner removes the exact transaction-created identity.
    Remove,
    /// The resource survives this removal unchanged.
    Retain,
    /// The resource is required for a complete removal, but this owner has no
    /// admitted removal path for it. It stays in the denominator and blocks
    /// apply; it is never dropped from the plan.
    Unsupported,
}

/// Postcondition one removal row must authoritatively prove.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalPostcondition {
    /// The exact previously admitted object is authoritatively absent.
    Absent,
    /// The resource is still present with its admitted identity.
    Retained,
}

/// Bounded execution contour for one removal row.
///
/// The bound counts attempts under this one removal operation identity only. A
/// proven not-applied attempt may be retried inside the bound; an unknown
/// outcome never creates a new operation identity and never silently spends
/// another attempt, it requires reconciliation first.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalEffectBound {
    /// Non-zero attempt currently committed for this row.
    pub attempt: u32,
    /// Maximum attempts admitted under this removal operation identity.
    pub max_attempts: u32,
}

impl CanaryRemovalEffectBound {
    const fn new() -> Self {
        Self {
            attempt: 1,
            max_attempts: CANARY_REMOVAL_ROW_MAX_ATTEMPTS,
        }
    }

    fn validate(self, field: &str) -> Result<(), InstallationError> {
        if self.attempt == 0 || self.max_attempts == 0 || self.attempt > self.max_attempts {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "must name a non-zero attempt inside a non-zero attempt bound".to_owned(),
            });
        }
        Ok(())
    }

    const fn next(self) -> Option<Self> {
        let attempt = self.attempt + 1;
        if attempt <= self.max_attempts {
            Some(Self {
                attempt,
                max_attempts: self.max_attempts,
            })
        } else {
            None
        }
    }
}

/// One frozen row of the complete canary-removal effect graph.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalEffect {
    /// Stable removal-effect identity, unique inside one plan.
    pub effect_id: PlatformHandle,
    /// Closed resource category this row accounts for.
    pub category: CanaryRemovalResource,
    /// Proven ownership of the resource.
    pub origin: CanaryRemovalResourceOrigin,
    /// Action this owner admits for the resource.
    pub action: CanaryRemovalAction,
    /// Exact external object identity this removal is admitted to remove.
    ///
    /// For every row backed by an original installer effect this is the
    /// identity that transaction durably recorded for that effect, so a
    /// substituted PID, path or service name cannot acquire ownership. For a
    /// row with no installer effect it is the exact approved identity the
    /// owning contour or registry projection admitted.
    pub resource_identity: PlatformHandle,
    /// Original effect receipt references proving creation or adoption.
    pub ownership_evidence: Vec<PlatformHandle>,
    /// Other admitted users that keep the resource alive.
    pub reference_users: Vec<PlatformHandle>,
    /// Removal effects that must be resolved before this row may start.
    pub prerequisites: Vec<PlatformHandle>,
    /// Postcondition this row must authoritatively prove.
    pub expected_postcondition: CanaryRemovalPostcondition,
    /// Queryable reconciliation handle owned by the resource's own owner.
    pub reconciliation_query: PlatformHandle,
    /// Bounded execution contour for this row.
    pub bound: CanaryRemovalEffectBound,
    /// Positional index of the original installer effect this row inverts.
    ///
    /// `None` marks a row this owner classifies and retires without an
    /// installer effect, which is the terminal registry record and the
    /// owner-derived contour rows.
    pub install_effect_index: Option<u32>,
}

impl CanaryRemovalEffect {
    fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (&self.effect_id, "canary_removal.effect.effect_id"),
            (
                &self.resource_identity,
                "canary_removal.effect.resource_identity",
            ),
            (
                &self.reconciliation_query,
                "canary_removal.effect.reconciliation_query",
            ),
        ] {
            handle(value, field)?;
        }
        handles(
            &self.ownership_evidence,
            "canary_removal.effect.ownership_evidence",
            true,
        )?;
        handles(
            &self.reference_users,
            "canary_removal.effect.reference_users",
            false,
        )?;
        handles(
            &self.prerequisites,
            "canary_removal.effect.prerequisites",
            false,
        )?;
        if self
            .ownership_evidence
            .iter()
            .any(|value| self.reference_users.iter().any(|user| user == value))
        {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.effect.reference_users".to_owned(),
                reason: "ownership evidence must not double as a reference user".to_owned(),
            });
        }
        if self
            .prerequisites
            .iter()
            .any(|value| value == &self.effect_id)
        {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.effect.prerequisites".to_owned(),
                reason: "a removal effect cannot require itself".to_owned(),
            });
        }
        self.bound.validate("canary_removal.effect.bound")?;
        let postcondition_matches = matches!(
            (self.action, self.expected_postcondition),
            (
                CanaryRemovalAction::Remove,
                CanaryRemovalPostcondition::Absent
            ) | (
                CanaryRemovalAction::Retain | CanaryRemovalAction::Unsupported,
                CanaryRemovalPostcondition::Retained
            )
        );
        if !postcondition_matches {
            return Err(InstallationError::IdentityConflict);
        }
        if self.action == CanaryRemovalAction::Remove
            && (self.origin != CanaryRemovalResourceOrigin::CreatedByInstallTransaction
                || !self.reference_users.is_empty())
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.origin == CanaryRemovalResourceOrigin::ForeignToThisRemoval
            && self.install_effect_index.is_some()
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Quiesce and retirement evidence observed for the removal target.
///
/// Every member is derived from the accepted registry or the original
/// transaction's own durable state. No member is a caller-authored assurance,
/// so a deadline expiry or an empty list can never force a green cleanup.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalQuiesce {
    /// Active generation observed at plan time; the target never equals it.
    pub active_generation: Option<PlatformHandle>,
    /// Last-known-good generation observed at plan time.
    pub last_known_good_generation: Option<PlatformHandle>,
    /// Observed activation-owner handoff that retired the target from the
    /// active pointer, when the registry records one.
    pub retirement_barrier: Option<PlatformHandle>,
    /// Original installer effects that were not authoritatively applied.
    pub open_install_effects: u32,
    /// Original transaction external changes without acknowledgement.
    pub pending_external_changes: u32,
    /// Generation currently staged in a pending activation, when one exists.
    pub pending_activation_generation: Option<PlatformHandle>,
}

impl CanaryRemovalQuiesce {
    fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (
                &self.active_generation,
                "canary_removal.quiesce.active_generation",
            ),
            (
                &self.last_known_good_generation,
                "canary_removal.quiesce.last_known_good_generation",
            ),
            (
                &self.retirement_barrier,
                "canary_removal.quiesce.retirement_barrier",
            ),
            (
                &self.pending_activation_generation,
                "canary_removal.quiesce.pending_activation_generation",
            ),
        ] {
            if let Some(value) = value {
                handle(value, field)?;
            }
        }
        Ok(())
    }
}

/// Exact build identity a removal is bound to.
///
/// Every member is an artifact digest taken from the accepted candidate
/// manifest. Removal never re-derives a build identity from a name, a
/// directory suffix, a version string or a caller boolean.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalBuildBinding {
    /// Approved Host image digest of the target generation.
    pub host_artifact_digest: PlatformHandle,
    /// Approved Kernel image digest of the target generation.
    pub kernel_artifact_digest: PlatformHandle,
    /// Approved Store bridge image digest of the target generation.
    pub store_bridge_artifact_digest: PlatformHandle,
    /// Approved canonical Store engine image digest of the target generation.
    pub canonical_store_artifact_digest: PlatformHandle,
}

impl CanaryRemovalBuildBinding {
    fn from_manifest(manifest: &super::CandidateManifest) -> Result<Self, InstallationError> {
        let binding = Self {
            host_artifact_digest: manifest.host_artifact_digest.clone(),
            kernel_artifact_digest: manifest.kernel_artifact_digest.clone(),
            store_bridge_artifact_digest: manifest.store_bridge_artifact_digest.clone(),
            canonical_store_artifact_digest: manifest.canonical_store_artifact_digest.clone(),
        };
        for (value, field) in [
            (
                &binding.host_artifact_digest,
                "canary_removal.build.host_artifact_digest",
            ),
            (
                &binding.kernel_artifact_digest,
                "canary_removal.build.kernel_artifact_digest",
            ),
            (
                &binding.store_bridge_artifact_digest,
                "canary_removal.build.store_bridge_artifact_digest",
            ),
            (
                &binding.canonical_store_artifact_digest,
                "canary_removal.build.canonical_store_artifact_digest",
            ),
        ] {
            sha256_handle(value, field)?;
        }
        Ok(binding)
    }
}

/// Read-only, versioned plan for removing one exact installed canary.
///
/// The plan is the complete finite denominator of the removal: every closed
/// resource category the accepted registry or the original transaction can
/// describe is present exactly once, and every category that is not removed is
/// present with an explicit `RETAINED` or `UNSUPPORTED` action.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalPlan {
    /// Versioned wire discriminator for this plan.
    pub canary_removal_wire_version: ContractVersion,
    /// Durable removal operation identity bound to the installed transaction.
    pub removal_transaction_id: PlatformHandle,
    /// Original installation transaction that installed the target.
    pub install_transaction_id: PlatformHandle,
    /// Immutable installer plan digest of that original transaction.
    pub install_plan_digest: PlatformHandle,
    /// Installation identity, lineage and sequence of the target.
    pub installation_epoch: InstallationEpoch,
    /// Exact generation this plan removes.
    pub generation: PlatformHandle,
    /// Canonical digest of the accepted target candidate manifest.
    pub manifest_digest: PlatformHandle,
    /// Build identity of the target generation.
    pub build: CanaryRemovalBuildBinding,
    /// Registry revision this plan was resolved against.
    pub registry_revision: u64,
    /// Explicit canary-removal authorization and its request identity.
    pub request: ManagedEnvironmentChangeRequest,
    /// Observed quiesce and retirement evidence.
    pub quiesce: CanaryRemovalQuiesce,
    /// Complete frozen effect graph, ordered by execution dependency.
    pub effects: Vec<CanaryRemovalEffect>,
    /// Digest binding this whole plan to its single removal operation identity.
    pub plan_digest: PlatformHandle,
}

impl CanaryRemovalPlan {
    /// Recomputes the domain-separated plan digest over every plan member
    /// except the digest itself.
    pub fn computed_digest(&self) -> Result<PlatformHandle, InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            canary_removal_wire_version: ContractVersion,
            removal_transaction_id: &'a PlatformHandle,
            install_transaction_id: &'a PlatformHandle,
            install_plan_digest: &'a PlatformHandle,
            installation_epoch: &'a InstallationEpoch,
            generation: &'a PlatformHandle,
            manifest_digest: &'a PlatformHandle,
            build: &'a CanaryRemovalBuildBinding,
            registry_revision: u64,
            request: &'a ManagedEnvironmentChangeRequest,
            quiesce: &'a CanaryRemovalQuiesce,
            effects: &'a [CanaryRemovalEffect],
        }

        let bytes = super::canonical_json_bytes(&DigestInput {
            canary_removal_wire_version: self.canary_removal_wire_version,
            removal_transaction_id: &self.removal_transaction_id,
            install_transaction_id: &self.install_transaction_id,
            install_plan_digest: &self.install_plan_digest,
            installation_epoch: &self.installation_epoch,
            generation: &self.generation,
            manifest_digest: &self.manifest_digest,
            build: &self.build,
            registry_revision: self.registry_revision,
            request: &self.request,
            quiesce: &self.quiesce,
            effects: &self.effects,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "canary_removal.plan.plan_digest".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| platform_error(&error))
    }

    /// Validates the plan without performing any external effect.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.canary_removal_wire_version != CANARY_REMOVAL_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "canary-removal plan wire {} cannot be read as {}",
                    self.canary_removal_wire_version, CANARY_REMOVAL_WIRE_VERSION
                ),
            });
        }
        if self.registry_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.plan.registry_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        for (value, field) in [
            (
                &self.removal_transaction_id,
                "canary_removal.plan.removal_transaction_id",
            ),
            (
                &self.install_transaction_id,
                "canary_removal.plan.install_transaction_id",
            ),
            (
                &self.install_plan_digest,
                "canary_removal.plan.install_plan_digest",
            ),
            (&self.generation, "canary_removal.plan.generation"),
        ] {
            handle(value, field)?;
        }
        sha256_handle(&self.manifest_digest, "canary_removal.plan.manifest_digest")?;
        sha256_handle(&self.plan_digest, "canary_removal.plan.plan_digest")?;
        self.installation_epoch.validate()?;
        self.request.validate()?;
        if self.request.action != ManagedEnvironmentAction::Remove
            || self.request.exact_candidate != self.generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.removal_transaction_id
            == canary_removal_operation_id(&self.install_transaction_id, &self.generation)?
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.quiesce.validate()?;
        if self.quiesce.active_generation.as_ref() == Some(&self.generation)
            || self.quiesce.last_known_good_generation.as_ref() == Some(&self.generation)
            || self.quiesce.open_install_effects != 0
            || self.quiesce.pending_external_changes != 0
            || self.quiesce.pending_activation_generation.as_ref() == Some(&self.generation)
        {
            return Err(InstallationError::IncompleteObservation(
                "canary removal requires an observed retirement of the target from the active pointer, the last-known-good pointer, any pending activation and every open install effect"
                    .to_owned(),
            ));
        }
        if self.effects.is_empty() {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.plan.effects".to_owned(),
                reason: "must contain the complete finite removal inventory".to_owned(),
            });
        }
        let mut identities = BTreeSet::new();
        let mut categories = BTreeSet::new();
        for effect in &self.effects {
            effect.validate()?;
            if !identities.insert(effect.effect_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "canary removal effect".to_owned(),
                    identity: effect.effect_id.as_str().to_owned(),
                });
            }
            if !categories.insert(effect.category) {
                return Err(InstallationError::Duplicate {
                    kind: "canary removal resource category".to_owned(),
                    identity: format!("{:?}", effect.category),
                });
            }
        }
        for effect in &self.effects {
            if effect
                .prerequisites
                .iter()
                .any(|value| !identities.contains(value.as_str()))
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if !categories.contains(&CanaryRemovalResource::GenerationRegistryRecord) {
            return Err(InstallationError::IncompleteObservation(
                "the terminal registry record must stay inside the removal denominator".to_owned(),
            ));
        }
        if self.computed_digest()? != self.plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Durable stage of one admitted canary-removal operation.
///
/// The stage is a pure projection of the durable per-row evidence, so a green
/// stage can never be written over an unresolved effect.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalStage {
    /// Removal intent is durable and no removal effect has started.
    Admitted,
    /// At least one removal effect is executing under its committed intent and
    /// none has been resolved yet.
    Executing,
    /// At least one effect outcome is unknown and requires reconciliation.
    Reconciling,
    /// Every resource outcome is observed and the terminal registry record is
    /// committed under the expected registry revision.
    Completed,
}

/// Authoritative resolution of one removal row.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalEffectDisposition {
    /// The exact previously admitted object is authoritatively absent.
    Absent,
    /// The removal mutation was issued and its postcondition was read back.
    Removed,
    /// The resource was intentionally left intact with its admitted identity.
    Retained,
}

/// Durable per-row state of one admitted canary-removal operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum CanaryRemovalEffectState {
    /// No removal intent has been committed for this row.
    Pending,
    /// The exact intent was durably committed before the mutating call.
    IntentCommitted {
        /// Non-zero execution attempt inside the row bound.
        attempt: u32,
        /// Digest of the exact removal request authorized for this attempt.
        intent_digest: PlatformHandle,
    },
    /// Authoritative readback proved the row's exact postcondition.
    Resolved {
        /// Observed postcondition class.
        disposition: CanaryRemovalEffectDisposition,
        /// Evidence proving the postcondition.
        evidence: Vec<PlatformHandle>,
    },
    /// The external outcome is unknown and requires reconciliation.
    Unknown {
        /// Stable evidence or failure reference retained for recovery.
        pending_ref: PlatformHandle,
    },
}

/// One durable progress entry bound one-to-one to a frozen plan row.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalEffectProgress {
    /// Removal effect identity from the frozen plan.
    pub effect_id: PlatformHandle,
    /// Current durable state of this row.
    pub state: CanaryRemovalEffectState,
}

/// Durable governed canary-removal operation bound to the original installed
/// transaction.
///
/// The original installation transaction is never reopened, reset or rolled
/// back by this record. It stays the sole owner of the install history; this
/// record owns only the removal intent, the removal-to-install linkage, the
/// per-row durable progress and the terminal disposition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalOperation {
    /// Versioned wire discriminator for this durable operation.
    pub canary_removal_wire_version: ContractVersion,
    /// Sole durable removal operation identity.
    pub removal_transaction_id: PlatformHandle,
    /// The frozen read-only plan this operation executes.
    pub plan: CanaryRemovalPlan,
    /// Current durable removal stage.
    pub stage: CanaryRemovalStage,
    /// Ordered durable per-row progress, one entry per plan row.
    pub effect_progress: Vec<CanaryRemovalEffectProgress>,
    /// Exact removal effect that currently blocks the terminal disposition.
    pub blocking_effect_id: Option<PlatformHandle>,
    /// Absolute injected-clock deadline of this operation's bounded reconcile
    /// wait.
    ///
    /// It is computed once at admission and never recomputed, so a resumed
    /// reconcile re-derives its remaining window from this recorded value
    /// instead of restarting the budget. It is a bound on driving, not a
    /// resolution: reaching it leaves every unresolved row, the blocking
    /// effect and the non-terminal stage exactly as observed.
    pub reconcile_deadline_ms: u64,
    /// Monotonic state revision used by the durable compare-and-save path.
    pub revision: u64,
}

impl CanaryRemovalOperation {
    /// Admits one removal operation from an already validated plan.
    fn admit(plan: CanaryRemovalPlan) -> Result<Self, InstallationError> {
        plan.validate()?;
        let mut effect_progress = Vec::with_capacity(plan.effects.len());
        for effect in &plan.effects {
            effect_progress.push(CanaryRemovalEffectProgress {
                effect_id: effect.effect_id.clone(),
                state: if effect.action == CanaryRemovalAction::Remove {
                    CanaryRemovalEffectState::Pending
                } else {
                    CanaryRemovalEffectState::Resolved {
                        disposition: CanaryRemovalEffectDisposition::Retained,
                        evidence: effect.ownership_evidence.clone(),
                    }
                },
            });
        }
        let operation = Self {
            canary_removal_wire_version: CANARY_REMOVAL_WIRE_VERSION,
            removal_transaction_id: plan.removal_transaction_id.clone(),
            plan,
            stage: CanaryRemovalStage::Admitted,
            effect_progress,
            blocking_effect_id: None,
            // The one deadline of the whole reconcile wait, taken once from the
            // observed clock at admission. It is never recomputed afterwards,
            // so neither a retry nor a resumed reconcile can restart it.
            reconcile_deadline_ms: wall_clock_millis()
                .saturating_add(CANARY_REMOVAL_RECONCILE_TIMEOUT_MS),
            revision: 1,
        };
        operation.validate()?;
        Ok(operation)
    }

    /// Validates the durable operation against its own frozen plan.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.canary_removal_wire_version != CANARY_REMOVAL_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "canary-removal operation wire {} cannot be read as {}",
                    self.canary_removal_wire_version, CANARY_REMOVAL_WIRE_VERSION
                ),
            });
        }
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        if self.reconcile_deadline_ms == 0 {
            return Err(InstallationError::InvalidField {
                field: "canary_removal.reconcile_deadline_ms".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.plan.validate()?;
        if self.removal_transaction_id != self.plan.removal_transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        if self.effect_progress.len() != self.plan.effects.len() {
            return Err(InstallationError::IncompleteObservation(
                "canary removal progress must stay one-to-one with its frozen plan".to_owned(),
            ));
        }
        for (effect, progress) in self.plan.effects.iter().zip(&self.effect_progress) {
            if progress.effect_id != effect.effect_id {
                return Err(InstallationError::IdentityConflict);
            }
            let admissible = match &progress.state {
                CanaryRemovalEffectState::Pending => effect.action == CanaryRemovalAction::Remove,
                CanaryRemovalEffectState::IntentCommitted {
                    attempt,
                    intent_digest,
                } => {
                    sha256_handle(intent_digest, "canary_removal.progress.intent_digest")?;
                    effect.action == CanaryRemovalAction::Remove
                        && *attempt > 0
                        && *attempt == effect.bound.attempt
                        && *attempt <= effect.bound.max_attempts
                }
                CanaryRemovalEffectState::Resolved {
                    disposition,
                    evidence,
                } => {
                    handles(evidence, "canary_removal.progress.evidence", true)?;
                    matches!(
                        (effect.action, *disposition),
                        (
                            CanaryRemovalAction::Remove,
                            CanaryRemovalEffectDisposition::Absent
                                | CanaryRemovalEffectDisposition::Removed
                        ) | (
                            CanaryRemovalAction::Retain | CanaryRemovalAction::Unsupported,
                            CanaryRemovalEffectDisposition::Retained
                        )
                    )
                }
                CanaryRemovalEffectState::Unknown { pending_ref } => {
                    handle(pending_ref, "canary_removal.progress.pending_ref")?;
                    effect.action == CanaryRemovalAction::Remove
                }
            };
            if !admissible {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if let Some(blocking) = &self.blocking_effect_id
            && !self
                .effect_progress
                .iter()
                .any(|progress| &progress.effect_id == blocking)
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.expected_stage()?;
        Ok(())
    }

    /// Derives the only stage the durable per-row evidence admits.
    ///
    /// The stage is never authored independently: a green stage over an
    /// unresolved effect is refused here and can never be persisted.
    fn expected_stage(&self) -> Result<(), InstallationError> {
        let mut open = 0_usize;
        let mut unknown = 0_usize;
        let mut started = 0_usize;
        for (effect, progress) in self.plan.effects.iter().zip(&self.effect_progress) {
            if effect.action != CanaryRemovalAction::Remove {
                continue;
            }
            match progress.state {
                CanaryRemovalEffectState::Pending => open += 1,
                CanaryRemovalEffectState::IntentCommitted { .. }
                | CanaryRemovalEffectState::Resolved { .. } => {
                    open += 1;
                    started += 1;
                }
                CanaryRemovalEffectState::Unknown { .. } => {
                    open += 1;
                    unknown += 1;
                    started += 1;
                }
            }
        }
        let expected = if unknown > 0 {
            CanaryRemovalStage::Reconciling
        } else if open == 0 {
            CanaryRemovalStage::Completed
        } else if started > 0 {
            CanaryRemovalStage::Executing
        } else {
            CanaryRemovalStage::Admitted
        };
        if self.stage != expected {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    fn project(&self) -> CanaryRemovalStatus {
        let mut resolved_effect_ids = Vec::new();
        let mut unresolved_effect_ids = Vec::new();
        let mut evidence_refs = Vec::new();
        let mut primary_uncertainty = None;
        let mut cleanup_uncertainty = None;
        for progress in &self.effect_progress {
            match &progress.state {
                CanaryRemovalEffectState::Resolved { evidence, .. } => {
                    resolved_effect_ids.push(progress.effect_id.clone());
                    evidence_refs.extend(evidence.iter().cloned());
                }
                CanaryRemovalEffectState::Unknown { pending_ref } => {
                    unresolved_effect_ids.push(progress.effect_id.clone());
                    if self.plan.effects.iter().any(|effect| {
                        effect.effect_id == progress.effect_id
                            && effect.category == CanaryRemovalResource::GenerationRegistryRecord
                    }) {
                        cleanup_uncertainty = Some(pending_ref.clone());
                    }
                    if primary_uncertainty.is_none() {
                        primary_uncertainty = Some(pending_ref.clone());
                    }
                }
                CanaryRemovalEffectState::Pending
                | CanaryRemovalEffectState::IntentCommitted { .. } => {
                    unresolved_effect_ids.push(progress.effect_id.clone());
                }
            }
        }
        let removals_resolved =
            self.plan
                .effects
                .iter()
                .zip(&self.effect_progress)
                .all(|(effect, progress)| {
                    effect.action != CanaryRemovalAction::Remove
                        || matches!(progress.state, CanaryRemovalEffectState::Resolved { .. })
                });
        let next_permitted_action = match self.stage {
            CanaryRemovalStage::Completed => CanaryRemovalNextAction::Readback,
            CanaryRemovalStage::Reconciling if cleanup_uncertainty.is_some() => {
                CanaryRemovalNextAction::ManualRecovery
            }
            CanaryRemovalStage::Reconciling | CanaryRemovalStage::Executing => {
                if removals_resolved {
                    CanaryRemovalNextAction::Readback
                } else {
                    CanaryRemovalNextAction::Reconcile
                }
            }
            CanaryRemovalStage::Admitted => CanaryRemovalNextAction::Reconcile,
        };
        CanaryRemovalStatus {
            removal_transaction_id: self.removal_transaction_id.clone(),
            install_transaction_id: self.plan.install_transaction_id.clone(),
            generation: self.plan.generation.clone(),
            plan_digest: self.plan.plan_digest.clone(),
            stage: self.stage,
            registry_revision: self.plan.registry_revision,
            resolved_effect_ids,
            unresolved_effect_ids,
            blocking_effect_id: self.blocking_effect_id.clone(),
            primary_uncertainty,
            cleanup_uncertainty,
            next_permitted_action,
            evidence_refs,
        }
    }
}

/// Next action the installation owner admits for one removal operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CanaryRemovalNextAction {
    /// Re-run the owner-driven readback and reconciliation for this operation.
    Reconcile,
    /// Re-run the independent final readback for this operation.
    Readback,
    /// The named blocking effect needs bounded manual recovery; no automatic
    /// retry is admitted under this removal operation identity.
    ManualRecovery,
}

/// Stable, secret-free disposition of one canary-removal operation.
///
/// Every member is an identity handle, a digest or a typed class. The
/// projection never carries a secret value, credential ciphertext, provider
/// output or an unretained raw path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRemovalStatus {
    /// Durable removal operation identity.
    pub removal_transaction_id: PlatformHandle,
    /// Original installation transaction this removal is bound to.
    pub install_transaction_id: PlatformHandle,
    /// Exact generation under removal.
    pub generation: PlatformHandle,
    /// Frozen plan digest this disposition was computed from.
    pub plan_digest: PlatformHandle,
    /// Durable removal stage.
    pub stage: CanaryRemovalStage,
    /// Registry revision the plan was admitted against.
    pub registry_revision: u64,
    /// Removal effects with an authoritative outcome.
    pub resolved_effect_ids: Vec<PlatformHandle>,
    /// Removal effects still requiring reconciliation or execution.
    pub unresolved_effect_ids: Vec<PlatformHandle>,
    /// Exact removal effect that currently blocks the terminal disposition.
    pub blocking_effect_id: Option<PlatformHandle>,
    /// Primary uncertainty retained for recovery.
    pub primary_uncertainty: Option<PlatformHandle>,
    /// Cleanup or diagnostic uncertainty retained beside the primary one.
    pub cleanup_uncertainty: Option<PlatformHandle>,
    /// The only action the owner admits next.
    pub next_permitted_action: CanaryRemovalNextAction,
    /// Non-secret evidence references retained for the resolved outcomes.
    pub evidence_refs: Vec<PlatformHandle>,
}

/// Revision/checksum version of one durable canary-removal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryRemovalOperationVersion {
    pub(crate) revision: u64,
    pub(crate) checksum: String,
}

impl CanaryRemovalOperationVersion {
    /// Derives the durable version from a validated operation value.
    pub(crate) fn of(operation: &CanaryRemovalOperation) -> Result<Self, InstallationError> {
        operation.validate()?;
        let bytes =
            serde_json::to_vec(operation).map_err(|error| InstallationError::CorruptRegistry {
                reason: error.to_string(),
            })?;
        Ok(Self {
            revision: operation.revision,
            checksum: sha256_hex(&bytes),
        })
    }
}

/// Derives the one durable removal operation identity for one installed
/// generation.
///
/// The identity is a pure function of the original installed transaction and
/// the target generation, so a reused identity can only ever describe the same
/// removal inputs; changed inputs are refused instead of silently admitted.
pub fn canary_removal_operation_id(
    install_transaction_id: &PlatformHandle,
    generation: &PlatformHandle,
) -> Result<PlatformHandle, InstallationError> {
    handle(
        install_transaction_id,
        "canary_removal.install_transaction_id",
    )?;
    handle(generation, "canary_removal.generation")?;
    PlatformHandle::new(format!(
        "{CANARY_REMOVAL_OPERATION_PREFIX}{}:{}",
        install_transaction_id.as_str(),
        generation.as_str()
    ))
    .map_err(|error| platform_error(&error))
}

/// Resolves the exact installed canary target and returns the frozen,
/// read-only removal plan.
///
/// This step loads the accepted installation registry, the original
/// transaction and any already admitted removal record read-only and creates
/// no file, secret, service, reservation or transaction row. A foreign,
/// ambiguous, replaced, production or last-known-good target is refused here,
/// before any destructive path exists. A reused removal identity with changed
/// inputs is refused here as well, so a conflicting re-admission fails fast
/// at the plan boundary instead of only at apply.
#[allow(
    clippy::too_many_lines,
    reason = "read-only target resolution keeps every refusal in one auditable boundary"
)]
pub(crate) fn plan_canary_removal<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    request: &ManagedEnvironmentChangeRequest,
    generation: &PlatformHandle,
) -> Result<CanaryRemovalPlan, InstallationError>
where
    P: InstallationEffectPort,
{
    request.validate()?;
    if request.action != ManagedEnvironmentAction::Remove {
        return Err(InstallationError::InvalidField {
            field: "canary_removal.request.action".to_owned(),
            reason: "canary removal requires an explicit Remove authorization".to_owned(),
        });
    }
    if &request.exact_candidate != generation {
        return Err(InstallationError::IdentityConflict);
    }
    handle(generation, "canary_removal.generation")?;
    let projection = registry.load()?;
    projection.validate()?;
    let target = resolve_approved_generation(&projection, generation)?;
    if target.active
        || target.last_known_good
        || projection
            .active_generation()
            .is_some_and(|active| active == generation)
        || projection
            .last_known_good_generation()
            .is_some_and(|lkg| lkg == generation)
    {
        return Err(InstallationError::IncompleteObservation(format!(
            "generation {} serves production or is the designated last-known-good; removal requires an observed authorized handoff through the activation owner first",
            generation.as_str()
        )));
    }
    let install = coordinator
        .store()
        .load(target.approval.transaction_id())?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: target.approval.transaction_id().as_str().to_owned(),
        })?;
    install.validate()?;
    if install.candidate_manifest.generation != *generation {
        return Err(InstallationError::IdentityConflict);
    }
    if install.stage() != InstallationStage::Completed {
        return Err(InstallationError::IncompleteObservation(format!(
            "canary removal requires a completed installation transaction, observed {:?}",
            install.stage()
        )));
    }
    if install.has_activation_projection_intent() {
        return Err(InstallationError::IncompleteObservation(
            "the activation owner still holds this transaction's pending activation intent"
                .to_owned(),
        ));
    }
    install.require_all_effects_applied()?;
    if !install.pending_external_changes.is_empty() {
        return Err(InstallationError::IncompleteObservation(
            "the installed transaction still carries unacknowledged external changes".to_owned(),
        ));
    }
    if install.installer_plan_digest != *target.approval.installer_plan_digest() {
        return Err(InstallationError::IdentityConflict);
    }
    let manifest_digest = candidate_manifest_digest(&target.manifest)?;
    if manifest_digest != candidate_manifest_digest(&install.candidate_manifest)? {
        return Err(InstallationError::IdentityConflict);
    }
    let survivors = surviving_generations(&projection, generation);
    let effects = freeze_effect_graph(&install, &survivors)?;
    let quiesce = CanaryRemovalQuiesce {
        active_generation: projection.active_generation().cloned(),
        last_known_good_generation: projection.last_known_good_generation().cloned(),
        retirement_barrier: observed_retirement_barrier(&projection, generation),
        open_install_effects: open_install_effect_count(&install)?,
        pending_external_changes: pending_external_change_count(&install)?,
        pending_activation_generation: projection
            .pending_activation
            .as_ref()
            .map(|pending| pending.manifest.generation.clone()),
    };
    let mut plan = CanaryRemovalPlan {
        canary_removal_wire_version: CANARY_REMOVAL_WIRE_VERSION,
        removal_transaction_id: canary_removal_operation_id(
            target.approval.transaction_id(),
            generation,
        )?,
        install_transaction_id: target.approval.transaction_id().clone(),
        install_plan_digest: install.installer_plan_digest.clone(),
        installation_epoch: install.installation_epoch.clone(),
        generation: generation.clone(),
        manifest_digest,
        build: CanaryRemovalBuildBinding::from_manifest(&install.candidate_manifest)?,
        registry_revision: projection.revision(),
        request: request.clone(),
        quiesce,
        effects,
        plan_digest: PlatformHandle::new("0".repeat(64)).map_err(|error| platform_error(&error))?,
    };
    plan.plan_digest = plan.computed_digest()?;
    plan.validate()?;
    // The admission fence fails fast at the plan boundary as well as durably
    // at apply: a removal already admitted for this exact target under
    // different inputs is an identity conflict here, mirroring
    // `admit_or_resume`. An identical digest proceeds so an idempotent re-plan
    // still resumes through the same operation identity.
    if let Some(existing) = coordinator
        .store()
        .load_canary_removal_for_generation(&plan.install_transaction_id, generation)?
    {
        existing.validate()?;
        if existing.plan.plan_digest != plan.plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(plan)
}

/// Admits and drives one removal operation for an already frozen plan.
///
/// Admission revalidates the exact plan digest and the current registry
/// revision, records the removal intent durably and only then issues a
/// destructive call. A reused removal identity with changed inputs is an
/// identity conflict; an identical replay resumes the same operation.
///
/// The drive is additionally bounded by the operation's one recorded reconcile
/// deadline, so a replay of an already admitted plan can never buy a fresh
/// unbounded wait.
pub(crate) fn apply_canary_removal<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    plan: &CanaryRemovalPlan,
) -> Result<CanaryRemovalStatus, InstallationError>
where
    P: InstallationEffectPort,
{
    let mut operation = admit_or_resume(coordinator, plan)?;
    if reconcile_budget_exhausted(&operation) {
        return Ok(operation.project());
    }
    let install = revalidate_fence(coordinator, registry, &operation)?;
    advance(coordinator, registry, &mut operation, &install)?;
    operation.validate()?;
    Ok(operation.project())
}

/// Reconciles one already admitted removal operation.
///
/// Recovery reuses the same operation identity and the same per-row intent
/// digests. It reconciles before any further attempt and never admits a fresh
/// removal identity for an unresolved effect.
pub(crate) fn recover_canary_removal<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    removal_transaction_id: &PlatformHandle,
) -> Result<CanaryRemovalStatus, InstallationError>
where
    P: InstallationEffectPort,
{
    let mut operation = load_operation(coordinator, removal_transaction_id)?;
    if operation.stage == CanaryRemovalStage::Completed {
        return Ok(operation.project());
    }
    if reconcile_budget_exhausted(&operation) {
        return Ok(operation.project());
    }
    let install = revalidate_fence(coordinator, registry, &operation)?;
    advance(coordinator, registry, &mut operation, &install)?;
    operation.validate()?;
    Ok(operation.project())
}

/// Requires the frozen effect graph to account for the install transaction's
/// own effect roster exactly.
///
/// The expected set is the original transaction's `installer_effects`, which
/// the installation owner durably recorded, not any list supplied alongside the
/// removal request and not the plan's own rows. Every member of that roster
/// must have exactly one plan row naming that exact effect identity, and every
/// plan row that claims an installer effect must name a member of the roster at
/// that exact position. A missing member means an exact job, pending write,
/// ORS operation, outbox row or external effect that this removal would
/// checkpoint, cancel or resolve without ever naming it, so the removal is
/// refused here rather than reported as a complete quiesce.
fn require_complete_effect_coverage(
    install: &InstallationTransaction,
    plan: &CanaryRemovalPlan,
) -> Result<(), InstallationError> {
    // Expected set: the effect identities the installation owner durably
    // recorded for the installed transaction.
    let mut expected = BTreeSet::new();
    for effect in &install.installer_effects {
        expected.insert(effect.effect_id().as_str());
    }
    // Observed set: the identities the frozen graph claims for that roster,
    // each re-read from the roster position the row itself names. A row that
    // names no position, an out-of-range position, or a position whose recorded
    // identity differs from the row's own identity all fail here.
    let mut observed = BTreeSet::new();
    for row in &plan.effects {
        let Some(index) = row.install_effect_index else {
            continue;
        };
        let index = usize::try_from(index).map_err(|_| InstallationError::IdentityConflict)?;
        let effect = install
            .installer_effects
            .get(index)
            .ok_or(InstallationError::IncompleteObservation(
            "a removal effect names an installer effect the installed transaction does not have"
                .to_owned(),
        ))?;
        if effect.effect_id() != &row.effect_id {
            return Err(InstallationError::IdentityConflict);
        }
        if !observed.insert(row.effect_id.as_str()) {
            return Err(InstallationError::Duplicate {
                kind: "canary removal installer effect coverage".to_owned(),
                identity: row.effect_id.as_str().to_owned(),
            });
        }
    }
    if observed != expected {
        return Err(InstallationError::IncompleteObservation(
            "the frozen removal effect graph does not account for the installed transaction's own effect roster"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Quiesces the canary's own owner effects before any dependent stop/delete.
///
/// `I14.23` orders a governed drain as "revoke/finish expiring action
/// authority; request jobs/modules checkpoint/cancel; drain canonical writes and
/// reconcile pending receipts; flush audit/outbox/ORS", and `I14.24` states the
/// matching recovery obligations as "revoke session/leases; checkpoint task/work
/// graph" and "revoke broker/session launch leases". This function is the
/// installation owner's half of that drain, and it is deliberately built out of
/// the owners that already exist rather than a second revocation scheme: there
/// is no second lease table, no parallel session registry, no new token format
/// and no port method added for it.
///
/// Every identity below is derived from the install transaction's own durable
/// record, and the plan contributes the second, independent set. A checkpoint
/// over a guessed job list, or a caller-supplied set reconciled against itself,
/// proves nothing and is refused here because the two sets are compared rather
/// than self-compared.
///
/// The three clauses of the drain are:
///
/// * **Exact jobs.** `require_all_effects_applied` is the existing owner
///   validator for "every installer effect this transaction durably created is
///   authoritatively settled", and `require_complete_effect_coverage` is what
///   makes that exact by naming each of them in the frozen graph. Their removal
///   is then driven row by row through the existing `InstallationEffectPort`
///   with the existing `Rollback` action, so each row's postcondition is read
///   back from the resource's own owner rather than assumed.
/// * **Pending writes, ORS, outbox and possible external effects.** The
///   transaction's own `pending_external_changes` is the only accepted source of
///   that set, and it must both be empty and equal the count the frozen plan
///   recorded. A caller that presents a narrower set than the transaction owns
///   is an identity conflict, not a clean drain.
/// * **Canary leases, sessions and routes.** The authority that can admit this
///   canary's leases, sessions and routes is the transaction's own supervision
///   authority. Its stable lease scope identity is validated in either strict
///   binding state, and when the authority is provisioned the existing owner's
///   own `validate()` is run against the originally recorded receipt - the owner
///   compares its recorded `watchdog_admission_template_digest` and
///   `provision_receipt_digest` itself. Nothing here recomputes a fresh digest
///   to stand in for that check, and nothing re-mints a lease, session or route
///   token. The only claim this owner makes is the one it can prove from its own
///   record: the authority that would admit those authorities is bound to this
///   exact generation of this exact installation, so retiring the generation
///   retires them with it. A transaction still holding a live activation
///   projection intent - the canary's own activation session boundary in this
///   owner - is refused outright.
///
/// The owner-derived rows are re-derived here and compared identity for
/// identity against the frozen plan. That is what stops a plan from naming a
/// substituted canary evidence root or a substituted Store/Blob object set and
/// still presenting itself as a complete owner-effect inventory, and it is what
/// keeps the shared and foreign rows `Retain` instead of letting a plan claim
/// to delete another generation's durable state.
///
/// Every failure is a refusal that leaves the durable incomplete recovery and
/// its blocking effect exactly as observed. A canary whose lease authority is
/// foreign, whose provision receipt does not validate, or whose owner-effect
/// identities do not re-derive is never removed by this owner.
fn require_quiesced_owner_effects(
    install: &InstallationTransaction,
    plan: &CanaryRemovalPlan,
) -> Result<(), InstallationError> {
    // Exact jobs: the existing owner validator, not a list assembled here.
    install.require_all_effects_applied()?;
    // Pending writes, ORS, outbox and possible external effects: resolved, and
    // the resolved set is the transaction's own rather than the request's.
    if !install.pending_external_changes.is_empty() {
        return Err(InstallationError::IncompleteObservation(
            "the installed transaction still carries unacknowledged external changes".to_owned(),
        ));
    }
    if pending_external_change_count(install)? != plan.quiesce.pending_external_changes
        || open_install_effect_count(install)? != plan.quiesce.open_install_effects
    {
        return Err(InstallationError::IdentityConflict);
    }
    // The canary's live activation session boundary: a held intent means the
    // activation owner can still project this generation, so its leases,
    // sessions and routes are not yet this removal's to retire.
    if install.has_activation_projection_intent() {
        return Err(InstallationError::IncompleteObservation(
            "the activation owner still holds this transaction's pending activation intent"
                .to_owned(),
        ));
    }
    let launch = &install.candidate_manifest.runtime_launch;
    // The lease/session/route admission authority of this exact generation. The
    // stable scope identity is validated in either strict binding state, so a
    // Phase-A candidate that never received a live overlay is still covered.
    let lease_scope = handle_ref(launch.supervision_lease_scope_id())?;
    if launch.generation != install.candidate_manifest.generation {
        return Err(InstallationError::IdentityConflict);
    }
    if let super::SupervisionAuthorityBinding::Provisioned { authority } =
        &launch.supervision_authority
    {
        // The existing lease owner's own validator, run against the originally
        // recorded receipt rather than against a digest recomputed here.
        authority
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "canary_removal.owner_effects.supervision_authority".to_owned(),
                reason: error.to_string(),
            })?;
        // The existing owner's own Watchdog admission template, validated by the
        // owner. This is the lease admission template that carries the canary's
        // lease scope, generation and trust anchor.
        let template = authority.watchdog_admission_template().map_err(|error| {
            InstallationError::InvalidField {
                field: "canary_removal.owner_effects.watchdog_admission_template".to_owned(),
                reason: error.to_string(),
            }
        })?;
        template
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "canary_removal.owner_effects.watchdog_admission_template".to_owned(),
                reason: error.to_string(),
            })?;
        // The authority must be this canary's own, in this installation. A
        // neighbour's or a foreign installation's authority is refused here
        // instead of being revoked under the wrong identity.
        let installation = &plan.installation_epoch.installation;
        if authority.supervision_lease_scope_id != lease_scope.as_str()
            || authority.candidate_generation != plan.generation.as_str()
            || authority.trust_anchor.installation_id != installation.as_str()
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    // The owner-derived rows, re-derived from the transaction and compared to
    // the frozen plan. Each category must appear exactly once, its identity
    // must be the one this transaction's own manifest derives, and the shared
    // or foreign rows must still be `Retain` so no plan can claim to delete
    // another generation's durable state.
    let expected_owners = [
        (
            CanaryRemovalResource::CanaryEvidenceRoot,
            install
                .candidate_manifest
                .runtime_launch
                .runtime_state_roots
                .canary_evidence_root()?,
            CanaryRemovalAction::Retain,
        ),
        (
            CanaryRemovalResource::StoreObjects,
            install.candidate_manifest.generation.clone(),
            CanaryRemovalAction::Retain,
        ),
        (
            CanaryRemovalResource::GenerationRegistryRecord,
            install.candidate_manifest.generation.clone(),
            CanaryRemovalAction::Remove,
        ),
    ];
    for (category, identity, action) in expected_owners {
        let mut rows = plan.effects.iter().filter(|row| row.category == category);
        let Some(row) = rows.next() else {
            return Err(InstallationError::IncompleteObservation(format!(
                "the frozen plan does not account for the canary's own {category:?} owner effect"
            )));
        };
        if rows.next().is_some() {
            return Err(InstallationError::Duplicate {
                kind: "canary removal owner-derived effect".to_owned(),
                identity: format!("{category:?}"),
            });
        }
        if row.resource_identity != identity || row.action != action {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(())
}

/// Re-observes the admission fence and the retirement barrier against the
/// owner's current durable projection.
///
/// The entry-point fence in `revalidate_fence` runs once per apply or recover
/// call. That is not enough for "stop new canary admissions": a pending
/// activation for the dying generation staged after that observation would
/// otherwise be green-lit for every remaining destructive row of the same
/// drive. The same owner projection is therefore re-read immediately before
/// each mutating call, so a new admission, a return to production or
/// last-known-good, or a lost retirement handoff refuses that row instead of
/// being inherited from a stale observation.
///
/// The expected set here is the plan's own frozen quiesce evidence and the
/// owner's own registry projection, never a list supplied alongside the
/// removal request.
fn observe_admission_fence(
    projection: &ApprovedGenerationRegistry,
    plan: &CanaryRemovalPlan,
) -> Result<(), InstallationError> {
    projection.validate()?;
    if projection
        .active_generation()
        .is_some_and(|active| active == &plan.generation)
        || projection
            .last_known_good_generation()
            .is_some_and(|lkg| lkg == &plan.generation)
    {
        return Err(InstallationError::IncompleteObservation(
            "the removal target serves production or is last-known-good again".to_owned(),
        ));
    }
    if let Some(pending) = &projection.pending_activation
        && pending.manifest.generation == plan.generation
    {
        return Err(InstallationError::IncompleteObservation(
            "the removal target is staged in a pending activation".to_owned(),
        ));
    }
    // The retirement barrier is the drain evidence a dependent stop/delete has
    // to follow. It must be recorded in the frozen plan and re-observed in this
    // same observation, so no stop/delete is ever issued for a target whose
    // retirement this attempt did not see.
    let Some(recorded) = &plan.quiesce.retirement_barrier else {
        return Err(InstallationError::IncompleteObservation(
            "a dependent canary stop/delete requires the observed activation-owner retirement barrier"
                .to_owned(),
        ));
    };
    if observed_retirement_barrier(projection, &plan.generation).as_ref() != Some(recorded) {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

/// Reports whether this operation's one recorded reconcile deadline has passed.
///
/// The window is re-derived from the durable operation state, never from a
/// fresh per-call budget, so a resumed or retried reconcile can neither restart
/// nor extend it. Every path that could issue a destructive call consults this
/// first: at expiry the drive is refused and the durable incomplete recovery is
/// preserved unchanged.
fn reconcile_budget_exhausted(operation: &CanaryRemovalOperation) -> bool {
    wall_clock_millis() >= operation.reconcile_deadline_ms
}

/// Returns the stable read-only disposition of one removal operation.
pub(crate) fn canary_removal_status<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    removal_transaction_id: &PlatformHandle,
) -> Result<CanaryRemovalStatus, InstallationError>
where
    P: InstallationEffectPort,
{
    Ok(load_operation(coordinator, removal_transaction_id)?.project())
}

fn resolve_approved_generation<'a>(
    projection: &'a ApprovedGenerationRegistry,
    generation: &PlatformHandle,
) -> Result<&'a super::ApprovedGeneration, InstallationError> {
    let mut matches = projection
        .generations()
        .iter()
        .filter(|entry| &entry.manifest.generation == generation);
    let Some(entry) = matches.next() else {
        return Err(InstallationError::IncompleteObservation(format!(
            "generation {} is not an approved generation of this installation",
            generation.as_str()
        )));
    };
    if matches.next().is_some() {
        return Err(InstallationError::Duplicate {
            kind: "approved generation".to_owned(),
            identity: generation.as_str().to_owned(),
        });
    }
    Ok(entry)
}

/// Counts the original transaction's installer effects that are not
/// authoritatively applied.
///
/// The count is read from the transaction's own durable effect roster, so a
/// frozen plan can never record an empty open-effect set that the install
/// record itself does not admit.
fn open_install_effect_count(install: &InstallationTransaction) -> Result<u32, InstallationError> {
    let open = install
        .effect_progress()
        .iter()
        .filter(|progress| {
            !matches!(
                progress.state,
                super::InstallationEffectProgressState::Applied { .. }
            )
        })
        .count();
    u32::try_from(open).map_err(|_| {
        InstallationError::IncompleteObservation(
            "the installed transaction names more open installer effects than one removal can record"
                .to_owned(),
        )
    })
}

/// Counts the original transaction's unacknowledged external changes.
///
/// These are the exact pending writes, ORS operations, outbox rows and external
/// effects the install record still carries unresolved. The count is taken from
/// that record rather than from any list supplied alongside the removal request,
/// so a caller cannot present a narrower set than the transaction owns.
fn pending_external_change_count(
    install: &InstallationTransaction,
) -> Result<u32, InstallationError> {
    u32::try_from(install.pending_external_changes.len()).map_err(|_| {
        InstallationError::IncompleteObservation(
            "the installed transaction names more pending external changes than one removal can record"
                .to_owned(),
        )
    })
}

/// Returns the exact observed handoff that retired the target from the active
/// pointer, when the activation owner recorded one.
///
/// A caller-supplied replacement generation is never accepted here: the only
/// admissible handoff evidence is the activation owner's own committed cutover
/// receipt naming the target as the predecessor it consumed.
fn observed_retirement_barrier(
    projection: &ApprovedGenerationRegistry,
    generation: &PlatformHandle,
) -> Option<PlatformHandle> {
    projection
        .committed_cutover_activation()
        .filter(|committed| committed.expected_predecessor == *generation)
        .map(|committed| committed.operation_id.clone())
}

fn surviving_generations(
    projection: &ApprovedGenerationRegistry,
    generation: &PlatformHandle,
) -> Vec<PlatformHandle> {
    projection
        .generations()
        .iter()
        .map(|entry| entry.manifest.generation.clone())
        .filter(|candidate| candidate != generation)
        .collect()
}

/// Freezes the complete finite removal effect graph from the original
/// transaction's own effect receipts.
///
/// The classification is uniform and evidence-bound: a row is `REMOVE` only
/// when the original transaction durably created the exact identity and no
/// surviving generation still references it; a shared or preexisting row is
/// `RETAINED` with its ownership evidence; a transaction-created row this owner
/// has no admitted removal path for is `UNSUPPORTED` and therefore blocks
/// apply instead of leaving the denominator.
fn freeze_effect_graph(
    install: &InstallationTransaction,
    survivors: &[PlatformHandle],
) -> Result<Vec<CanaryRemovalEffect>, InstallationError> {
    let mut rows = Vec::new();
    for (index, effect) in install.installer_effects.iter().enumerate() {
        let progress = install
            .effect_progress()
            .get(index)
            .ok_or(InstallationError::IdentityConflict)?;
        let (category, identity, shared, removal_supported) = match effect {
            InstallerEffectPlan::CreateRoot { .. } => (
                CanaryRemovalResource::InstallationRoot,
                applied_identity(progress)?,
                true,
                false,
            ),
            InstallerEffectPlan::ApplyAcl { .. } => (
                CanaryRemovalResource::InstallationAcl,
                applied_identity(progress)?,
                true,
                false,
            ),
            InstallerEffectPlan::StagePackage { .. } => (
                CanaryRemovalResource::GenerationPackageRoot,
                applied_identity(progress)?,
                false,
                true,
            ),
            InstallerEffectPlan::RegisterService { .. } => (
                CanaryRemovalResource::ServiceRegistration,
                applied_identity(progress)?,
                true,
                false,
            ),
            InstallerEffectPlan::StartService { .. } => (
                CanaryRemovalResource::ServiceStart,
                applied_identity(progress)?,
                true,
                false,
            ),
            InstallerEffectPlan::ProvisionStoreCredential { .. } => (
                CanaryRemovalResource::StoreCredential,
                applied_identity(progress)?,
                false,
                true,
            ),
            InstallerEffectPlan::MaterializePhaseB { .. } => (
                CanaryRemovalResource::PhaseBLiveOverlay,
                applied_identity(progress)?,
                true,
                false,
            ),
        };
        let created = matches!(
            progress.state,
            super::InstallationEffectProgressState::Applied {
                disposition: super::InstallationEffectDisposition::CreatedByTransaction,
                ..
            }
        );
        let origin = if created {
            CanaryRemovalResourceOrigin::CreatedByInstallTransaction
        } else {
            CanaryRemovalResourceOrigin::PreexistingAtInstall
        };
        let reference_users = if shared {
            survivors.to_vec()
        } else {
            Vec::new()
        };
        let action = classify_action(origin, !reference_users.is_empty(), removal_supported);
        rows.push(CanaryRemovalEffect {
            effect_id: effect.effect_id().clone(),
            category,
            origin,
            action,
            resource_identity: identity,
            ownership_evidence: ownership_evidence(install, index)?,
            reference_users,
            prerequisites: Vec::new(),
            expected_postcondition: if action == CanaryRemovalAction::Remove {
                CanaryRemovalPostcondition::Absent
            } else {
                CanaryRemovalPostcondition::Retained
            },
            reconciliation_query: reconciliation_query(install, index, action)?,
            bound: CanaryRemovalEffectBound::new(),
            install_effect_index: Some(u32::try_from(index).map_err(|_| {
                InstallationError::InvalidField {
                    field: "canary_removal.effect.install_effect_index".to_owned(),
                    reason: "installer effect index is out of range".to_owned(),
                }
            })?),
        });
    }
    rows.push(canary_evidence_row(install, survivors)?);
    rows.push(store_objects_row(&install.candidate_manifest.generation)?);
    rows.push(registry_record_row(&install.candidate_manifest.generation)?);
    order_effect_graph(&mut rows);
    Ok(rows)
}

fn classify_action(
    origin: CanaryRemovalResourceOrigin,
    referenced: bool,
    removal_supported: bool,
) -> CanaryRemovalAction {
    if origin != CanaryRemovalResourceOrigin::CreatedByInstallTransaction || referenced {
        CanaryRemovalAction::Retain
    } else if removal_supported {
        CanaryRemovalAction::Remove
    } else {
        CanaryRemovalAction::Unsupported
    }
}

fn applied_identity(
    progress: &super::InstallationEffectProgress,
) -> Result<PlatformHandle, InstallationError> {
    match &progress.state {
        super::InstallationEffectProgressState::Applied {
            external_identity, ..
        } => Ok(external_identity.clone()),
        _ => Err(InstallationError::IncompleteObservation(
            "canary removal requires an applied installer effect receipt".to_owned(),
        )),
    }
}

fn ownership_evidence(
    install: &InstallationTransaction,
    index: usize,
) -> Result<Vec<PlatformHandle>, InstallationError> {
    let progress = install
        .effect_progress()
        .get(index)
        .ok_or(InstallationError::IdentityConflict)?;
    let super::InstallationEffectProgressState::Applied {
        evidence,
        postcondition_digest,
        ..
    } = &progress.state
    else {
        return Err(InstallationError::IncompleteObservation(
            "canary removal requires an applied installer effect receipt".to_owned(),
        ));
    };
    let mut owned = vec![
        handle_ref(&format!(
            "canary-removal/evidence/install-effect:{}:{}",
            install.transaction_id.as_str(),
            install.installer_effects[index].effect_id().as_str()
        ))?,
        postcondition_digest.clone(),
    ];
    owned.extend(evidence.iter().cloned());
    Ok(owned)
}

fn reconciliation_query(
    install: &InstallationTransaction,
    index: usize,
    action: CanaryRemovalAction,
) -> Result<PlatformHandle, InstallationError> {
    let disposition = if action == CanaryRemovalAction::Remove {
        "remove"
    } else {
        "retain"
    };
    PlatformHandle::new(format!(
        "canary-removal/reconcile/{disposition}:{}:{}",
        install.transaction_id.as_str(),
        install.installer_effects[index].effect_id().as_str()
    ))
    .map_err(|error| platform_error(&error))
}

fn canary_evidence_row(
    install: &InstallationTransaction,
    survivors: &[PlatformHandle],
) -> Result<CanaryRemovalEffect, InstallationError> {
    let root = install
        .candidate_manifest
        .runtime_launch
        .runtime_state_roots
        .canary_evidence_root()?;
    let reference_users = survivors.to_vec();
    let action = classify_action(
        CanaryRemovalResourceOrigin::ForeignToThisRemoval,
        !reference_users.is_empty(),
        false,
    );
    let query = format!(
        "canary-removal/reconcile/canary-evidence-root:{}",
        install.transaction_id.as_str()
    );
    Ok(CanaryRemovalEffect {
        effect_id: handle_ref(&format!(
            "canary-removal/effect/canary-evidence-root:{}",
            install.transaction_id.as_str()
        ))?,
        category: CanaryRemovalResource::CanaryEvidenceRoot,
        origin: CanaryRemovalResourceOrigin::ForeignToThisRemoval,
        action,
        resource_identity: root.clone(),
        ownership_evidence: vec![root],
        reference_users,
        prerequisites: Vec::new(),
        expected_postcondition: CanaryRemovalPostcondition::Retained,
        reconciliation_query: PlatformHandle::new(query).map_err(|error| platform_error(&error))?,
        bound: CanaryRemovalEffectBound::new(),
        install_effect_index: None,
    })
}

fn store_objects_row(
    generation: &PlatformHandle,
) -> Result<CanaryRemovalEffect, InstallationError> {
    let evidence = PlatformHandle::new(format!("canary-removal/evidence/store-owner:{generation}"))
        .map_err(|error| platform_error(&error))?;
    let query = format!("canary-removal/reconcile/store-owner:{generation}");
    Ok(CanaryRemovalEffect {
        effect_id: handle_ref(&format!("canary-removal/effect/store-objects:{generation}"))?,
        category: CanaryRemovalResource::StoreObjects,
        origin: CanaryRemovalResourceOrigin::ForeignToThisRemoval,
        action: CanaryRemovalAction::Retain,
        resource_identity: generation.clone(),
        ownership_evidence: vec![evidence],
        reference_users: Vec::new(),
        prerequisites: Vec::new(),
        expected_postcondition: CanaryRemovalPostcondition::Retained,
        reconciliation_query: PlatformHandle::new(query).map_err(|error| platform_error(&error))?,
        bound: CanaryRemovalEffectBound::new(),
        install_effect_index: None,
    })
}

fn registry_record_row(
    generation: &PlatformHandle,
) -> Result<CanaryRemovalEffect, InstallationError> {
    let evidence = PlatformHandle::new(format!(
        "canary-removal/evidence/registry-record:{generation}"
    ))
    .map_err(|error| platform_error(&error))?;
    let query = format!("canary-removal/reconcile/registry-record:{generation}");
    Ok(CanaryRemovalEffect {
        effect_id: handle_ref(&format!(
            "canary-removal/effect/registry-record:{generation}"
        ))?,
        category: CanaryRemovalResource::GenerationRegistryRecord,
        origin: CanaryRemovalResourceOrigin::CreatedByInstallTransaction,
        action: CanaryRemovalAction::Remove,
        resource_identity: generation.clone(),
        ownership_evidence: vec![evidence],
        reference_users: Vec::new(),
        prerequisites: Vec::new(),
        expected_postcondition: CanaryRemovalPostcondition::Absent,
        reconciliation_query: PlatformHandle::new(query).map_err(|error| platform_error(&error))?,
        bound: CanaryRemovalEffectBound::new(),
        install_effect_index: None,
    })
}

/// Orders the frozen graph so every prerequisite row precedes its dependent
/// row and the terminal registry record stays last.
///
/// The terminal registry record is the hand-off of control to the surviving
/// installer/Host owner, so it cannot commit before every resource outcome is
/// observed. Keeping it last is also what leaves the running coordinator, its
/// journal and its recovery key available until the final readback finishes.
fn order_effect_graph(rows: &mut [CanaryRemovalEffect]) {
    let mut removals = rows
        .iter()
        .filter(|row| {
            row.action == CanaryRemovalAction::Remove
                && row.category != CanaryRemovalResource::GenerationRegistryRecord
        })
        .map(|row| row.effect_id.clone())
        .collect::<Vec<_>>();
    removals.sort();
    let mut order = removals;
    let registry_rows = rows
        .iter()
        .filter(|row| row.category == CanaryRemovalResource::GenerationRegistryRecord)
        .map(|row| row.effect_id.clone())
        .collect::<Vec<_>>();
    order.extend(registry_rows);
    for row in rows.iter_mut() {
        row.prerequisites = order
            .iter()
            .take_while(|id| *id != &row.effect_id)
            .cloned()
            .collect();
    }
    rows.sort_by_key(|row| {
        order
            .iter()
            .position(|id| id == &row.effect_id)
            .unwrap_or(usize::MAX)
    });
}

fn load_operation<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    removal_transaction_id: &PlatformHandle,
) -> Result<CanaryRemovalOperation, InstallationError>
where
    P: InstallationEffectPort,
{
    let operation = coordinator
        .store()
        .load_canary_removal_operation(removal_transaction_id)?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: removal_transaction_id.as_str().to_owned(),
        })?;
    operation.validate()?;
    Ok(operation)
}

fn admit_or_resume<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    plan: &CanaryRemovalPlan,
) -> Result<CanaryRemovalOperation, InstallationError>
where
    P: InstallationEffectPort,
{
    plan.validate()?;
    if let Some(existing) = coordinator
        .store()
        .load_canary_removal_operation(&plan.removal_transaction_id)?
    {
        existing.validate()?;
        if existing.plan.plan_digest != plan.plan_digest {
            return Err(InstallationError::IdentityConflict);
        }
        return Ok(existing);
    }
    let operation = CanaryRemovalOperation::admit(plan.clone())?;
    coordinator
        .store_mut()
        .create_canary_removal_operation(&operation)?;
    Ok(operation)
}

/// Revalidates the durable fence before any destructive action: the exact
/// installed transaction and its completed stage, the re-observed drain
/// evidence (applied effects, no pending external change, no held activation
/// intent), the current registry revision, the target's still-retired
/// position, any pending activation, and the required re-observed
/// activation-owner retirement handoff a dependent stop/delete has to follow.
#[allow(
    clippy::too_many_lines,
    reason = "the pre-destructive fence keeps every drift check in one auditable boundary"
)]
fn revalidate_fence<P>(
    coordinator: &InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    operation: &CanaryRemovalOperation,
) -> Result<InstallationTransaction, InstallationError>
where
    P: InstallationEffectPort,
{
    let plan = &operation.plan;
    if plan
        .effects
        .iter()
        .any(|row| row.action == CanaryRemovalAction::Unsupported)
    {
        return Err(InstallationError::IncompleteObservation(
            "the frozen plan names a required cleanup this owner cannot perform".to_owned(),
        ));
    }
    let install = coordinator
        .store()
        .load(&plan.install_transaction_id)?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: plan.install_transaction_id.as_str().to_owned(),
        })?;
    install.validate()?;
    if install.installer_plan_digest != plan.install_plan_digest
        || install.candidate_manifest.generation != plan.generation
        || candidate_manifest_digest(&install.candidate_manifest)? != plan.manifest_digest
    {
        return Err(InstallationError::IdentityConflict);
    }
    if install.stage() != InstallationStage::Completed {
        return Err(InstallationError::IdentityConflict);
    }
    // Quiesce is re-observed at fence time, not just at plan time: the drain
    // evidence (every installer effect authoritatively applied, no
    // unacknowledged external change, no activation intent still held by the
    // activation owner) must still hold immediately before a dependent
    // stop/delete, so a drift between planning and execution can never
    // green-light a destructive call. An incomplete drain stays a refusal and
    // preserves the durable incomplete recovery; it never forces a green
    // cleanup.
    //
    // `require_quiesced_owner_effects` is that whole observation in one place:
    // the exact jobs, the pending writes/ORS/outbox entries and the canary's own
    // lease/session/route authority, each compared against the transaction's own
    // durable record rather than against a list supplied with the request. The
    // plan's recorded quiesce counts are re-derived from the transaction's roster
    // inside it, so a plan can never be read as covering a narrower set of open
    // effects or pending writes/ORS/outbox rows than the transaction actually
    // owns.
    require_quiesced_owner_effects(&install, plan)?;
    // The frozen effect graph is checked against the install transaction's own
    // effect roster, which is the independent expected set: every installer
    // effect of the transaction must have exactly one plan row naming that
    // exact effect identity, and every plan row that claims an installer effect
    // must name one that exists. Comparing the graph against itself would
    // prove nothing and could not detect a dropped or substituted member.
    require_complete_effect_coverage(&install, plan)?;
    let projection = registry.load()?;
    projection.validate()?;
    // The target generation record is the one registry member a completed
    // removal may make absent, and only as its terminal step. Its absence is
    // therefore also the accepted evidence that the terminal registry
    // projection already committed before a crash lost this operation's final
    // save; every other drift stays a conflict.
    let already_retired = match resolve_approved_generation(&projection, &plan.generation) {
        Ok(target) => {
            if target.active
                || target.last_known_good
                || projection
                    .active_generation()
                    .is_some_and(|active| active == &plan.generation)
                || projection
                    .last_known_good_generation()
                    .is_some_and(|lkg| lkg == &plan.generation)
            {
                return Err(InstallationError::IncompleteObservation(
                    "the removal target serves production or is last-known-good again".to_owned(),
                ));
            }
            false
        }
        Err(InstallationError::IncompleteObservation(_)) => {
            if projection.revision() != plan.registry_revision.saturating_add(1) {
                return Err(InstallationError::IncompleteObservation(
                    "the removal target is absent from the registry without a committed terminal removal"
                        .to_owned(),
                ));
            }
            true
        }
        Err(error) => return Err(error),
    };
    // The admission fence is re-observed before the revision pin: a pending
    // activation staged for the dying generation after the plan was frozen is
    // a fence refusal naming the exact race, not a generic revision drift. All
    // other registry drift still conflicts below, so unrelated staging can
    // never green-light a destructive call either.
    if !already_retired {
        observe_admission_fence(&projection, plan)?;
    }
    if !already_retired && projection.revision() != plan.registry_revision {
        return Err(InstallationError::CompareAndSaveConflict {
            expected: plan.registry_revision,
            actual: projection.revision(),
        });
    }
    Ok(install)
}

/// Drives the dependency-ordered removal effects and the terminal readback.
fn advance<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    operation: &mut CanaryRemovalOperation,
    install: &InstallationTransaction,
) -> Result<(), InstallationError>
where
    P: InstallationEffectPort,
{
    let registry_row = operation
        .plan
        .effects
        .iter()
        .position(|row| row.category == CanaryRemovalResource::GenerationRegistryRecord)
        .ok_or(InstallationError::IncompleteObservation(
            "the frozen plan lost its terminal registry record".to_owned(),
        ))?;
    for _ in 0..operation.plan.effects.len() {
        let Some(position) = (0..registry_row).find(|position| {
            !matches!(
                operation.effect_progress[*position].state,
                CanaryRemovalEffectState::Resolved { .. }
            )
        }) else {
            break;
        };
        if matches!(
            operation.effect_progress[position].state,
            CanaryRemovalEffectState::Unknown { .. }
        ) {
            break;
        }
        advance_row(coordinator, registry, operation, install, position)?;
    }
    if operation
        .effect_progress
        .iter()
        .any(|progress| matches!(progress.state, CanaryRemovalEffectState::Unknown { .. }))
    {
        operation.blocking_effect_id = Some(
            operation
                .effect_progress
                .iter()
                .find(|progress| matches!(progress.state, CanaryRemovalEffectState::Unknown { .. }))
                .ok_or(InstallationError::IncompleteObservation(
                    "blocking effect is absent from durable progress".to_owned(),
                ))?
                .effect_id
                .clone(),
        );
        operation.validate()?;
        return Ok(());
    }
    if operation.effect_progress[..registry_row]
        .iter()
        .any(|progress| !matches!(progress.state, CanaryRemovalEffectState::Resolved { .. }))
    {
        operation.validate()?;
        return Ok(());
    }
    finish_with_readback(coordinator, registry, operation, install, registry_row)
}

/// Re-observes everything that could have changed since the entry-point fence,
/// immediately before one mutating call, and refuses that call if any of it did.
///
/// The entry fence observes these once per apply or recover call, so observing
/// them again here is what stops a change made *between two rows of one drive*
/// from being inherited from a now-stale observation:
///
/// * the operation's one recorded reconcile deadline, so a deadline expiring
///   between two rows refuses the next mutating call instead of letting the
///   drive run past its own bound to a terminal `Completed`;
/// * the admission fence, against a projection read now, so a canary admission
///   or a return to production or last-known-good staged between two rows
///   refuses this dependent stop/delete;
/// * the canary's own owner effects and the installer-effect coverage, against
///   a transaction re-loaded from the durable store rather than the one the
///   entry fence read, so a pending write, ORS operation, outbox row or possible
///   external effect, a lease/session/route authority rebound to a neighbour, or
///   a substituted owner-derived identity refuses this mutating call.
///
/// The re-loaded transaction is also compared back to the transaction the entry
/// fence admitted, so a substituted or replaced install transaction is refused
/// rather than quietly re-validated on its own terms.
///
/// Every check here fails closed and returns before any durable write, so a
/// refusal leaves the non-terminal stage, the blocking effect and every
/// unresolved row exactly as the previous rows left them.
fn reobserve_before_mutation(
    registry: &RedbInstallationRegistry,
    store: &RedbInstallationTransactionStore,
    operation: &CanaryRemovalOperation,
    install: &InstallationTransaction,
    row: &CanaryRemovalEffect,
) -> Result<(), InstallationError> {
    // The deadline is re-observed immediately before the mutating call, not
    // only at the entry-point fence. Expiry refuses the call and leaves the
    // durable projection exactly as the previous rows left it: the non-terminal
    // stage, the blocking effect and every unresolved `Unknown` row stay as
    // observed, so a deadline can never author a terminal `Completed` or a
    // clean cleanup.
    if reconcile_budget_exhausted(operation) {
        let unresolved = operation
            .effect_progress
            .iter()
            .filter(|progress| !matches!(progress.state, CanaryRemovalEffectState::Resolved { .. }))
            .count();
        return Err(InstallationError::IncompleteObservation(format!(
            "the bounded reconcile wait for removal {} expired with {} of {} removal effect(s) still unresolved; the exact blocking effect {} keeps this operation in incomplete recovery and no further mutating call is admitted under this operation identity",
            operation.removal_transaction_id.as_str(),
            unresolved,
            operation.plan.effects.len(),
            row.effect_id.as_str()
        )));
    }
    observe_admission_fence(&registry.load()?, &operation.plan)?;
    let observed_install = store.load(&operation.plan.install_transaction_id)?.ok_or(
        InstallationError::TransactionNotFound {
            transaction_id: operation.plan.install_transaction_id.as_str().to_owned(),
        },
    )?;
    observed_install.validate()?;
    if observed_install.transaction_id != install.transaction_id
        || observed_install.installer_plan_digest != operation.plan.install_plan_digest
        || observed_install.candidate_manifest.generation != operation.plan.generation
    {
        return Err(InstallationError::IdentityConflict);
    }
    require_quiesced_owner_effects(&observed_install, &operation.plan)?;
    require_complete_effect_coverage(&observed_install, &operation.plan)
}

/// Revalidates the retained resource identity, commits the exact intent before
/// the mutating call, and persists the observed result before advancing.
///
/// Immediately before the mutating call `reobserve_before_mutation` re-checks
/// the recorded reconcile deadline, the admission fence, the canary's own owner
/// effects and the installer-effect coverage, so none of them can be inherited
/// from the entry-point observation after changing mid-drive.
fn advance_row<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    operation: &mut CanaryRemovalOperation,
    install: &InstallationTransaction,
    position: usize,
) -> Result<(), InstallationError>
where
    P: InstallationEffectPort,
{
    let row = operation
        .plan
        .effects
        .get(position)
        .ok_or(InstallationError::IdentityConflict)?
        .clone();
    let index = row
        .install_effect_index
        .ok_or(InstallationError::IdentityConflict)?;
    let install_index = usize::try_from(index).map_err(|_| InstallationError::IdentityConflict)?;
    let resume = matches!(
        operation.effect_progress[position].state,
        CanaryRemovalEffectState::IntentCommitted { .. }
    );
    let attempt = row.bound;
    let request = effect_request(
        install,
        install_index,
        attempt.attempt,
        InstallationEffectAction::Rollback,
        Some(row.resource_identity.clone()),
    )?;
    let InstallationCoordinator { port, store } = coordinator;
    match port.reconcile(&request) {
        PortOutcome::Known(observed) => match classify_observation(&observed, &row) {
            RowClassification::Absent(evidence) => {
                if evidence.is_empty() {
                    return unknown_row(
                        store,
                        operation,
                        position,
                        readback_ref("unavailable", &row)?,
                    );
                }
                resolve_row(store, operation, position, evidence)?;
                return Ok(());
            }
            RowClassification::Matching => {}
            RowClassification::Conflict => return Err(InstallationError::IdentityConflict),
        },
        other => {
            unknown_row(store, operation, position, port_pending(other))?;
            return Ok(());
        }
    }
    // Everything that could have changed since the entry fence is re-observed
    // here, immediately before the mutating call, rather than inherited from
    // that one observation.
    reobserve_before_mutation(registry, store, operation, install, &row)?;
    let admitted_attempt = if resume {
        let Some(next) = attempt.next() else {
            return unknown_row(store, operation, position, exhausted_bound_ref(&row)?);
        };
        next
    } else {
        attempt
    };
    commit_intent(store, operation, position, admitted_attempt, &request)?;
    port.execute(&request);
    match port.reconcile(&request) {
        PortOutcome::Known(observed) => match classify_observation(&observed, &row) {
            RowClassification::Absent(evidence) => {
                if evidence.is_empty() {
                    unknown_row(
                        store,
                        operation,
                        position,
                        readback_ref("unavailable", &row)?,
                    )?;
                } else {
                    resolve_row(store, operation, position, evidence)?;
                }
            }
            RowClassification::Matching => {
                unknown_row(
                    store,
                    operation,
                    position,
                    unproven_postcondition_ref(&row)?,
                )?;
            }
            RowClassification::Conflict => return Err(InstallationError::IdentityConflict),
        },
        other => unknown_row(store, operation, position, port_pending(other))?,
    }
    Ok(())
}

enum RowClassification {
    Absent(Vec<PlatformHandle>),
    Matching,
    Conflict,
}

/// Authoritative readback classification for one removal row.
///
/// Absence is idempotent success only for the exact previously admitted object
/// with authoritative absence evidence. A readback that cannot classify the
/// object is an unknown outcome, and a readback proving a different object is
/// an identity conflict rather than an absent resource.
fn classify_observation(
    observed: &InstallationEffectObservation,
    row: &CanaryRemovalEffect,
) -> RowClassification {
    match observed {
        InstallationEffectObservation::Absent { evidence, .. } => {
            RowClassification::Absent(evidence.clone())
        }
        InstallationEffectObservation::Matching {
            disposition,
            external_identity,
            ..
        } => {
            if *disposition != super::InstallationEffectDisposition::CreatedByTransaction
                || external_identity != &row.resource_identity
            {
                RowClassification::Conflict
            } else {
                RowClassification::Matching
            }
        }
        InstallationEffectObservation::Mismatch { .. } => RowClassification::Conflict,
    }
}

fn exhausted_bound_ref(row: &CanaryRemovalEffect) -> Result<PlatformHandle, InstallationError> {
    handle_ref(&format!(
        "unknown:canary-removal-bound-exhausted:{}",
        row.effect_id.as_str()
    ))
}

fn unproven_postcondition_ref(
    row: &CanaryRemovalEffect,
) -> Result<PlatformHandle, InstallationError> {
    handle_ref(&format!(
        "unknown:canary-removal-unproven-postcondition:{}",
        row.effect_id.as_str()
    ))
}

fn readback_ref(
    kind: &str,
    row: &CanaryRemovalEffect,
) -> Result<PlatformHandle, InstallationError> {
    handle_ref(&format!(
        "unknown:canary-removal-readback-{kind}:{}",
        row.effect_id.as_str()
    ))
}

fn handle_ref(value: &str) -> Result<PlatformHandle, InstallationError> {
    PlatformHandle::new(value.to_owned()).map_err(|error| platform_error(&error))
}

/// Commits the exact removal intent before the mutating call.
fn commit_intent(
    store: &mut RedbInstallationTransactionStore,
    operation: &mut CanaryRemovalOperation,
    position: usize,
    attempt: CanaryRemovalEffectBound,
    request: &super::InstallationEffectRequest,
) -> Result<(), InstallationError> {
    let expected = CanaryRemovalOperationVersion::of(operation)?;
    let intent_digest = PlatformHandle::new(sha256_hex(&serde_json::to_vec(request).map_err(
        |error| InstallationError::InvalidField {
            field: "canary_removal.intent".to_owned(),
            reason: error.to_string(),
        },
    )?))
    .map_err(|error| platform_error(&error))?;
    operation.effect_progress[position].state = CanaryRemovalEffectState::IntentCommitted {
        attempt: attempt.attempt,
        intent_digest,
    };
    operation.plan.effects[position].bound = attempt;
    operation.stage = CanaryRemovalStage::Executing;
    operation.revision = next_revision(expected.revision)?;
    operation.validate()?;
    store.compare_and_save_canary_removal_operation(&expected, operation)
}

fn resolve_row(
    store: &mut RedbInstallationTransactionStore,
    operation: &mut CanaryRemovalOperation,
    position: usize,
    evidence: Vec<PlatformHandle>,
) -> Result<(), InstallationError> {
    let expected = CanaryRemovalOperationVersion::of(operation)?;
    let removed = matches!(
        operation.effect_progress[position].state,
        CanaryRemovalEffectState::IntentCommitted { .. }
    );
    operation.effect_progress[position].state = CanaryRemovalEffectState::Resolved {
        disposition: if removed {
            CanaryRemovalEffectDisposition::Removed
        } else {
            CanaryRemovalEffectDisposition::Absent
        },
        evidence,
    };
    operation.revision = next_revision(expected.revision)?;
    operation.validate()?;
    store.compare_and_save_canary_removal_operation(&expected, operation)
}

fn unknown_row(
    store: &mut RedbInstallationTransactionStore,
    operation: &mut CanaryRemovalOperation,
    position: usize,
    pending_ref: PlatformHandle,
) -> Result<(), InstallationError> {
    let expected = CanaryRemovalOperationVersion::of(operation)?;
    operation.effect_progress[position].state = CanaryRemovalEffectState::Unknown { pending_ref };
    operation.blocking_effect_id = Some(operation.effect_progress[position].effect_id.clone());
    operation.stage = CanaryRemovalStage::Reconciling;
    operation.revision = next_revision(expected.revision)?;
    operation.validate()?;
    store.compare_and_save_canary_removal_operation(&expected, operation)
}

fn next_revision(expected: u64) -> Result<u64, InstallationError> {
    expected
        .checked_add(1)
        .ok_or_else(|| InstallationError::InvalidField {
            field: "canary_removal.revision".to_owned(),
            reason: "revision overflow".to_owned(),
        })
}

/// Builds the readback request for one already-executed plan row, or `None`
/// when that row names no installation effect and therefore has nothing to read
/// back from its owner.
///
/// The row's own `install_effect_index` selects which exact effect of the
/// transaction is reconciled, and the row's own bound attempt and resource
/// identity supply the preconditions, so the readback is addressed to THIS row
/// rather than to a position in a list this loop happens to be walking.
fn readback_request(
    install: &InstallationTransaction,
    row: &CanaryRemovalEffect,
) -> Result<Option<InstallationEffectRequest>, InstallationError> {
    let Some(index) = row.install_effect_index else {
        return Ok(None);
    };
    let install_index = usize::try_from(index).map_err(|_| InstallationError::IdentityConflict)?;
    Ok(Some(effect_request(
        install,
        install_index,
        row.bound.attempt,
        InstallationEffectAction::Rollback,
        Some(row.resource_identity.clone()),
    )?))
}

/// Finishes by independent readback, then commits the terminal registry
/// projection under the expected registry revision.
///
/// The readback runs against the resource's own owner and is separate from the
/// mutating call, so a green stage can never come from a lost response. A
/// readback that cannot prove absence preserves the original identity and the
/// safe next action instead of reporting a clean removal.
fn finish_with_readback<P>(
    coordinator: &mut InstallationCoordinator<P, RedbInstallationTransactionStore>,
    registry: &RedbInstallationRegistry,
    operation: &mut CanaryRemovalOperation,
    install: &InstallationTransaction,
    registry_row: usize,
) -> Result<(), InstallationError>
where
    P: InstallationEffectPort,
{
    let mut readback_evidence = Vec::new();
    for position in 0..registry_row {
        let row = operation.plan.effects[position].clone();
        let Some(request) = readback_request(install, &row)? else {
            continue;
        };
        let InstallationCoordinator { port, store } = coordinator;
        match port.reconcile(&request) {
            PortOutcome::Known(InstallationEffectObservation::Absent {
                evidence,
                observed_precondition,
                ..
            }) => {
                if evidence.is_empty() {
                    return unknown_row(
                        store,
                        operation,
                        position,
                        readback_ref("unavailable", &row)?,
                    );
                }
                readback_evidence.push(observed_precondition.digest);
                readback_evidence.extend(evidence);
            }
            PortOutcome::Known(_) => {
                return unknown_row(
                    store,
                    operation,
                    position,
                    readback_ref("still-present", &row)?,
                );
            }
            other => {
                return unknown_row(store, operation, position, port_pending(other));
            }
        }
    }
    // The terminal projection is the last durable step and is idempotent: a
    // retry after a crash between the registry commit and this operation's
    // final save observes the record already absent and only re-commits the
    // terminal evidence.
    let current = registry.load()?;
    if resolve_approved_generation(&current, &operation.plan.generation).is_ok() {
        // The terminal registry retirement is the one mutating call left in
        // this operation, and it is issued after the per-row readback loop, not
        // at the entry fence. Both the bounded reconcile deadline and the
        // admission fence are therefore re-observed here against a projection
        // read after that loop: a deadline that expires mid-readback, or a
        // canary admission or a return to production/last-known-good staged
        // after the last row, refuses this call instead of being inherited
        // from a stale entry-point observation. Neither refusal writes
        // anything, so the durable incomplete recovery survives unchanged.
        if reconcile_budget_exhausted(operation) {
            return Err(InstallationError::IncompleteObservation(format!(
                "the bounded reconcile wait for removal {} expired before the terminal registry retirement of generation {}; the exact blocking effect {} keeps this operation in incomplete recovery and no terminal commit is admitted under this operation identity",
                operation.removal_transaction_id.as_str(),
                operation.plan.generation.as_str(),
                operation.plan.effects[registry_row].effect_id.as_str()
            )));
        }
        observe_admission_fence(&current, &operation.plan)?;
        // The owner effects are re-observed here as well, against a transaction
        // re-loaded from the durable store, so a pending write, ORS operation,
        // outbox row or possible external effect, or a rebound lease/session/route
        // authority, staged during the per-row readback refuses the terminal
        // commit rather than being inherited from the entry observation. Like the
        // two refusals above, this one writes nothing.
        let observed_install = coordinator
            .store()
            .load(&operation.plan.install_transaction_id)?
            .ok_or(InstallationError::TransactionNotFound {
                transaction_id: operation.plan.install_transaction_id.as_str().to_owned(),
            })?;
        observed_install.validate()?;
        require_quiesced_owner_effects(&observed_install, &operation.plan)?;
        require_complete_effect_coverage(&observed_install, &operation.plan)?;
        let terminal = registry.mutate_atomic(operation.plan.registry_revision, |projection| {
            projection.retire_retired_generation(&operation.plan.generation)
        });
        match terminal {
            Ok(()) => {}
            // A registry that still projects this generation is a retained
            // cleanup uncertainty owned by the activation/registry owner, not a
            // crash: the blocking row stays durable so the next permitted
            // action is bounded manual recovery instead of a fresh destructive
            // attempt.
            Err(
                InstallationError::IncompleteObservation(_)
                | InstallationError::MigrationRequired { .. },
            ) => {
                return unknown_row(
                    coordinator.store_mut(),
                    operation,
                    registry_row,
                    readback_ref(
                        "registry-terminal-held",
                        &operation.plan.effects[registry_row],
                    )?,
                );
            }
            Err(error) => return Err(error),
        }
    }
    let expected = CanaryRemovalOperationVersion::of(operation)?;
    readback_evidence.push(handle_ref(&format!(
        "canary-removal/readback/registry-terminal:{}",
        operation.plan.generation.as_str()
    ))?);
    operation.effect_progress[registry_row].state = CanaryRemovalEffectState::Resolved {
        disposition: CanaryRemovalEffectDisposition::Removed,
        evidence: readback_evidence,
    };
    operation.blocking_effect_id = None;
    operation.stage = CanaryRemovalStage::Completed;
    operation.revision = next_revision(expected.revision)?;
    operation.validate()?;
    coordinator
        .store_mut()
        .compare_and_save_canary_removal_operation(&expected, operation)
}
