//! Durable installation transaction aggregate, lifecycle and wire validation.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    ActivationCommitReceipt, ActiveVerifiedReceiptBinding, CandidateManifest, ContractVersion,
    HostPhaseBMaterializationReceipt, INSTALLATION_SECRET_CREATION_PROOF_VERSION,
    INSTALLATION_TRANSACTION_WIRE_VERSION, InstallationActivationApproval,
    InstallationActivationProjectionIntent, InstallationEffectPrecondition, InstallationEpoch,
    InstallationError, InstallationProfile, InstallationServiceBootstrap,
    InstallationServiceStartProof, InstallationStepOutcome, InstallerEffectPlan,
    InstallerServiceControlGrantReceipt, InstallerServiceRegistrationApproval,
    InstallerServiceRole, ManagedEnvironmentChangeRequest, PlannedChange, PlatformHandle,
    RuntimeStateRoots, StagingReceipt, StoreCredentialLifecycle, StoreCredentialProgress,
    candidate_manifest_digest, handle, handles, ownership_secret_absence_evidence,
    phase_b_scm_digest, sha256_handle, sha256_hex, validate_installer_effects,
    validate_package_binding, validate_phase_b_effect_bindings,
    validate_staging_receipt_for_observation, validate_staging_receipt_for_plan,
};
/// Store-volume observation used to evaluate the immutable free-space policy.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreFreeSpaceObservation {
    /// Windows observed caller-available bytes.
    Known {
        /// Caller-available bytes on the Store data volume.
        available_bytes: u64,
        /// Evidence binding the observation to the volume and instant.
        evidence_refs: Vec<PlatformHandle>,
    },
    /// Windows could not classify the current available space.
    Unknown {
        /// Evidence or failure capsule references for recovery.
        evidence_refs: Vec<PlatformHandle>,
    },
}

/// Durable installer stage. A partial external effect cannot skip recovery.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationStage {
    /// Immutable plan exists but no external effect has started.
    Planned,
    /// Candidate bytes are being copied into an isolated staging root.
    Staging,
    /// Hashes/signatures/dependency closure have been observed.
    StaticVerified,
    /// Candidate registrations are being prepared without authority.
    Registering,
    /// The activation pointer or service configuration is being switched.
    Activating,
    /// Runtime health and conformance have been observed.
    ActiveVerified,
    /// Superseded staging and registrations are being removed.
    Cleaning,
    /// Transaction has completed with an observed disposition.
    Completed,
    /// External outcome is unknown and requires reconciliation or rollback.
    RollbackRequired,
    /// Candidate was rolled back with an observed disposition.
    RolledBack,
    /// Recovery could not safely determine a disposition.
    Quarantined,
}

impl InstallationStage {
    fn can_advance(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Planned, Self::Staging | Self::RollbackRequired)
                | (Self::Staging, Self::StaticVerified | Self::RollbackRequired)
                | (
                    Self::StaticVerified,
                    Self::Registering | Self::RollbackRequired
                )
                | (Self::Registering, Self::Activating | Self::RollbackRequired)
                | (
                    Self::Activating,
                    Self::ActiveVerified | Self::RollbackRequired
                )
                | (Self::ActiveVerified, Self::Cleaning | Self::Completed)
                | (Self::Cleaning, Self::Completed | Self::RollbackRequired)
                | (Self::RollbackRequired, Self::RolledBack | Self::Quarantined)
        )
    }
}

/// Proven ownership of an observed installer effect.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationEffectDisposition {
    /// The exact external object was created by this transaction intent.
    CreatedByTransaction,
    /// The exact requested postcondition already existed before execution.
    PreexistingMatching,
}

/// Exact OS identity and security state observed through one retained handle.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationOsObjectSnapshot {
    /// Digest of the canonical UTF-16 path returned by Windows for the handle.
    pub canonical_path_digest: PlatformHandle,
    /// NTFS volume serial number.
    pub volume_serial_number: u32,
    /// Stable file index on that volume.
    pub file_index: u64,
    /// Digest of owner, DACL and descriptor control read from the handle.
    pub security_descriptor_digest: PlatformHandle,
}

impl InstallationOsObjectSnapshot {
    fn validate(&self, field: &str) -> Result<(), InstallationError> {
        sha256_handle(
            &self.canonical_path_digest,
            &format!("{field}.canonical_path_digest"),
        )?;
        if self.file_index == 0 {
            return Err(InstallationError::InvalidField {
                field: format!("{field}.file_index"),
                reason: "must be non-zero".to_owned(),
            });
        }
        sha256_handle(
            &self.security_descriptor_digest,
            &format!("{field}.security_descriptor_digest"),
        )
    }
}

/// Typed Windows proof that an exact target was absent below pinned parents.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRootAbsentSnapshot {
    /// Digest of the exact requested target path in canonical UTF-16 form.
    pub target_path_digest: PlatformHandle,
    /// OS-known-folder/profile anchor retained during observation.
    pub profile_anchor: InstallationOsObjectSnapshot,
    /// Ordered existing objects from the profile anchor through the parent.
    pub ancestors: Vec<InstallationOsObjectSnapshot>,
    /// Exact retained parent handle used for the absence observation.
    pub parent: InstallationOsObjectSnapshot,
    /// Explicit negative observation; never inferred from an empty identity.
    pub root_absent: bool,
}

impl InstallationRootAbsentSnapshot {
    pub(super) fn validate(&self) -> Result<(), InstallationError> {
        sha256_handle(
            &self.target_path_digest,
            "effect.precondition.os_snapshot.target_path_digest",
        )?;
        self.profile_anchor
            .validate("effect.precondition.os_snapshot.profile_anchor")?;
        if self.ancestors.is_empty() {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.os_snapshot.ancestors".to_owned(),
                reason: "must include the retained parent contour".to_owned(),
            });
        }
        for (index, ancestor) in self.ancestors.iter().enumerate() {
            ancestor.validate(&format!(
                "effect.precondition.os_snapshot.ancestors[{index}]"
            ))?;
        }
        self.parent
            .validate("effect.precondition.os_snapshot.parent")?;
        if self.ancestors.last() != Some(&self.parent) || !self.root_absent {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.os_snapshot".to_owned(),
                reason: "must end at the retained parent and prove exact absence".to_owned(),
            });
        }
        Ok(())
    }
}

/// Durable lifecycle of one Credential Manager ownership-key reference.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationSecretLifecycle {
    /// The committed reference remains required for execute/reconcile/rollback.
    Active,
    /// Deletion intent was committed before the Credential Manager delete.
    DeleteIntentCommitted,
    /// Authoritative readback proved the Credential Manager target absent.
    Deleted,
}

/// Durable filesystem create classification. Only `Created` can authorize a
/// transaction-created root.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationCreateDisposition {
    /// No root create result has been durably recorded.
    NotAttempted,
    /// The exact OS create call reported a newly-created directory.
    Created,
    /// The exact OS create call reported an existing path.
    AlreadyExists,
}

/// Durable Credential Manager provisioning classification. This is deliberately
/// separate from the filesystem create result: the credential must be durably
/// proven before any filesystem mutation is admitted.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationSecretProvisionDisposition {
    /// No provider mutation has been durably classified.
    NotAttempted,
    /// The exact credential was read back and matched its durable proof.
    Created,
}

/// Non-secret proof that one provider-created ownership credential belongs to
/// the exact transaction/effect attempt. The authenticator is keyed by the
/// credential bytes and therefore cannot be forged or substituted by durable
/// JSON alone.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSecretCreationProof {
    /// Version of the canonical proof payload.
    pub version: u32,
    /// Lowercase hexadecimal HMAC-SHA256 authenticator.
    pub authenticator: PlatformHandle,
}

impl InstallationSecretCreationProof {
    pub(super) fn validate(&self) -> Result<(), InstallationError> {
        if self.version != INSTALLATION_SECRET_CREATION_PROOF_VERSION {
            return Err(InstallationError::InvalidField {
                field: "effect_progress.ownership_secret.creation_proof.version".to_owned(),
                reason: format!(
                    "must equal current proof version {INSTALLATION_SECRET_CREATION_PROOF_VERSION}"
                ),
            });
        }
        sha256_handle(
            &self.authenticator,
            "effect_progress.ownership_secret.creation_proof.authenticator",
        )
    }
}

/// Provider scope for one durable installer ownership-key reference.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallationSecretScope {
    /// Windows Credential Manager under one exact current-user SID.
    WindowsCredentialManagerCurrentUser,
}

/// Non-secret durable reference issued before Credential Manager mutation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSecretReference {
    /// Unpredictable provider target.
    pub target: PlatformHandle,
    /// Exact process-token SID that owns the provider scope.
    pub expected_principal_sid: PlatformHandle,
    /// Provider scope; ciphertext alone is never authorization.
    pub scope: InstallationSecretScope,
}

impl InstallationSecretReference {
    fn validate(&self) -> Result<(), InstallationError> {
        handle(
            &self.target,
            "effect_progress.ownership_secret.reference.target",
        )?;
        handle(
            &self.expected_principal_sid,
            "effect_progress.ownership_secret.reference.expected_principal_sid",
        )?;
        let target_token = self
            .target
            .as_str()
            .strip_prefix("eliot/installer-root/v1/");
        if target_token.is_none_or(|token| {
            token.len() != 32
                || !token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) || !self.expected_principal_sid.as_str().starts_with("S-")
        {
            return Err(InstallationError::InvalidField {
                field: "effect_progress.ownership_secret.reference".to_owned(),
                reason: "invalid Credential Manager target or principal SID".to_owned(),
            });
        }
        Ok(())
    }
}

/// Durable reference to an ownership key held only by Credential Manager.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationOwnershipSecret {
    /// Current-user Credential Manager target and exact expected owner SID.
    pub reference: InstallationSecretReference,
    /// Root create disposition durably captured after the OS call.
    pub create_disposition: InstallationCreateDisposition,
    /// Credential Manager create result, independent from filesystem state.
    pub secret_provision_disposition: InstallationSecretProvisionDisposition,
    /// Non-secret proof bound to the exact provider mutation.
    pub creation_proof: InstallationSecretCreationProof,
    /// Intent-before-delete lifecycle.
    pub lifecycle: InstallationSecretLifecycle,
}

impl InstallationOwnershipSecret {
    pub(super) fn validate(&self) -> Result<(), InstallationError> {
        self.reference.validate()?;
        self.creation_proof.validate()
    }
}

/// Durable progress for exactly one immutable installer effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum InstallationEffectProgressState {
    /// No effect intent has been committed.
    Pending,
    /// The exact intent was durably committed before the platform call.
    IntentCommitted {
        /// Non-zero execution attempt.
        attempt: u32,
        /// Digest of the exact request authorized for this attempt.
        intent_digest: PlatformHandle,
    },
    /// Authoritative readback proved the exact postcondition.
    Applied {
        /// Whether this transaction created or merely adopted the object.
        disposition: InstallationEffectDisposition,
        /// Exact provider object identity observed after the effect.
        external_identity: PlatformHandle,
        /// Evidence proving the authoritative postcondition.
        evidence: Vec<PlatformHandle>,
        /// Digest of the authoritative postcondition.
        postcondition_digest: PlatformHandle,
    },
    /// Authoritative classification was impossible or mismatched.
    Unknown {
        /// Stable evidence/reference requiring recovery.
        pending_ref: PlatformHandle,
    },
}

/// One-to-one durable progress entry bound to an installer effect identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEffectProgress {
    /// Immutable effect identity from the installer plan.
    pub effect_id: PlatformHandle,
    /// Typed OS precondition admitted by the coordinator before intent commit.
    pub admitted_precondition: Option<InstallationEffectPrecondition>,
    /// Credential Manager reference retained across restart and recovery.
    pub ownership_secret: Option<InstallationOwnershipSecret>,
    /// Unpredictable public nonce retained for one SCM registration effect.
    pub registration_nonce: Option<PlatformHandle>,
    /// Typed authoritative SCM DACL receipt for the Watchdog registration.
    /// This member is mandatory on the current wire and is `None` for every
    /// non-Watchdog-registration effect.
    pub service_control_grant: Option<InstallerServiceControlGrantReceipt>,
    /// Absolute injected-clock deadline for one bounded SCM start
    /// convergence window.  The deadline is created before the start intent
    /// is persisted and retained across restart; it never authorizes a second
    /// `StartServiceW` call.
    pub service_start_deadline_ms: Option<u64>,
    /// Exact proof that the provider issued this transaction's `StartServiceW`
    /// call.  It is paired with the `IntentCommitted.intent_digest`; a
    /// readback without this proof can never become transaction ownership.
    #[serde(default)]
    pub service_start_proof: Option<InstallationServiceStartProof>,
    /// `LocalService` Store credential lifecycle, present only for its effect.
    pub store_credential: Option<StoreCredentialProgress>,
    /// Complete immutable package receipt, present only for `StagePackage`.
    pub staging_receipt: Option<StagingReceipt>,
    /// Complete typed Host Phase-B receipt, present only for
    /// `MaterializePhaseB`.
    pub phase_b_receipt: Option<HostPhaseBMaterializationReceipt>,
    /// Current durable effect state.
    pub state: InstallationEffectProgressState,
}

/// Durable installation/update transaction and its recovery projection.
///
/// Mutable durability state is intentionally read-only outside this crate:
///
/// ```compile_fail
/// use eliot_installation::{InstallationStage, InstallationTransaction};
///
/// fn forge_stage(transaction: &mut InstallationTransaction) {
///     transaction.stage = InstallationStage::Completed;
/// }
/// ```
///
/// The raw stage transition is crate-private. In particular, callers cannot
/// compile an arbitrary `ActiveVerified` advance; the public replacement
/// requires an opaque [`ActivationCommitReceipt`].
///
/// ```compile_fail
/// use eliot_installation::{InstallationStage, InstallationTransaction};
///
/// fn forge_active(transaction: &mut InstallationTransaction) {
///     transaction.advance(InstallationStage::ActiveVerified, Vec::new());
/// }
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationTransaction {
    /// Required breaking discriminator for this transaction projection only.
    pub transaction_wire_version: ContractVersion,
    /// Stable transaction identity.
    pub transaction_id: PlatformHandle,
    /// Installation lineage at transaction creation.
    pub installation_epoch: InstallationEpoch,
    /// Selected path/supervision profile.
    pub profile: InstallationProfile,
    /// Governing request identity.
    pub request: ManagedEnvironmentChangeRequest,
    /// Previously active generation, if one exists.
    pub current_active_manifest: Option<CandidateManifest>,
    /// Immutable candidate generation.
    pub candidate_manifest: CandidateManifest,
    /// Isolated staging root.
    pub staging_root: PlatformHandle,
    /// Planned OS/file/plugin/service changes.
    pub planned_changes: Vec<PlannedChange>,
    /// Typed root/ACL/SCM effects bound one-to-one to `planned_changes`.
    pub installer_effects: Vec<InstallerEffectPlan>,
    /// Minimum caller-available bytes required on the Store data volume.
    pub minimum_store_available_bytes: u64,
    /// Digest binding the sole transaction identity to its immutable installer plan.
    pub installer_plan_digest: PlatformHandle,
    /// One-to-one ordered durable progress for `installer_effects`.
    pub(super) effect_progress: Vec<InstallationEffectProgress>,
    /// Precondition observations captured before staging.
    pub precondition_evidence: Vec<PlatformHandle>,
    /// Current durable stage.
    pub(super) stage: InstallationStage,
    /// Evidence references for completed stages.
    pub completed_stage_refs: Vec<PlatformHandle>,
    /// External objects changed but not yet acknowledged.
    pub pending_external_changes: Vec<PlatformHandle>,
    /// Rollback or forward-repair plan.
    pub rollback_plan: PlatformHandle,
    /// Last-known-good manifest/generation reference.
    pub last_known_good: Option<PlatformHandle>,
    /// No-return boundary evidence, when activation crossed it.
    pub no_return_boundary: Option<PlatformHandle>,
    /// Observed postconditions.
    pub observed_postconditions: Vec<PlatformHandle>,
    /// Exact registry terminal that authorized `ActiveVerified`, retained as
    /// a private v9 binding for crash/retry reconciliation.
    pub(super) active_verified_receipt: Option<ActiveVerifiedReceiptBinding>,
    /// Exact signed activation projection intent persisted with the
    /// `Registering -> Activating` transaction CAS.
    pub(super) activation_projection_intent: Option<InstallationActivationProjectionIntent>,
    /// Operator recovery command/reference.
    pub recovery_command: PlatformHandle,
    /// Monotonic state revision.
    pub(super) revision: u64,
    /// In-memory proof that this value came from the planner constructor.
    ///
    /// This is deliberately skipped from the wire representation. A value
    /// decoded from diagnostic JSON or the durable store can be inspected and
    /// reconciled, but cannot be used to create a new production store.
    #[serde(skip)]
    planner_construction_proof: PlannerConstructionProof,
}

#[derive(Clone, Copy, Debug)]
enum PlannerConstructionProof {
    Bound,
    Unbound,
}

// The binding is an in-memory capability and is intentionally excluded from
// transaction value equality, which compares the durable wire projection.
impl PartialEq for PlannerConstructionProof {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for PlannerConstructionProof {}

impl InstallationTransaction {
    /// Creates a validated immutable plan at `PLANNED`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        transaction_id: PlatformHandle,
        installation_epoch: InstallationEpoch,
        profile: InstallationProfile,
        request: ManagedEnvironmentChangeRequest,
        current_active_manifest: Option<CandidateManifest>,
        candidate_manifest: CandidateManifest,
        staging_root: PlatformHandle,
        planned_changes: Vec<PlannedChange>,
        installer_effects: Vec<InstallerEffectPlan>,
        minimum_store_available_bytes: u64,
        precondition_evidence: Vec<PlatformHandle>,
        recovery_command: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        Self::new_with_construction_proof(
            transaction_id,
            installation_epoch,
            profile,
            request,
            current_active_manifest,
            candidate_manifest,
            staging_root,
            planned_changes,
            installer_effects,
            minimum_store_available_bytes,
            precondition_evidence,
            recovery_command,
            PlannerConstructionProof::Bound,
        )
    }

    /// Creates a validated, unbound transaction projection for read-only
    /// fixture and diagnostic consumers.
    ///
    /// The returned value is intentionally not accepted by
    /// [`RedbInstallationTransactionStore::create_planned_at_exact_path`].
    /// Production plans must come from the in-crate generation planner, which
    /// retains the sealed construction proof.
    #[doc(hidden)]
    #[allow(
        dead_code,
        reason = "diagnostic fixture seam; store admission remains bound"
    )]
    #[allow(clippy::too_many_arguments)]
    pub fn new_unbound_for_fixture(
        transaction_id: PlatformHandle,
        installation_epoch: InstallationEpoch,
        profile: InstallationProfile,
        request: ManagedEnvironmentChangeRequest,
        current_active_manifest: Option<CandidateManifest>,
        candidate_manifest: CandidateManifest,
        staging_root: PlatformHandle,
        planned_changes: Vec<PlannedChange>,
        installer_effects: Vec<InstallerEffectPlan>,
        minimum_store_available_bytes: u64,
        precondition_evidence: Vec<PlatformHandle>,
        recovery_command: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        Self::new_with_construction_proof(
            transaction_id,
            installation_epoch,
            profile,
            request,
            current_active_manifest,
            candidate_manifest,
            staging_root,
            planned_changes,
            installer_effects,
            minimum_store_available_bytes,
            precondition_evidence,
            recovery_command,
            PlannerConstructionProof::Unbound,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "constructor validates the complete immutable installation transaction boundary"
    )]
    fn new_with_construction_proof(
        transaction_id: PlatformHandle,
        installation_epoch: InstallationEpoch,
        profile: InstallationProfile,
        request: ManagedEnvironmentChangeRequest,
        current_active_manifest: Option<CandidateManifest>,
        candidate_manifest: CandidateManifest,
        staging_root: PlatformHandle,
        planned_changes: Vec<PlannedChange>,
        installer_effects: Vec<InstallerEffectPlan>,
        minimum_store_available_bytes: u64,
        precondition_evidence: Vec<PlatformHandle>,
        recovery_command: PlatformHandle,
        planner_construction_proof: PlannerConstructionProof,
    ) -> Result<Self, InstallationError> {
        handle(&transaction_id, "transaction_id")?;
        installation_epoch.validate()?;
        request.validate()?;
        candidate_manifest.validate()?;
        if candidate_manifest.runtime_launch.profile != profile {
            return Err(InstallationError::ProfileViolation(
                "transaction profile must equal the candidate runtime launch profile".to_owned(),
            ));
        }
        if candidate_manifest.runtime_launch.installation_epoch != installation_epoch {
            return Err(InstallationError::InvalidField {
                field: "candidate_manifest.runtime_launch.installation_epoch".to_owned(),
                reason: "must exactly equal the transaction installation epoch".to_owned(),
            });
        }
        if let Some(manifest) = &current_active_manifest {
            manifest.validate()?;
        }
        handle(&staging_root, "staging_root")?;
        handle(&recovery_command, "recovery_command")?;
        handles(&precondition_evidence, "precondition_evidence", true)?;
        let mut change_ids = BTreeSet::new();
        for change in &planned_changes {
            change.validate()?;
            if !change_ids.insert(change.change_id.as_str()) {
                return Err(InstallationError::Duplicate {
                    kind: "planned change".to_owned(),
                    identity: change.change_id.as_str().to_owned(),
                });
            }
        }
        if planned_changes.is_empty() {
            return Err(InstallationError::InvalidField {
                field: "planned_changes".to_owned(),
                reason: "must contain an explicit effect plan".to_owned(),
            });
        }
        if minimum_store_available_bytes == 0 {
            return Err(InstallationError::InvalidField {
                field: "minimum_store_available_bytes".to_owned(),
                reason: "must be a non-zero explicit policy value".to_owned(),
            });
        }
        validate_installer_effects(
            profile,
            &candidate_manifest.runtime_launch.runtime_state_roots,
            &candidate_manifest.store_credential_target,
            &planned_changes,
            &installer_effects,
        )?;
        if profile.is_disposable() && staging_root.as_str().contains("..") {
            return Err(InstallationError::ProfileViolation(
                "portable staging root must remain repository-local".to_owned(),
            ));
        }
        validate_package_binding(&candidate_manifest, &staging_root, &installer_effects)?;
        let rollback_plan = request.rollback_plan.clone();
        let installer_plan_digest =
            PlatformHandle::new(sha256_hex(&Self::installer_plan_unsigned_bytes(
                &transaction_id,
                &candidate_manifest,
                &staging_root,
                &candidate_manifest.runtime_launch.runtime_state_roots,
                minimum_store_available_bytes,
                &planned_changes,
                &installer_effects,
            )?))
            .map_err(|error| InstallationError::InvalidField {
                field: "installer_plan_digest".to_owned(),
                reason: error.to_string(),
            })?;
        let effect_progress = installer_effects
            .iter()
            .map(|effect| InstallationEffectProgress {
                effect_id: effect.effect_id().clone(),
                admitted_precondition: None,
                ownership_secret: None,
                registration_nonce: None,
                service_control_grant: None,
                service_start_deadline_ms: None,
                service_start_proof: None,
                store_credential: None,
                staging_receipt: None,
                phase_b_receipt: None,
                state: InstallationEffectProgressState::Pending,
            })
            .collect();
        Ok(Self {
            transaction_wire_version: INSTALLATION_TRANSACTION_WIRE_VERSION,
            transaction_id,
            installation_epoch,
            profile,
            request,
            current_active_manifest,
            candidate_manifest,
            staging_root,
            planned_changes,
            installer_effects,
            minimum_store_available_bytes,
            installer_plan_digest,
            effect_progress,
            precondition_evidence,
            stage: InstallationStage::Planned,
            completed_stage_refs: Vec::new(),
            pending_external_changes: Vec::new(),
            rollback_plan,
            last_known_good: None,
            no_return_boundary: None,
            observed_postconditions: Vec::new(),
            active_verified_receipt: None,
            activation_projection_intent: None,
            recovery_command,
            revision: 1,
            planner_construction_proof,
        })
    }

    /// Returns the current durable stage without exposing a mutation seam.
    #[must_use]
    pub const fn stage(&self) -> InstallationStage {
        self.stage
    }

    /// Returns the ordered effect progress as a read-only projection.
    #[must_use]
    pub fn effect_progress(&self) -> &[InstallationEffectProgress] {
        &self.effect_progress
    }

    /// Returns the durable signed activation projection binding, when this
    /// transaction has crossed the signed activation boundary.
    #[must_use]
    pub(crate) fn activation_projection_intent(
        &self,
    ) -> Option<&InstallationActivationProjectionIntent> {
        self.activation_projection_intent.as_ref()
    }

    /// Reports whether the signed activation projection boundary is durably
    /// present without exposing its authority-bearing payload.
    #[must_use]
    pub fn has_activation_projection_intent(&self) -> bool {
        self.activation_projection_intent.is_some()
    }

    /// Requires authoritative readback for every immutable installer effect.
    ///
    /// This is the core admission gate for any registry or approval
    /// projection.  A transaction with a pending intent, unknown outcome, or
    /// merely planned effect must not become an approved generation.
    pub fn require_all_effects_applied(&self) -> Result<(), InstallationError> {
        self.validate()?;
        if self.effect_progress.iter().any(|progress| {
            !matches!(
                progress.state,
                InstallationEffectProgressState::Applied { .. }
            )
        }) {
            return Err(InstallationError::IncompleteObservation(
                "all installer effects require authoritative applied readback before registry staging or approval projection"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Requires the signed pending-activation boundary to be durable.
    ///
    /// Every effect before activation must already have authoritative
    /// `Applied` progress.  The exact ordered `Watchdog` then `Host`
    /// `StartService` effects must remain `Pending`; the coordinator is the
    /// sole owner of executing those effects after the signed stage commits.
    pub fn require_pre_activation_effects_applied(&self) -> Result<(), InstallationError> {
        self.require_pre_activation_effects_at(InstallationStage::Activating)
    }

    /// Validates the same exact pre-activation contour before the signed
    /// authority transition commits `Registering -> Activating`.
    pub(crate) fn require_pre_activation_effects_ready(&self) -> Result<(), InstallationError> {
        self.require_pre_activation_effects_at(InstallationStage::Registering)
    }

    /// Requires the signed pending-activation contour at either side of the
    /// sealed `Registering -> Activating` CAS.  The exact ordered service
    /// starts remain pending in both states; all preceding effects are already
    /// durably `Applied`.
    pub(crate) fn require_signed_pending_activation_effects(
        &self,
    ) -> Result<(), InstallationError> {
        match self.stage {
            InstallationStage::Registering | InstallationStage::Activating => {
                self.require_pre_activation_effects_at(self.stage)
            }
            stage => Err(InstallationError::IncompleteObservation(format!(
                "signed pending activation requires the Registering or Activating boundary, observed {stage:?}"
            ))),
        }
    }

    /// Requires the first-install bootstrap prefix to be durable.
    ///
    /// Both Watchdog and Host `StartService` effects remain `Pending` through
    /// the signed activation projection.  Every earlier root, package, and
    /// service-registration effect must have authoritative readback, and the
    /// transaction-owned credential remains after the ordered `Watchdog` then
    /// `Host` starts so the Host can authenticate its epoch/process challenge
    /// before `LocalService` secrets are generated.
    pub(crate) fn require_bootstrap_effects_ready(&self) -> Result<(), InstallationError> {
        self.require_pre_activation_effects_ready()
    }

    fn require_pre_activation_effects_at(
        &self,
        expected_stage: InstallationStage,
    ) -> Result<(), InstallationError> {
        self.validate()?;
        if self.stage != expected_stage {
            return Err(InstallationError::IncompleteObservation(format!(
                "signed pending activation requires the {expected_stage:?} transaction boundary"
            )));
        }

        let first_start = self
            .installer_effects
            .iter()
            .position(|effect| matches!(effect, InstallerEffectPlan::StartService { .. }))
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "signed pending activation requires Watchdog then Host service starts"
                        .to_owned(),
                )
            })?;
        for idx in 0..first_start {
            if !matches!(
                self.effect_progress[idx].state,
                InstallationEffectProgressState::Applied { .. }
            ) {
                return Err(InstallationError::IncompleteObservation(
                    "all effects before Host bootstrap must be applied".to_owned(),
                ));
            }
        }
        let mut start_roles = Vec::new();
        let mut cursor = first_start;
        while cursor < self.installer_effects.len() {
            match &self.installer_effects[cursor] {
                InstallerEffectPlan::StartService { role, .. } => {
                    if !matches!(
                        self.effect_progress[cursor].state,
                        InstallationEffectProgressState::Pending
                    ) {
                        return Err(InstallationError::IncompleteObservation(
                            "signed pending activation requires ordered service starts to remain pending"
                                .to_owned(),
                        ));
                    }
                    if self.effect_progress[cursor].service_start_proof.is_some()
                        || self.effect_progress[cursor]
                            .service_start_deadline_ms
                            .is_some()
                    {
                        return Err(InstallationError::IncompleteObservation(
                            "pending service start must not carry synthetic proof".to_owned(),
                        ));
                    }
                    start_roles.push(*role);
                    cursor += 1;
                }
                _ => break,
            }
        }
        if start_roles != [InstallerServiceRole::Watchdog, InstallerServiceRole::Host] {
            return Err(InstallationError::IncompleteObservation(
                "signed pending activation requires Watchdog then Host service starts".to_owned(),
            ));
        }
        let suffix = &self.installer_effects[cursor..];
        if suffix.len() != 2
            || !matches!(
                suffix[0],
                InstallerEffectPlan::ProvisionStoreCredential { .. }
            )
            || !matches!(suffix[1], InstallerEffectPlan::MaterializePhaseB { .. })
        {
            return Err(InstallationError::IncompleteObservation(
                "first-install bootstrap must be followed by ordered credential then PhaseB"
                    .to_owned(),
            ));
        }
        for idx in cursor..self.installer_effects.len() {
            if !matches!(
                self.effect_progress[idx].state,
                InstallationEffectProgressState::Pending
            ) {
                return Err(InstallationError::IncompleteObservation(
                    "post-start suffix must remain pending through activation".to_owned(),
                ));
            }
            if self.effect_progress[idx]
                .store_credential
                .as_ref()
                .is_some_and(|c| c.receipt.is_some())
                || self.effect_progress[idx].phase_b_receipt.is_some()
                || self.effect_progress[idx].staging_receipt.is_some()
            {
                return Err(InstallationError::IncompleteObservation(
                    "pending suffix must not carry synthetic receipts".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Projects the two installer-owned SCM approvals from authoritative
    /// durable service-effect progress.
    ///
    /// Only `Applied` service effects can produce an approval.  A missing
    /// nonce, pending intent, or unknown effect is returned as a stable
    /// fail-closed classification; no nonce is copied into the error.
    pub(crate) fn service_registration_approvals(
        &self,
    ) -> Result<Vec<InstallerServiceRegistrationApproval>, InstallationError> {
        self.validate()?;
        self.service_registration_approvals_unchecked()
    }

    pub(super) fn service_registration_approvals_unchecked(
        &self,
    ) -> Result<Vec<InstallerServiceRegistrationApproval>, InstallationError> {
        let mut approvals = Vec::new();
        let mut roles = BTreeSet::new();
        let mut nonces = BTreeSet::<PlatformHandle>::new();
        for (effect, progress) in self.installer_effects.iter().zip(&self.effect_progress) {
            let InstallerEffectPlan::RegisterService {
                effect_id,
                role,
                service_name,
                executable_path,
                account,
                automatic_start,
            } = effect
            else {
                continue;
            };
            let registration_nonce = progress.registration_nonce.clone().ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "service registration approval is missing its durable nonce".to_owned(),
                )
            })?;
            let configuration_digest = match &progress.state {
                InstallationEffectProgressState::Applied {
                    external_identity, ..
                } => external_identity.clone(),
                InstallationEffectProgressState::Pending
                | InstallationEffectProgressState::IntentCommitted { .. } => {
                    return Err(InstallationError::IncompleteObservation(
                        "service registration effect is pending authoritative readback".to_owned(),
                    ));
                }
                InstallationEffectProgressState::Unknown { .. } => {
                    return Err(InstallationError::IncompleteObservation(
                        "service registration effect requires reconciliation".to_owned(),
                    ));
                }
            };
            if !roles.insert(*role) {
                return Err(InstallationError::Duplicate {
                    kind: "service registration role".to_owned(),
                    identity: format!("{role:?}"),
                });
            }
            if !nonces.insert(registration_nonce.clone()) {
                return Err(InstallationError::IdentityConflict);
            }
            let approval = InstallerServiceRegistrationApproval {
                transaction_id: self.transaction_id.clone(),
                generation: self.candidate_manifest.generation.clone(),
                effect_id: effect_id.clone(),
                role: *role,
                service_name: service_name.clone(),
                executable_path: executable_path.clone(),
                account: *account,
                automatic_start: *automatic_start,
                service_bootstrap: InstallationServiceBootstrap {
                    descriptor_path: self
                        .candidate_manifest
                        .runtime_launch
                        .authority_descriptor_path
                        .clone(),
                    descriptor_digest: phase_b_scm_digest(
                        &self
                            .candidate_manifest
                            .runtime_launch
                            .authority_descriptor_digest,
                    )?,
                    installation_id: self
                        .candidate_manifest
                        .runtime_launch
                        .installation_epoch
                        .installation
                        .clone(),
                    plan_generation: self
                        .candidate_manifest
                        .runtime_launch
                        .authority_generation
                        .value(),
                    host_state_root: self
                        .candidate_manifest
                        .runtime_launch
                        .runtime_state_roots
                        .host_state_root
                        .clone(),
                },
                registration_nonce,
                configuration_digest,
                service_control_grant: progress.service_control_grant.clone(),
            };
            approval.validate()?;
            approvals.push(approval);
        }
        approvals.sort_by_key(|approval| approval.role);
        Ok(approvals)
    }

    /// Returns the monotonic durable revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn installer_plan_unsigned_bytes(
        transaction_id: &PlatformHandle,
        candidate_manifest: &CandidateManifest,
        staging_root: &PlatformHandle,
        runtime_state_roots: &RuntimeStateRoots,
        minimum_store_available_bytes: u64,
        planned_changes: &[PlannedChange],
        installer_effects: &[InstallerEffectPlan],
    ) -> Result<Vec<u8>, InstallationError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            transaction_id: &'a PlatformHandle,
            candidate_manifest: &'a CandidateManifest,
            staging_root: &'a PlatformHandle,
            runtime_state_roots: &'a RuntimeStateRoots,
            minimum_store_available_bytes: u64,
            planned_changes: &'a [PlannedChange],
            installer_effects: &'a [InstallerEffectPlan],
        }
        serde_json::to_vec(&Unsigned {
            transaction_id,
            candidate_manifest,
            staging_root,
            runtime_state_roots,
            minimum_store_available_bytes,
            planned_changes,
            installer_effects,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "installer_plan".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the complete transaction projection.
    #[allow(
        clippy::too_many_lines,
        reason = "the complete transaction invariant is intentionally audited in one boundary"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.transaction_wire_version != INSTALLATION_TRANSACTION_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "installation transaction wire {} cannot be read as {}",
                    self.transaction_wire_version, INSTALLATION_TRANSACTION_WIRE_VERSION
                ),
            });
        }
        handle(&self.transaction_id, "transaction_id")?;
        self.installation_epoch.validate()?;
        self.request.validate()?;
        self.candidate_manifest.validate()?;
        if self.profile != self.candidate_manifest.runtime_launch.profile {
            return Err(InstallationError::ProfileViolation(
                "transaction profile must equal the candidate runtime launch profile".to_owned(),
            ));
        }
        if self.candidate_manifest.runtime_launch.installation_epoch != self.installation_epoch {
            return Err(InstallationError::InvalidField {
                field: "candidate_manifest.runtime_launch.installation_epoch".to_owned(),
                reason: "must exactly equal the transaction installation epoch".to_owned(),
            });
        }
        if let Some(manifest) = &self.current_active_manifest {
            manifest.validate()?;
        }
        handle(&self.staging_root, "staging_root")?;
        handle(&self.rollback_plan, "rollback_plan")?;
        handle(&self.recovery_command, "recovery_command")?;
        if self.minimum_store_available_bytes == 0 {
            return Err(InstallationError::InvalidField {
                field: "minimum_store_available_bytes".to_owned(),
                reason: "must be a non-zero explicit policy value".to_owned(),
            });
        }
        for change in &self.planned_changes {
            change.validate()?;
        }
        validate_installer_effects(
            self.profile,
            &self.candidate_manifest.runtime_launch.runtime_state_roots,
            &self.candidate_manifest.store_credential_target,
            &self.planned_changes,
            &self.installer_effects,
        )?;
        validate_phase_b_effect_bindings(&self.candidate_manifest, &self.installer_effects)?;
        validate_package_binding(
            &self.candidate_manifest,
            &self.staging_root,
            &self.installer_effects,
        )?;
        sha256_handle(&self.installer_plan_digest, "installer_plan_digest")?;
        if sha256_hex(&Self::installer_plan_unsigned_bytes(
            &self.transaction_id,
            &self.candidate_manifest,
            &self.staging_root,
            &self.candidate_manifest.runtime_launch.runtime_state_roots,
            self.minimum_store_available_bytes,
            &self.planned_changes,
            &self.installer_effects,
        )?) != self.installer_plan_digest.as_str()
        {
            return Err(InstallationError::InvalidField {
                field: "installer_plan_digest".to_owned(),
                reason: "installer plan digest mismatch".to_owned(),
            });
        }
        self.validate_effect_progress()?;
        self.validate_stage_progress()?;
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        handles(&self.precondition_evidence, "precondition_evidence", true)?;
        handles(&self.completed_stage_refs, "completed_stage_refs", false)?;
        handles(
            &self.pending_external_changes,
            "pending_external_changes",
            false,
        )?;
        handles(
            &self.observed_postconditions,
            "observed_postconditions",
            false,
        )?;
        match (&self.stage, &self.active_verified_receipt) {
            (
                InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed,
                Some(receipt),
            ) => receipt.validate_against_transaction(self)?,
            (
                InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed,
                None,
            ) => {
                return Err(InstallationError::IncompleteObservation(
                    "active/completed transaction requires the exact committed activation receipt"
                        .to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(InstallationError::IncompleteObservation(
                    "activation receipt cannot exist before ActiveVerified".to_owned(),
                ));
            }
            (_, None) => {}
        }
        if let Some(intent) = &self.activation_projection_intent {
            if self.stage == InstallationStage::Registering {
                return Err(InstallationError::IncompleteObservation(
                    "activation projection intent cannot precede the Activating boundary"
                        .to_owned(),
                ));
            }
            intent.validate_against_transaction(self)?;
        }
        if matches!(
            self.stage,
            InstallationStage::ActiveVerified | InstallationStage::Completed
        ) && self.observed_postconditions.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "active/completed transaction requires postcondition evidence".to_owned(),
            ));
        }
        if matches!(self.stage, InstallationStage::RollbackRequired)
            && self.pending_external_changes.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "rollback-required transaction must name pending external changes".to_owned(),
            ));
        }
        if matches!(
            self.stage,
            InstallationStage::RolledBack | InstallationStage::Quarantined
        ) && self.pending_external_changes.is_empty()
            && self.completed_stage_refs.is_empty()
        {
            return Err(InstallationError::IncompleteObservation(
                "terminal recovery state requires disposition evidence".to_owned(),
            ));
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        clippy::match_same_arms,
        reason = "one audit boundary validates all coupled durable effect-progress invariants"
    )]
    pub(super) fn validate_effect_progress(&self) -> Result<(), InstallationError> {
        if self.effect_progress.len() != self.installer_effects.len() {
            return Err(InstallationError::IdentityConflict);
        }
        let mut unsettled_seen = false;
        for (effect, progress) in self.installer_effects.iter().zip(&self.effect_progress) {
            if progress.effect_id != *effect.effect_id() {
                return Err(InstallationError::IdentityConflict);
            }
            if let Some(precondition) = &progress.admitted_precondition {
                precondition.validate()?;
                let snapshot_matches = match effect {
                    InstallerEffectPlan::ProvisionStoreCredential { .. } => {
                        precondition.credential_snapshot.is_some()
                            && precondition.os_snapshot.is_none()
                    }
                    InstallerEffectPlan::StagePackage { .. }
                    | InstallerEffectPlan::MaterializePhaseB { .. } => {
                        precondition.credential_snapshot.is_none()
                            && (matches!(effect, InstallerEffectPlan::MaterializePhaseB { .. })
                                || precondition.package_snapshot.is_some())
                            && precondition.os_snapshot.is_none()
                    }
                    InstallerEffectPlan::RegisterService { .. }
                    | InstallerEffectPlan::StartService { .. } => {
                        precondition.credential_snapshot.is_none()
                    }
                    _ => {
                        precondition.os_snapshot.is_some()
                            && precondition.credential_snapshot.is_none()
                    }
                };
                if !snapshot_matches {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.admitted_precondition".to_owned(),
                        reason: "must contain the typed snapshot for its exact effect".to_owned(),
                    });
                }
            }
            if let Some(ownership) = &progress.ownership_secret {
                ownership.validate()?;
                match ownership.lifecycle {
                    InstallationSecretLifecycle::Active
                        if !matches!(
                            self.stage,
                            InstallationStage::Completed | InstallationStage::RolledBack
                        ) => {}
                    InstallationSecretLifecycle::DeleteIntentCommitted
                        if self.stage == InstallationStage::RollbackRequired => {}
                    InstallationSecretLifecycle::Deleted
                        if matches!(
                            self.stage,
                            InstallationStage::RolledBack | InstallationStage::Completed
                        ) && self
                            .completed_stage_refs
                            .contains(&ownership_secret_absence_evidence(&ownership.reference)) => {
                    }
                    _ => {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.ownership_secret.lifecycle".to_owned(),
                            reason: "secret lifecycle does not match transaction recovery phase"
                                .to_owned(),
                        });
                    }
                }
            }
            if let Some(nonce) = &progress.registration_nonce {
                if !matches!(
                    effect,
                    InstallerEffectPlan::RegisterService { .. }
                        | InstallerEffectPlan::StartService { .. }
                ) {
                    return Err(InstallationError::IdentityConflict);
                }
                sha256_handle(nonce, "effect_progress.registration_nonce")?;
            }
            match (effect, &progress.state, &progress.service_control_grant) {
                (
                    InstallerEffectPlan::RegisterService {
                        role: InstallerServiceRole::Watchdog,
                        ..
                    },
                    InstallationEffectProgressState::Applied { .. },
                    Some(receipt),
                ) => receipt.validate()?,
                (
                    InstallerEffectPlan::RegisterService {
                        role: InstallerServiceRole::Watchdog,
                        ..
                    },
                    InstallationEffectProgressState::Applied { .. },
                    None,
                ) => {
                    return Err(InstallationError::IncompleteObservation(
                        "applied Watchdog registration requires its exact Host control grant receipt"
                            .to_owned(),
                    ));
                }
                (_, _, Some(_)) => return Err(InstallationError::IdentityConflict),
                (_, _, None) => {}
            }
            if matches!(
                &progress.state,
                InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Applied { .. }
            ) && matches!(
                effect,
                InstallerEffectPlan::RegisterService { .. }
                    | InstallerEffectPlan::StartService { .. }
            ) && progress.registration_nonce.is_none()
            {
                return Err(InstallationError::InvalidField {
                    field: "effect_progress.registration_nonce".to_owned(),
                    reason: "service intent requires durable nonce".to_owned(),
                });
            }
            match (effect, &progress.state, progress.service_start_deadline_ms) {
                (
                    InstallerEffectPlan::StartService { .. },
                    InstallationEffectProgressState::Pending,
                    None,
                )
                | (
                    InstallerEffectPlan::StartService { .. },
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::PreexistingMatching,
                        ..
                    },
                    None,
                ) => {}
                (
                    InstallerEffectPlan::StartService { .. },
                    InstallationEffectProgressState::Unknown { .. },
                    None,
                ) if progress.admitted_precondition.is_none() => {}
                (
                    InstallerEffectPlan::StartService { .. },
                    InstallationEffectProgressState::Unknown { .. },
                    Some(deadline),
                )
                | (
                    InstallerEffectPlan::StartService { .. },
                    InstallationEffectProgressState::IntentCommitted { .. },
                    Some(deadline),
                )
                | (
                    InstallerEffectPlan::StartService { .. },
                    InstallationEffectProgressState::Applied { .. },
                    Some(deadline),
                ) if deadline != 0 => {}
                (InstallerEffectPlan::StartService { .. }, _, Some(0)) => {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.service_start_deadline_ms".to_owned(),
                        reason: "must be non-zero when persisted for SCM start convergence"
                            .to_owned(),
                    });
                }
                (InstallerEffectPlan::StartService { .. }, _, None) => {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.service_start_deadline_ms".to_owned(),
                        reason: "committed SCM start progress requires a durable deadline"
                            .to_owned(),
                    });
                }
                (_, _, Some(_)) => {
                    return Err(InstallationError::IdentityConflict);
                }
                _ => {}
            }
            if let Some(proof) = &progress.service_start_proof {
                if !matches!(effect, InstallerEffectPlan::StartService { .. }) {
                    return Err(InstallationError::IdentityConflict);
                }
                sha256_handle(
                    &proof.intent_digest,
                    "effect_progress.service_start_proof.intent_digest",
                )?;
                if let Some(lineage) = &proof.process_lineage {
                    lineage.validate()?;
                }
                match &progress.state {
                    InstallationEffectProgressState::IntentCommitted { intent_digest, .. }
                        if proof.intent_digest != *intent_digest =>
                    {
                        return Err(InstallationError::IdentityConflict);
                    }
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Unknown { .. }
                    | InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    } => {}
                    _ => {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.service_start_proof".to_owned(),
                            reason:
                                "caller-start proof requires an unsettled or transaction-created start"
                                    .to_owned(),
                        });
                    }
                }
                if matches!(
                    progress.state,
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    }
                ) && proof.process_lineage.is_none()
                {
                    return Err(InstallationError::IncompleteObservation(
                        "transaction-created service start requires provider process lineage"
                            .to_owned(),
                    ));
                }
            }
            if matches!(
                progress.state,
                InstallationEffectProgressState::Applied {
                    disposition: InstallationEffectDisposition::CreatedByTransaction,
                    ..
                }
            ) && matches!(effect, InstallerEffectPlan::StartService { .. })
                && progress.service_start_proof.is_none()
            {
                return Err(InstallationError::IncompleteObservation(
                    "transaction-created service start requires the exact issued-call proof"
                        .to_owned(),
                ));
            }
            if let Some(credential) = &progress.store_credential {
                credential.validate()?;
                let InstallerEffectPlan::ProvisionStoreCredential { provision, .. } = effect else {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.store_credential".to_owned(),
                        reason: "credential progress belongs only to its provision effect"
                            .to_owned(),
                    });
                };
                match credential.lifecycle {
                    StoreCredentialLifecycle::Active
                        if !matches!(
                            self.stage,
                            InstallationStage::Completed | InstallationStage::RolledBack
                        ) => {}
                    StoreCredentialLifecycle::DeleteIntentCommitted
                    | StoreCredentialLifecycle::DeleteExecuted
                        if self.stage == InstallationStage::RollbackRequired => {}
                    StoreCredentialLifecycle::Deleted
                        if matches!(
                            self.stage,
                            InstallationStage::RolledBack | InstallationStage::Completed
                        ) => {}
                    _ => {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.store_credential.lifecycle".to_owned(),
                            reason: "credential lifecycle does not match transaction phase"
                                .to_owned(),
                        });
                    }
                }
                if let Some(receipt) = &credential.receipt
                    && (receipt.transaction_id != self.transaction_id
                        || receipt.effect_id != progress.effect_id
                        || receipt.generation != provision.generation
                        || receipt.config_digest != provision.config_digest
                        || receipt.target != provision.target
                        || receipt.provider != provision.provider
                        || receipt.scope != provision.scope
                        || receipt.principal_sid != provision.expected_principal_sid)
                {
                    return Err(InstallationError::IdentityConflict);
                }
            } else if matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
                && !matches!(progress.state, InstallationEffectProgressState::Pending)
            {
                return Err(InstallationError::InvalidField {
                    field: "effect_progress.store_credential".to_owned(),
                    reason: "committed credential effect requires typed durable progress"
                        .to_owned(),
                });
            }
            if let Some(receipt) = &progress.staging_receipt {
                let InstallerEffectPlan::StagePackage { .. } = effect else {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.staging_receipt".to_owned(),
                        reason: "package receipts belong only to the StagePackage effect"
                            .to_owned(),
                    });
                };
                validate_staging_receipt_for_plan(effect, receipt)?;
                let Some(precondition) = progress.admitted_precondition.as_ref() else {
                    return Err(InstallationError::IncompleteObservation(
                        "package receipt requires its durable source observation".to_owned(),
                    ));
                };
                let Some(snapshot) = precondition.package_snapshot.as_ref() else {
                    return Err(InstallationError::IncompleteObservation(
                        "package receipt requires its durable source observation".to_owned(),
                    ));
                };
                validate_staging_receipt_for_observation(snapshot, receipt)?;
            } else if matches!(
                (&progress.state, effect),
                (
                    InstallationEffectProgressState::Applied { .. },
                    InstallerEffectPlan::StagePackage { .. }
                )
            ) {
                return Err(InstallationError::InvalidField {
                    field: "effect_progress.staging_receipt".to_owned(),
                    reason: "applied package effect requires its typed staging receipt".to_owned(),
                });
            }
            if let Some(receipt) = &progress.phase_b_receipt {
                if !matches!(effect, InstallerEffectPlan::MaterializePhaseB { .. }) {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.phase_b_receipt".to_owned(),
                        reason: "Phase-B receipts belong only to the materialization effect"
                            .to_owned(),
                    });
                }
                receipt.validate()?;
                if receipt.transaction_id != self.transaction_id
                    || receipt.effect_id != progress.effect_id
                    || receipt.candidate_manifest_digest
                        != candidate_manifest_digest(&self.candidate_manifest)?
                {
                    return Err(InstallationError::IdentityConflict);
                }
            } else if matches!(
                (&progress.state, effect),
                (
                    InstallationEffectProgressState::Applied { .. },
                    InstallerEffectPlan::MaterializePhaseB { .. }
                )
            ) {
                return Err(InstallationError::InvalidField {
                    field: "effect_progress.phase_b_receipt".to_owned(),
                    reason: "applied Phase-B effect requires its typed receipt".to_owned(),
                });
            }
            if self.stage == InstallationStage::RolledBack
                && matches!(effect, InstallerEffectPlan::MaterializePhaseB { .. })
                && !matches!(progress.state, InstallationEffectProgressState::Pending)
            {
                return Err(InstallationError::InvalidField {
                    field: "effect_progress.phase_b_receipt".to_owned(),
                    reason: "a transaction with any Phase-B authority intent or live binding cannot be reported RolledBack"
                        .to_owned(),
                });
            }
            match (
                &progress.state,
                effect,
                &progress.admitted_precondition,
                &progress.ownership_secret,
            ) {
                (
                    InstallationEffectProgressState::Pending
                    | InstallationEffectProgressState::Unknown { .. },
                    _,
                    None,
                    None,
                ) => {}
                (
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Unknown { .. }
                    | InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    },
                    InstallerEffectPlan::CreateRoot { .. },
                    Some(_),
                    Some(_),
                ) => {}
                (
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Unknown { .. }
                    | InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    },
                    InstallerEffectPlan::StagePackage { .. },
                    Some(precondition),
                    ownership,
                ) if precondition.package_snapshot.is_some()
                    && ownership.as_ref().is_none_or(|ownership| {
                        ownership.lifecycle != InstallationSecretLifecycle::Deleted
                            && matches!(
                                ownership.secret_provision_disposition,
                                InstallationSecretProvisionDisposition::NotAttempted
                                    | InstallationSecretProvisionDisposition::Created
                            )
                    }) => {}
                (
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Unknown { .. }
                    | InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    },
                    InstallerEffectPlan::MaterializePhaseB { .. },
                    Some(_),
                    None,
                ) => {}
                (
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::PreexistingMatching,
                        ..
                    },
                    InstallerEffectPlan::CreateRoot { .. },
                    None,
                    None,
                ) => {}
                (
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Applied { .. }
                    | InstallationEffectProgressState::Unknown { .. },
                    InstallerEffectPlan::ApplyAcl { .. }
                    | InstallerEffectPlan::RegisterService { .. }
                    | InstallerEffectPlan::StartService { .. }
                    | InstallerEffectPlan::MaterializePhaseB { .. },
                    _,
                    None,
                ) => {}
                (
                    InstallationEffectProgressState::IntentCommitted { .. }
                    | InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        ..
                    }
                    | InstallationEffectProgressState::Unknown { .. },
                    InstallerEffectPlan::ProvisionStoreCredential { .. },
                    Some(_),
                    Some(_),
                ) if progress.store_credential.is_some() => {}
                _ => {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress.capability".to_owned(),
                        reason: "precondition and ownership must match the effect phase".to_owned(),
                    });
                }
            }
            match &progress.state {
                InstallationEffectProgressState::Applied {
                    disposition,
                    external_identity,
                    evidence,
                    postcondition_digest,
                    ..
                } if !unsettled_seen => {
                    if *disposition == InstallationEffectDisposition::CreatedByTransaction
                        && !matches!(
                            effect,
                            InstallerEffectPlan::RegisterService { .. }
                                | InstallerEffectPlan::StartService { .. }
                                | InstallerEffectPlan::StagePackage { .. }
                                | InstallerEffectPlan::MaterializePhaseB { .. }
                        )
                        && progress.ownership_secret.as_ref().is_none_or(|ownership| {
                            ownership.create_disposition != InstallationCreateDisposition::Created
                        })
                    {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.disposition".to_owned(),
                            reason: "transaction ownership requires a durable Created result"
                                .to_owned(),
                        });
                    }
                    if *disposition == InstallationEffectDisposition::CreatedByTransaction
                        && matches!(effect, InstallerEffectPlan::CreateRoot { .. })
                        && progress.ownership_secret.as_ref().is_none_or(|ownership| {
                            ownership.secret_provision_disposition
                                != InstallationSecretProvisionDisposition::Created
                        })
                    {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.ownership_secret.secret_provision_disposition"
                                .to_owned(),
                            reason: format!(
                                "root ownership requires a durable credential proof for {}",
                                effect.effect_id().as_str()
                            ),
                        });
                    }
                    if progress.ownership_secret.as_ref().is_some_and(|ownership| {
                        ownership.create_disposition == InstallationCreateDisposition::AlreadyExists
                    }) {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.ownership_secret.create_disposition".to_owned(),
                            reason: "AlreadyExists can never enter Applied ownership".to_owned(),
                        });
                    }
                    handle(external_identity, "effect_progress.external_identity")?;
                    handles(evidence, "effect_progress.evidence", true)?;
                    sha256_handle(postcondition_digest, "effect_progress.postcondition_digest")?;
                    if matches!(effect, InstallerEffectPlan::ProvisionStoreCredential { .. })
                        && progress
                            .store_credential
                            .as_ref()
                            .is_none_or(|credential| credential.receipt.is_none())
                    {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.store_credential.receipt".to_owned(),
                            reason: "applied credential ownership requires exact Host receipt"
                                .to_owned(),
                        });
                    }
                    if matches!(effect, InstallerEffectPlan::StagePackage { .. })
                        && progress.staging_receipt.is_none()
                    {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.staging_receipt".to_owned(),
                            reason: "applied package effect requires a durable receipt".to_owned(),
                        });
                    }
                }
                InstallationEffectProgressState::Pending => unsettled_seen = true,
                InstallationEffectProgressState::IntentCommitted {
                    attempt,
                    intent_digest,
                } if !unsettled_seen => {
                    if *attempt == 0 {
                        return Err(InstallationError::InvalidField {
                            field: "effect_progress.attempt".to_owned(),
                            reason: "must be non-zero".to_owned(),
                        });
                    }
                    sha256_handle(intent_digest, "effect_progress.intent_digest")?;
                    unsettled_seen = true;
                }
                InstallationEffectProgressState::Unknown { pending_ref } if !unsettled_seen => {
                    handle(pending_ref, "effect_progress.pending_ref")?;
                    unsettled_seen = true;
                }
                InstallationEffectProgressState::Applied { .. }
                | InstallationEffectProgressState::IntentCommitted { .. }
                | InstallationEffectProgressState::Unknown { .. } => {
                    return Err(InstallationError::InvalidField {
                        field: "effect_progress".to_owned(),
                        reason: "progress must be an applied prefix followed by at most one active state and a pending suffix".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_stage_progress(&self) -> Result<(), InstallationError> {
        let Some(package_index) = self
            .installer_effects
            .iter()
            .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }))
        else {
            return Ok(());
        };
        let package_applied = matches!(
            self.effect_progress[package_index].state,
            InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                ..
            }
        ) && self.effect_progress[package_index]
            .staging_receipt
            .is_some();
        if matches!(
            self.stage,
            InstallationStage::StaticVerified
                | InstallationStage::Registering
                | InstallationStage::Activating
                | InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed
        ) && !package_applied
        {
            return Err(InstallationError::IncompleteObservation(
                "static verification and later stages require the applied package receipt"
                    .to_owned(),
            ));
        }
        if self.stage == InstallationStage::Staging
            && package_index > 0
            && self.effect_progress[..package_index]
                .iter()
                .any(|progress| {
                    !matches!(
                        progress.state,
                        InstallationEffectProgressState::Applied { .. }
                    )
                })
        {
            return Err(InstallationError::IncompleteObservation(
                "package staging cannot begin before preceding root/ACL effects are applied"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn is_constructor_planned(&self) -> bool {
        matches!(
            self.planner_construction_proof,
            PlannerConstructionProof::Bound
        ) && self.transaction_wire_version == INSTALLATION_TRANSACTION_WIRE_VERSION
            && self.stage == InstallationStage::Planned
            && self.revision == 1
            && self.completed_stage_refs.is_empty()
            && self.pending_external_changes.is_empty()
            && self.observed_postconditions.is_empty()
            && self.active_verified_receipt.is_none()
            && self.last_known_good.is_none()
            && self.no_return_boundary.is_none()
            && self
                .effect_progress
                .iter()
                .all(|progress| matches!(progress.state, InstallationEffectProgressState::Pending))
    }

    /// Records the real Store-volume observation through this transaction's
    /// existing fail-closed state machine.
    pub fn record_store_free_space(
        &mut self,
        observation: StoreFreeSpaceObservation,
    ) -> Result<InstallationStepOutcome, InstallationError> {
        self.validate()?;
        match observation {
            StoreFreeSpaceObservation::Known {
                available_bytes,
                evidence_refs,
            } => {
                handles(&evidence_refs, "free_space.evidence_refs", true)?;
                if available_bytes < self.minimum_store_available_bytes {
                    return Ok(InstallationStepOutcome::Rejected);
                }
                self.precondition_evidence.extend(evidence_refs.clone());
                self.revision = self.revision.checked_add(1).ok_or_else(|| {
                    InstallationError::InvalidField {
                        field: "revision".to_owned(),
                        reason: "overflow".to_owned(),
                    }
                })?;
                self.validate()?;
                Ok(InstallationStepOutcome::Applied {
                    stage: self.stage,
                    evidence_refs,
                })
            }
            StoreFreeSpaceObservation::Unknown { evidence_refs } => {
                self.mark_unknown(evidence_refs.clone())?;
                Ok(InstallationStepOutcome::RollbackRequired {
                    pending_refs: evidence_refs,
                })
            }
        }
    }

    /// Advances one non-runtime-health stage using observed evidence and
    /// increments the revision.
    ///
    /// This raw transition is crate-private. `ActiveVerified` is never a
    /// value accepted by this path; it requires the opaque receipt produced by
    /// the read-only registry terminal projection below.
    pub(super) fn advance(
        &mut self,
        next: InstallationStage,
        evidence: Vec<PlatformHandle>,
    ) -> Result<(), InstallationError> {
        if next == InstallationStage::ActiveVerified {
            return Err(InstallationError::IncompleteObservation(
                "ActiveVerified requires the exact committed activation receipt".to_owned(),
            ));
        }
        if !self.stage.can_advance(next) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: next,
            });
        }
        handles(&evidence, "stage_evidence", true)?;
        self.completed_stage_refs.extend(evidence);
        self.stage = next;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.validate()
    }

    /// Crosses the signed activation boundary only for the exact verified
    /// approval and immutable plan.  The transaction store owns the CAS that
    /// persists this mutation; callers never receive a raw stage-advance seam.
    pub(crate) fn advance_to_activating_for_signed_approval(
        &mut self,
        approval: &InstallationActivationApproval,
        activation_projection_intent: InstallationActivationProjectionIntent,
    ) -> Result<(), InstallationError> {
        if self.stage != InstallationStage::Registering {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::Activating,
            });
        }
        self.require_signed_pending_activation_effects()?;
        approval.validate_against(self)?;
        let evidence = PlatformHandle::new(sha256_hex(
            format!(
                "signed-activation-stage-v1\0{}\0{}\0{}",
                self.transaction_id.as_str(),
                self.installer_plan_digest.as_str(),
                approval.approval_ref.as_str(),
            )
            .as_bytes(),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "stage_evidence".to_owned(),
            reason: error.to_string(),
        })?;
        let original_revision = self.revision;
        self.advance(InstallationStage::Activating, vec![evidence])?;
        if activation_projection_intent.original_transaction_revision != original_revision {
            return Err(InstallationError::IdentityConflict);
        }
        activation_projection_intent.validate_against_transaction(self)?;
        if !activation_projection_intent
            .verified_approval
            .matches_approval(approval)
        {
            return Err(InstallationError::IdentityConflict);
        }
        self.activation_projection_intent = Some(activation_projection_intent);
        self.validate()
    }

    /// Quarantines a signed projection mismatch without rolling back any
    /// external effect or changing another actor's transaction.
    pub(crate) fn quarantine_activation_projection(
        &mut self,
        pending_ref: PlatformHandle,
    ) -> Result<(), InstallationError> {
        if self.stage != InstallationStage::Activating {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::Quarantined,
            });
        }
        handle(&pending_ref, "activation_projection.pending_ref")?;
        self.pending_external_changes = vec![pending_ref];
        self.stage = InstallationStage::Quarantined;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.validate()
    }

    /// Advances from `Activating` to `ActiveVerified` using the exact
    /// read-only registry terminal proof. The proof is consumed and its
    /// complete binding is persisted in the v21 transaction projection.
    pub fn advance_to_active_verified(
        &mut self,
        receipt: ActivationCommitReceipt,
        evidence: Vec<PlatformHandle>,
    ) -> Result<(), InstallationError> {
        if self.stage != InstallationStage::Activating {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::ActiveVerified,
            });
        }
        self.validate()?;
        handles(&evidence, "stage_evidence", true)?;
        receipt.validate_against_transaction(self)?;
        if self.active_verified_receipt.is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        self.completed_stage_refs.extend(evidence);
        self.observed_postconditions
            .extend(self.completed_stage_refs.clone());
        self.active_verified_receipt = Some(receipt.binding());
        self.stage = InstallationStage::ActiveVerified;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.validate()
    }

    /// Records an external effect whose outcome cannot yet be classified.
    pub fn mark_unknown(&mut self, pending: Vec<PlatformHandle>) -> Result<(), InstallationError> {
        handles(&pending, "pending_external_changes", true)?;
        if !self.stage.can_advance(InstallationStage::RollbackRequired) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::RollbackRequired,
            });
        }
        if self.stage == InstallationStage::Activating {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::RollbackRequired,
            });
        }
        if self.activation_projection_intent.is_some() {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::RollbackRequired,
            });
        }
        self.pending_external_changes = pending;
        self.stage = InstallationStage::RollbackRequired;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.validate()
    }

    /// Records a no-return activation boundary after explicit observation.
    pub fn record_no_return_boundary(
        &mut self,
        reference: PlatformHandle,
    ) -> Result<(), InstallationError> {
        handle(&reference, "no_return_boundary")?;
        if !matches!(
            self.stage,
            InstallationStage::Activating | InstallationStage::ActiveVerified
        ) {
            return Err(InstallationError::IllegalTransition {
                from: self.stage,
                to: InstallationStage::ActiveVerified,
            });
        }
        self.no_return_boundary = Some(reference);
        self.validate()
    }
}

/// Private durable decoder shape for [`InstallationTransaction`].  The
/// public transaction intentionally does not implement `Deserialize`: an
/// arbitrary caller-authored JSON record must not be able to manufacture the
/// private v9 activation receipt binding.  Only the version-gated decoder
/// below may reconstruct this shape, and it still runs the full transaction
/// validator before admission.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationTransactionWire {
    transaction_wire_version: ContractVersion,
    transaction_id: PlatformHandle,
    installation_epoch: InstallationEpoch,
    profile: InstallationProfile,
    request: ManagedEnvironmentChangeRequest,
    current_active_manifest: Option<CandidateManifest>,
    candidate_manifest: CandidateManifest,
    staging_root: PlatformHandle,
    planned_changes: Vec<PlannedChange>,
    installer_effects: Vec<InstallerEffectPlan>,
    minimum_store_available_bytes: u64,
    installer_plan_digest: PlatformHandle,
    effect_progress: Vec<InstallationEffectProgress>,
    precondition_evidence: Vec<PlatformHandle>,
    stage: InstallationStage,
    completed_stage_refs: Vec<PlatformHandle>,
    pending_external_changes: Vec<PlatformHandle>,
    rollback_plan: PlatformHandle,
    last_known_good: Option<PlatformHandle>,
    no_return_boundary: Option<PlatformHandle>,
    observed_postconditions: Vec<PlatformHandle>,
    active_verified_receipt: Option<ActiveVerifiedReceiptBinding>,
    activation_projection_intent: Option<InstallationActivationProjectionIntent>,
    recovery_command: PlatformHandle,
    revision: u64,
}

impl InstallationTransactionWire {
    fn into_transaction(self) -> InstallationTransaction {
        InstallationTransaction {
            transaction_wire_version: self.transaction_wire_version,
            transaction_id: self.transaction_id,
            installation_epoch: self.installation_epoch,
            profile: self.profile,
            request: self.request,
            current_active_manifest: self.current_active_manifest,
            candidate_manifest: self.candidate_manifest,
            staging_root: self.staging_root,
            planned_changes: self.planned_changes,
            installer_effects: self.installer_effects,
            minimum_store_available_bytes: self.minimum_store_available_bytes,
            installer_plan_digest: self.installer_plan_digest,
            effect_progress: self.effect_progress,
            precondition_evidence: self.precondition_evidence,
            stage: self.stage,
            completed_stage_refs: self.completed_stage_refs,
            pending_external_changes: self.pending_external_changes,
            rollback_plan: self.rollback_plan,
            last_known_good: self.last_known_good,
            no_return_boundary: self.no_return_boundary,
            observed_postconditions: self.observed_postconditions,
            active_verified_receipt: self.active_verified_receipt,
            activation_projection_intent: self.activation_projection_intent,
            recovery_command: self.recovery_command,
            revision: self.revision,
            planner_construction_proof: PlannerConstructionProof::Unbound,
        }
    }
}

/// Validates the canonical transaction JSON without exposing a deserialized
/// transaction authority object to another crate. Pre-v22 records are
/// classified as an explicit migration requirement rather than synthesizing
/// missing progress.
pub fn validate_installation_transaction_json(bytes: &[u8]) -> Result<(), InstallationError> {
    decode_installation_transaction_json_with_policy(bytes, false).map(|_| ())
}

/// Decodes canonical transaction JSON for installation-internal callers and
/// tests. The returned value is unbound unless it was produced by the
/// planner; callers outside this crate must use
/// [`validate_installation_transaction_json`].
#[cfg(test)]
pub(super) fn decode_installation_transaction_json(
    bytes: &[u8],
) -> Result<InstallationTransaction, InstallationError> {
    decode_installation_transaction_json_with_policy(bytes, false)
}

/// Decodes a transaction record from the ACL-protected redb store. This
/// private replay lane may restore an already advanced transaction so the
/// store can compare it with a freshly read registry receipt. Untrusted JSON
/// callers must use [`validate_installation_transaction_json`], which rejects
/// advanced runtime states before any caller can present them as installer
/// authority.
pub(super) fn decode_installation_transaction_json_from_store(
    bytes: &[u8],
) -> Result<InstallationTransaction, InstallationError> {
    decode_installation_transaction_json_with_policy(bytes, true)
}

fn validate_current_transaction_progress(
    value: &serde_json::Value,
) -> Result<(), InstallationError> {
    let effect_progress = value
        .get("effect_progress")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| InstallationError::CorruptRegistry {
            reason: "installation transaction wire is missing mandatory effect progress array"
                .to_owned(),
        })?;
    for (index, progress) in effect_progress.iter().enumerate() {
        let progress = progress
            .as_object()
            .ok_or_else(|| InstallationError::CorruptRegistry {
                reason: format!(
                    "installation transaction effect progress entry {index} is not an object"
                ),
            })?;
        for (field, label) in [
            ("service_control_grant", "service control grant"),
            ("registration_nonce", "registration nonce"),
            ("service_start_deadline_ms", "service start deadline"),
            ("service_start_proof", "service start proof"),
        ] {
            if !progress.contains_key(field) {
                return Err(InstallationError::CorruptRegistry {
                    reason: format!(
                        "installation transaction effect progress entry {index} is missing mandatory {label} member"
                    ),
                });
            }
        }
        if let Some(ownership) = progress
            .get("ownership_secret")
            .filter(|ownership| !ownership.is_null())
        {
            let object = ownership
                .as_object()
                .ok_or_else(|| InstallationError::CorruptRegistry {
                    reason: format!(
                        "installation transaction effect progress entry {index} ownership secret is not an object"
                    ),
                })?;
            for (field, label) in [
                (
                    "secret_provision_disposition",
                    "secret provision disposition",
                ),
                ("creation_proof", "credential creation proof"),
            ] {
                if !object.contains_key(field) {
                    return Err(InstallationError::MigrationRequired {
                        reason: format!(
                            "installation transaction effect progress entry {index} is missing mandatory {label}; explicit migration to v22 is required"
                        ),
                    });
                }
            }
        }
        if let Some(proof) = progress
            .get("service_start_proof")
            .filter(|proof| !proof.is_null())
        {
            let proof = proof
                .as_object()
                .ok_or_else(|| InstallationError::CorruptRegistry {
                    reason: format!(
                        "installation transaction effect progress entry {index} service start proof is not an object"
                    ),
                })?;
            if !proof.contains_key("process_lineage") {
                return Err(InstallationError::CorruptRegistry {
                    reason: format!(
                        "installation transaction effect progress entry {index} service start proof is missing mandatory process lineage member"
                    ),
                });
            }
        }
    }
    Ok(())
}

fn decode_installation_transaction_json_with_policy(
    bytes: &[u8],
    allow_advanced_state: bool,
) -> Result<InstallationTransaction, InstallationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    let version = value.get("transaction_wire_version").ok_or_else(|| {
        InstallationError::MigrationRequired {
            reason: "installation transaction predates the required v22 discriminator".to_owned(),
        }
    })?;
    let version: ContractVersion = serde_json::from_value(version.clone()).map_err(|_| {
        InstallationError::MigrationRequired {
            reason: "installation transaction has an unsupported wire discriminator".to_owned(),
        }
    })?;
    if version != INSTALLATION_TRANSACTION_WIRE_VERSION {
        return Err(InstallationError::MigrationRequired {
            reason: format!(
                "installation transaction wire {version} requires explicit migration to {INSTALLATION_TRANSACTION_WIRE_VERSION}"
            ),
        });
    }
    if !value
        .as_object()
        .is_some_and(|object| object.contains_key("activation_projection_intent"))
    {
        return Err(InstallationError::CorruptRegistry {
            reason: "installation transaction wire is missing mandatory activation projection intent member"
                .to_owned(),
        });
    }
    validate_current_transaction_progress(&value)?;
    let transaction: InstallationTransactionWire =
        serde_json::from_value(value).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    let transaction = transaction.into_transaction();
    transaction.validate()?;
    if !allow_advanced_state
        && matches!(
            transaction.stage(),
            InstallationStage::ActiveVerified
                | InstallationStage::Cleaning
                | InstallationStage::Completed
        )
    {
        return Err(InstallationError::MigrationRequired {
            reason: "advanced transaction state requires ACL-protected store replay and an exact registry receipt"
                .to_owned(),
        });
    }
    Ok(transaction)
}

/// Parses the stable identity used to address one durable installation transaction.
///
/// This narrow adapter keeps CLI callers on the installation contract without
/// importing the platform crate or constructing a second transaction identity
/// path. It performs only the same text validation used by the transaction
/// constructor; the durable store remains the authority for existence and CAS.
pub fn parse_installation_transaction_id(
    value: impl Into<String>,
) -> Result<PlatformHandle, InstallationError> {
    PlatformHandle::new(value.into()).map_err(|error| InstallationError::InvalidField {
        field: "transaction_id".to_owned(),
        reason: error.to_string(),
    })
}
