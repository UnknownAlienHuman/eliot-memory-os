//! Deterministic model-free setup binding and its ordered milestone table.
//!
//! I3.2 (`docs/architecture/I03-02-deterministic-setup-before-agents.md`)
//! defines the exact seven-step trust-root sequence that must complete before
//! any agent authority exists. The installation transaction's generic
//! `PLANNED -> COMPLETED` stage machine is not itself this sequence; this
//! module owns the bounded setup substate and its closed transition table
//! under the same installation owner, with no second setup database.
//!
//! A milestone is complete only with its required observation/receipt: an enum
//! increment or a caller Boolean is insufficient. The binding is persisted in
//! the existing protected operational journal (the installation transaction
//! redb store) before canonical storage is available, so restart resumes the
//! same transaction and its proven milestones instead of creating another root
//! of trust.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use eliot_config::initial_snapshot::{
    InitialConfigSnapshotTrustAnchor, InitialSnapshotError, InitialSnapshotVerificationContext,
    PrivacyChoice, SignedInitialConfigSnapshot,
};

use super::{
    ContractVersion, InstallationError, InstallationProfile, PlatformHandle, handle, handles,
    runtime_sha256_handle, sha256_hex,
};

/// Breaking wire revision for durable [`SetupBinding`] records.
pub const SETUP_BINDING_WIRE_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// The ordered I3.2 trust milestones.
///
/// The sequence is closed: the only admitted advance is the immediately
/// following milestone, each completed only with its required observation.
/// Restart resumes at the recorded milestone; the table never resets a
/// completed installation into first-run setup.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetupMilestone {
    /// The user confirmed the installation identity.
    InstallationIdentityConfirmed,
    /// The System Owner principal was established.
    SystemOwnerEstablished,
    /// Local service keys and tokens were generated.
    ServiceKeysGenerated,
    /// ACLs were installed.
    AclsInstalled,
    /// The privacy mode was selected.
    PrivacyModeSelected,
    /// Storage started and was verified.
    StorageVerified,
    /// The first signed configuration snapshot was created.
    InitialSnapshotCreated,
}

impl SetupMilestone {
    /// Returns all seven milestones in their exact I3.2 order.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [
            Self::InstallationIdentityConfirmed,
            Self::SystemOwnerEstablished,
            Self::ServiceKeysGenerated,
            Self::AclsInstalled,
            Self::PrivacyModeSelected,
            Self::StorageVerified,
            Self::InitialSnapshotCreated,
        ]
    }

    /// Returns the zero-based position of this milestone in the closed table.
    #[must_use]
    pub const fn position(self) -> usize {
        self as usize
    }

    /// Returns the stable effect identity required for this milestone's
    /// observation.
    #[must_use]
    pub const fn effect_identity(self) -> &'static str {
        match self {
            Self::InstallationIdentityConfirmed => "setup:identity-confirmed",
            Self::SystemOwnerEstablished => "setup:system-owner-established",
            Self::ServiceKeysGenerated => "setup:service-keys-generated",
            Self::AclsInstalled => "setup:acls-installed",
            Self::PrivacyModeSelected => "setup:privacy-mode-selected",
            Self::StorageVerified => "setup:storage-verified",
            Self::InitialSnapshotCreated => "setup:initial-snapshot-created",
        }
    }

    /// Returns the next milestone, or `None` when the binding is complete.
    #[must_use]
    pub fn next(self) -> Option<Self> {
        Self::all().get(self.position() + 1).copied()
    }

    /// The closed ordered transition table: the only admitted advance is the
    /// immediately following milestone. Skipping, repeating, and rolling back
    /// are all refused.
    #[must_use]
    pub const fn can_advance(self, next: Self) -> bool {
        next.position() == self.position() + 1
    }
}

/// Non-secret reference to one generated service key or token.
///
/// Secrets are generated through the existing cryptographic/secret-provider
/// boundary and are never derived from installation names, fixtures, or
/// timestamps. Only the scoped reference and the owning principal SID are
/// retained in the durable binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupKeyReference {
    /// Stable opaque key identity.
    pub key_id: PlatformHandle,
    /// Non-secret provider target (for example a Credential Manager target).
    pub target_ref: PlatformHandle,
    /// Exact principal SID that owns the key.
    pub principal_sid: PlatformHandle,
}

impl SetupKeyReference {
    fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.key_id, "setup_binding.key_references.key_id")?;
        handle(&self.target_ref, "setup_binding.key_references.target_ref")?;
        if !self.principal_sid.as_str().starts_with("S-") {
            return Err(InstallationError::InvalidField {
                field: "setup_binding.key_references.principal_sid".to_owned(),
                reason: "must be a principal SID".to_owned(),
            });
        }
        Ok(())
    }
}

/// The exact observed effect proving one setup milestone's postcondition.
///
/// The observation binds the milestone's stable effect identity, non-secret
/// evidence references, and the digest of the exact observed postcondition.
/// An enum increment or caller Boolean cannot substitute for it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupEffectObservation {
    /// Stable identity of the observed setup effect.
    pub effect_id: PlatformHandle,
    /// Non-secret evidence references proving the postcondition.
    pub evidence_refs: Vec<PlatformHandle>,
    /// Digest of the exact observed postcondition.
    pub observed_digest: PlatformHandle,
}

impl SetupEffectObservation {
    fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.effect_id, "setup_binding.observed_effects.effect_id")?;
        handles(
            &self.evidence_refs,
            "setup_binding.observed_effects.evidence_refs",
            true,
        )?;
        runtime_sha256_handle(
            &self.observed_digest,
            "setup_binding.observed_effects.observed_digest",
        )
    }
}

/// Inputs for advancing the setup binding by exactly one milestone.
///
/// The caller declares the milestone it completed. The closed transition
/// table admits it only when it is the immediately following milestone of the
/// recorded state, so an out-of-order, repeated or rolled-back milestone is
/// refused with the exact recovery action instead of being silently reordered.
///
/// Each milestone admits only its own inputs: key references are bound only
/// when entering [`SetupMilestone::ServiceKeysGenerated`] and the privacy
/// choice only when entering [`SetupMilestone::PrivacyModeSelected`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupAdvanceInput {
    /// Milestone this input completes. It must be the immediate successor of
    /// the recorded milestone.
    pub milestone: SetupMilestone,
    /// Exact observed effect for the milestone being entered.
    pub observation: SetupEffectObservation,
    /// Non-secret references to the generated service keys/tokens.
    pub key_references: Vec<SetupKeyReference>,
    /// Privacy mode selection for the privacy milestone.
    pub privacy_choice: Option<PrivacyChoice>,
}

/// Read-only setup status for authenticated setup-status/recovery queries.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SetupStatus {
    /// No setup binding exists for the installation.
    NotStarted,
    /// Setup is in progress at one ordered milestone.
    InProgress {
        /// Milestone the binding has reached.
        milestone: SetupMilestone,
        /// Durable binding revision.
        revision: u64,
    },
    /// All seven milestones and the signed initial snapshot are complete.
    Complete {
        /// Durable binding revision.
        revision: u64,
    },
}

/// The closed model-free setup state for one installation transaction.
///
/// The binding references the transaction/installation identity, the selected
/// profile and root digest, the expected previous revision, the confirmed
/// owner, the generated key references, the privacy choice, the exact
/// observed effects, and the final signed configuration reference. Mutable
/// progression state is read-only outside this crate; the raw milestone
/// transition is crate-private and requires the exact observation for the
/// milestone being entered.
///
/// ```compile_fail
/// use eliot_installation::{SetupBinding, SetupMilestone};
///
/// fn forge_complete(binding: &mut SetupBinding) {
///     binding.state = SetupMilestone::InitialSnapshotCreated;
/// }
/// ```
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupBinding {
    /// Breaking wire discriminator for this binding projection.
    pub wire_version: ContractVersion,
    /// Sole installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Installation identity confirmed at milestone 1.
    pub installation_id: PlatformHandle,
    /// Selected supervision/path profile.
    pub profile: InstallationProfile,
    /// Digest of the exact profile-bound runtime root topology.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Revision of the prior durable setup binding (0 = fresh setup).
    pub expected_previous_revision: u64,
    /// Confirmed System Owner reference.
    pub confirmed_owner: PlatformHandle,
    /// Non-secret references to the generated service keys/tokens.
    pub(super) key_references: Vec<SetupKeyReference>,
    /// Privacy mode selection, bound at milestone 5.
    pub(super) privacy_choice: Option<PrivacyChoice>,
    /// Exact observed effects, one per completed milestone in order.
    pub(super) observed_effects: Vec<SetupEffectObservation>,
    /// Final signed configuration snapshot reference, bound at milestone 7.
    pub(super) configuration_snapshot_ref: Option<PlatformHandle>,
    /// Current milestone in the closed ordered table.
    pub(super) state: SetupMilestone,
    /// Monotonic durable revision.
    pub(super) revision: u64,
    /// Digest of the exact canonical binding bytes.
    pub binding_digest: PlatformHandle,
}

/// The read-only status projection of one setup binding.
impl SetupBinding {
    /// Creates the binding at milestone 1 with the confirmed identity
    /// observation.
    ///
    /// The observed digest is derived deterministically from the confirmed
    /// identity facts; the caller supplies only the non-secret evidence
    /// references proving the authenticated local user and installation
    /// confirmation.
    ///
    /// # Errors
    /// Returns [`InstallationError`] when the identity facts are invalid.
    pub fn new(
        transaction_id: PlatformHandle,
        installation_id: PlatformHandle,
        profile: InstallationProfile,
        runtime_state_roots_digest: PlatformHandle,
        expected_previous_revision: u64,
        confirmed_owner: PlatformHandle,
        identity_evidence: Vec<PlatformHandle>,
    ) -> Result<Self, InstallationError> {
        handle(&transaction_id, "setup_binding.transaction_id")?;
        handle(&installation_id, "setup_binding.installation_id")?;
        runtime_sha256_handle(
            &runtime_state_roots_digest,
            "setup_binding.runtime_state_roots_digest",
        )?;
        handle(&confirmed_owner, "setup_binding.confirmed_owner")?;
        handles(&identity_evidence, "setup_binding.identity_evidence", true)?;
        let milestone = SetupMilestone::InstallationIdentityConfirmed;
        let observed_digest = PlatformHandle::new(sha256_hex(
            format!(
                "eliot.setup.identity-confirmed.v1\0{}\0{}\0{}\0{}\0{}",
                transaction_id.as_str(),
                installation_id.as_str(),
                profile_ref(profile)?,
                runtime_state_roots_digest.as_str(),
                confirmed_owner.as_str(),
            )
            .as_bytes(),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "setup_binding.observed_effects.observed_digest".to_owned(),
            reason: error.to_string(),
        })?;
        let observed_effects = vec![SetupEffectObservation {
            effect_id: PlatformHandle::new(milestone.effect_identity()).map_err(|error| {
                InstallationError::InvalidField {
                    field: "setup_binding.observed_effects.effect_id".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            evidence_refs: identity_evidence,
            observed_digest,
        }];
        let canonical = canonical_binding_bytes(
            &transaction_id,
            &installation_id,
            profile,
            &runtime_state_roots_digest,
            expected_previous_revision,
            &confirmed_owner,
            &[],
            None,
            &observed_effects,
            None,
            milestone,
            1,
        )?;
        let binding = Self {
            wire_version: SETUP_BINDING_WIRE_VERSION,
            transaction_id,
            installation_id,
            profile,
            runtime_state_roots_digest,
            expected_previous_revision,
            confirmed_owner,
            key_references: Vec::new(),
            privacy_choice: None,
            observed_effects,
            configuration_snapshot_ref: None,
            state: milestone,
            revision: 1,
            binding_digest: PlatformHandle::new(sha256_hex(&canonical)).map_err(|error| {
                InstallationError::InvalidField {
                    field: "setup_binding.binding_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Advances the binding by exactly one milestone with its required
    /// observation, incrementing the revision.
    ///
    /// The input declares the milestone it completed. The closed transition
    /// table admits it only when it is the immediate successor of the recorded
    /// milestone, and the supplied observation must carry that milestone's
    /// stable effect identity — an observation of a different operation cannot
    /// be presented as the milestone it claims to record. A refusal names the
    /// exact recovery action.
    ///
    /// Key references are bound only when entering
    /// [`SetupMilestone::ServiceKeysGenerated`], the privacy choice only when
    /// entering [`SetupMilestone::PrivacyModeSelected`], and the final
    /// configuration reference only when entering
    /// [`SetupMilestone::InitialSnapshotCreated`] — the configuration snapshot
    /// reference is the observed snapshot envelope digest. A completed binding
    /// cannot advance.
    ///
    /// # Errors
    /// Returns [`InstallationError`] on an out-of-order advance, a mismatched
    /// observation, or a missing required input.
    pub fn advance(&mut self, input: SetupAdvanceInput) -> Result<(), InstallationError> {
        let next = self.state.next().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "setup binding is already complete at the initial snapshot milestone".to_owned(),
            )
        })?;
        if !self.state.can_advance(input.milestone) {
            return Err(InstallationError::IncompleteObservation(format!(
                "setup advance refused: transaction {} is recorded at {} and {} is not its ordered successor; recovery: resume the same setup transaction and complete the pending milestone {} first",
                self.transaction_id.as_str(),
                self.state.effect_identity(),
                input.milestone.effect_identity(),
                next.effect_identity(),
            )));
        }
        if input.observation.effect_id.as_str() != next.effect_identity() {
            return Err(InstallationError::InvalidField {
                field: "setup.observation.effect_id".to_owned(),
                reason: format!(
                    "observation of {} was supplied for milestone {}; recovery: observe the exact effect of {} before advancing",
                    input.observation.effect_id.as_str(),
                    next.effect_identity(),
                    next.effect_identity(),
                ),
            });
        }
        input.observation.validate()?;
        if matches!(next, SetupMilestone::ServiceKeysGenerated) {
            if input.key_references.is_empty() {
                return Err(InstallationError::IncompleteObservation(
                    "service key generation requires non-empty key references".to_owned(),
                ));
            }
            for reference in &input.key_references {
                reference.validate()?;
            }
            self.key_references = input.key_references;
        } else if !input.key_references.is_empty() {
            return Err(InstallationError::InvalidField {
                field: "setup.observation.key_references".to_owned(),
                reason: "key references are bound only at the service key milestone".to_owned(),
            });
        }
        if matches!(next, SetupMilestone::PrivacyModeSelected) {
            let choice = input.privacy_choice.ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "privacy mode selection requires the confirmed choice".to_owned(),
                )
            })?;
            self.privacy_choice = Some(choice);
        } else if input.privacy_choice.is_some() {
            return Err(InstallationError::InvalidField {
                field: "setup.observation.privacy_choice".to_owned(),
                reason: "the privacy choice is bound only at the privacy milestone".to_owned(),
            });
        }
        if matches!(next, SetupMilestone::InitialSnapshotCreated) {
            self.configuration_snapshot_ref = Some(input.observation.observed_digest.clone());
        }
        self.observed_effects.push(input.observation);
        self.state = next;
        self.revision =
            self.revision
                .checked_add(1)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "setup_binding.revision".to_owned(),
                    reason: "overflow".to_owned(),
                })?;
        self.binding_digest = self.compute_digest()?;
        self.validate()
    }

    /// Returns the current milestone without exposing a mutation seam.
    #[must_use]
    pub const fn state(&self) -> SetupMilestone {
        self.state
    }

    /// Returns the monotonic durable revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the non-secret generated key references.
    #[must_use]
    pub fn key_references(&self) -> &[SetupKeyReference] {
        &self.key_references
    }

    /// Returns the confirmed privacy mode selection.
    #[must_use]
    pub const fn privacy_choice(&self) -> Option<PrivacyChoice> {
        self.privacy_choice
    }

    /// Returns the exact observed effects in milestone order.
    #[must_use]
    pub fn observed_effects(&self) -> &[SetupEffectObservation] {
        &self.observed_effects
    }

    /// Returns the final signed configuration snapshot reference.
    #[must_use]
    pub const fn configuration_snapshot_ref(&self) -> Option<&PlatformHandle> {
        self.configuration_snapshot_ref.as_ref()
    }

    /// Returns the read-only setup status for authenticated recovery queries.
    #[must_use]
    pub fn status(&self) -> SetupStatus {
        if self.state == SetupMilestone::InitialSnapshotCreated {
            SetupStatus::Complete {
                revision: self.revision,
            }
        } else {
            SetupStatus::InProgress {
                milestone: self.state,
                revision: self.revision,
            }
        }
    }

    /// Requires all seven milestones and the final configuration reference.
    ///
    /// This is the admission gate for any authority entrypoint: a missing,
    /// corrupt, foreign, stale, or partially published record cannot unlock
    /// ordinary agents.
    ///
    /// # Errors
    /// Returns [`InstallationError`] when the binding is incomplete or invalid.
    pub fn require_complete(&self) -> Result<(), InstallationError> {
        self.validate()?;
        if self.state != SetupMilestone::InitialSnapshotCreated {
            return Err(InstallationError::IncompleteObservation(format!(
                "setup binding is incomplete at milestone {:?}",
                self.state
            )));
        }
        if self.configuration_snapshot_ref.is_none() {
            return Err(InstallationError::IncompleteObservation(
                "setup binding is missing its final configuration reference".to_owned(),
            ));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<PlatformHandle, InstallationError> {
        let bytes = self.canonical_bytes()?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "setup_binding.binding_digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Returns the canonical bytes covered by [`Self::binding_digest`].
    ///
    /// # Errors
    /// Returns [`InstallationError`] when the binding cannot be canonicalized.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InstallationError> {
        canonical_binding_bytes(
            &self.transaction_id,
            &self.installation_id,
            self.profile,
            &self.runtime_state_roots_digest,
            self.expected_previous_revision,
            &self.confirmed_owner,
            &self.key_references,
            self.privacy_choice,
            &self.observed_effects,
            self.configuration_snapshot_ref.as_ref(),
            self.state,
            self.revision,
        )
    }

    /// Validates the complete binding projection.
    ///
    /// # Errors
    /// Returns [`InstallationError`] when any binding invariant fails.
    #[allow(
        clippy::too_many_lines,
        reason = "the complete setup binding invariant is intentionally audited in one boundary"
    )]
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.wire_version != SETUP_BINDING_WIRE_VERSION {
            return Err(InstallationError::MigrationRequired {
                reason: format!(
                    "setup binding wire {} cannot be read as {}",
                    self.wire_version, SETUP_BINDING_WIRE_VERSION
                ),
            });
        }
        handle(&self.transaction_id, "setup_binding.transaction_id")?;
        handle(&self.installation_id, "setup_binding.installation_id")?;
        runtime_sha256_handle(
            &self.runtime_state_roots_digest,
            "setup_binding.runtime_state_roots_digest",
        )?;
        handle(&self.confirmed_owner, "setup_binding.confirmed_owner")?;
        let completed = self.state.position() + 1;
        if self.observed_effects.len() != completed {
            return Err(InstallationError::IncompleteObservation(format!(
                "setup binding requires exactly {completed} observed effects, observed {}",
                self.observed_effects.len()
            )));
        }
        for (index, observation) in self.observed_effects.iter().enumerate() {
            observation.validate()?;
            let expected_milestone = SetupMilestone::all()[index];
            if observation.effect_id.as_str() != expected_milestone.effect_identity() {
                return Err(InstallationError::InvalidField {
                    field: format!("setup_binding.observed_effects[{index}].effect_id"),
                    reason: format!("must equal {}", expected_milestone.effect_identity()),
                });
            }
        }
        if self.state.position() >= SetupMilestone::ServiceKeysGenerated.position() {
            if self.key_references.is_empty() {
                return Err(InstallationError::IncompleteObservation(
                    "setup binding requires non-empty service key references".to_owned(),
                ));
            }
            for reference in &self.key_references {
                reference.validate()?;
            }
        }
        if self.state.position() >= SetupMilestone::PrivacyModeSelected.position()
            && self.privacy_choice.is_none()
        {
            return Err(InstallationError::IncompleteObservation(
                "setup binding requires the confirmed privacy mode selection".to_owned(),
            ));
        }
        match self.configuration_snapshot_ref.as_ref() {
            Some(snapshot_ref) if self.state == SetupMilestone::InitialSnapshotCreated => {
                runtime_sha256_handle(snapshot_ref, "setup_binding.configuration_snapshot_ref")?;
                let last = self.observed_effects.last().ok_or_else(|| {
                    InstallationError::IncompleteObservation(
                        "setup binding requires the initial snapshot observation".to_owned(),
                    )
                })?;
                if last.observed_digest.as_str() != snapshot_ref.as_str() {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            Some(_) => {
                return Err(InstallationError::IncompleteObservation(
                    "configuration snapshot reference cannot precede the initial snapshot milestone"
                        .to_owned(),
                ));
            }
            None => {}
        }
        if self.revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "setup_binding.revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        runtime_sha256_handle(&self.binding_digest, "setup_binding.binding_digest")?;
        if sha256_hex(&self.canonical_bytes()?) != self.binding_digest.as_str() {
            return Err(InstallationError::InvalidField {
                field: "setup_binding.binding_digest".to_owned(),
                reason: "setup binding digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

fn profile_ref(profile: InstallationProfile) -> Result<String, InstallationError> {
    let text = match profile {
        InstallationProfile::SystemService => "system_service",
        InstallationProfile::UserMode => "user_mode",
        InstallationProfile::PortableDev => "portable_dev",
    };
    if text.is_empty() {
        return Err(InstallationError::InvalidField {
            field: "setup_binding.profile".to_owned(),
            reason: "profile reference must be non-blank".to_owned(),
        });
    }
    Ok(text.to_owned())
}

/// Returns the canonical bytes whose digest is the binding digest. The wire
/// discriminator and the digest itself are envelope members, not content.
#[allow(clippy::too_many_arguments)]
fn canonical_binding_bytes(
    transaction_id: &PlatformHandle,
    installation_id: &PlatformHandle,
    profile: InstallationProfile,
    runtime_state_roots_digest: &PlatformHandle,
    expected_previous_revision: u64,
    confirmed_owner: &PlatformHandle,
    key_references: &[SetupKeyReference],
    privacy_choice: Option<PrivacyChoice>,
    observed_effects: &[SetupEffectObservation],
    configuration_snapshot_ref: Option<&PlatformHandle>,
    state: SetupMilestone,
    revision: u64,
) -> Result<Vec<u8>, InstallationError> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        transaction_id: &'a PlatformHandle,
        installation_id: &'a PlatformHandle,
        profile: InstallationProfile,
        runtime_state_roots_digest: &'a PlatformHandle,
        expected_previous_revision: u64,
        confirmed_owner: &'a PlatformHandle,
        key_references: &'a [SetupKeyReference],
        privacy_choice: Option<PrivacyChoice>,
        observed_effects: &'a [SetupEffectObservation],
        configuration_snapshot_ref: Option<&'a PlatformHandle>,
        state: SetupMilestone,
        revision: u64,
    }
    serde_json::to_vec(&Canonical {
        transaction_id,
        installation_id,
        profile,
        runtime_state_roots_digest,
        expected_previous_revision,
        confirmed_owner,
        key_references,
        privacy_choice,
        observed_effects,
        configuration_snapshot_ref,
        state,
        revision,
    })
    .map_err(|error| InstallationError::InvalidField {
        field: "setup_binding".to_owned(),
        reason: error.to_string(),
    })
}

/// Verifies a completed setup binding and its signed initial snapshot against
/// the trust anchor, producing the sealed admission result consumed by every
/// authority entrypoint.
///
/// The verifier's trusted key reference lives in
/// [`InitialConfigSnapshotTrustAnchor`], outside the untrusted snapshot. The
/// context values are observed from the binding itself, so a wrong-key,
/// modified snapshot, changed root, or stale revision refuses here rather
/// than admitting an agent.
///
/// Neither refusal is collapsed into a string: the durable binding's own typed
/// failure and the snapshot owner's typed failure are both preserved, and each
/// carries the exact recovery action.
///
/// # Errors
/// Returns [`SetupAdmissionError`] when the binding is incomplete, the
/// snapshot fails verification, or the bindings disagree.
pub fn verify_setup_binding(
    binding: &SetupBinding,
    snapshot: &SignedInitialConfigSnapshot,
    anchor: &InitialConfigSnapshotTrustAnchor,
) -> Result<VerifiedSetupBinding, SetupAdmissionError> {
    binding.require_complete()?;
    let context = InitialSnapshotVerificationContext {
        installation_id: binding.installation_id.as_str().to_owned(),
        profile_ref: profile_ref(binding.profile)?,
        runtime_state_roots_digest: binding.runtime_state_roots_digest.as_str().to_owned(),
        key_identity: binding.confirmed_owner.as_str().to_owned(),
        setup_revision: binding.revision,
    };
    let verified = anchor.verify(snapshot, &context)?;
    let snapshot_ref = binding.configuration_snapshot_ref.as_ref().ok_or_else(|| {
        InstallationError::IncompleteObservation(
            "setup binding is missing its final configuration reference".to_owned(),
        )
    })?;
    if snapshot_ref.as_str() != verified.envelope_digest() {
        return Err(SetupAdmissionError::Snapshot(
            InitialSnapshotError::BindingMismatch,
        ));
    }
    let snapshot_privacy = verified.payload().privacy_choice()?;
    if Some(snapshot_privacy) != binding.privacy_choice {
        return Err(SetupAdmissionError::Snapshot(
            InitialSnapshotError::BindingMismatch,
        ));
    }
    Ok(VerifiedSetupBinding::new(
        binding.installation_id.as_str().to_owned(),
        binding.profile,
        binding.runtime_state_roots_digest.clone(),
        binding.confirmed_owner.clone(),
        binding.privacy_choice.ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "setup binding requires the confirmed privacy mode selection".to_owned(),
            )
        })?,
        binding.key_references.clone(),
        snapshot_ref.clone(),
        binding.revision,
        verified.payload().snapshot_id.clone(),
    ))
}

/// Typed setup admission failure.
///
/// The durable binding owner's [`InstallationError`] and the configuration
/// owner's [`InitialSnapshotError`] are both preserved, so a wrong owner, key,
/// root or generation is never flattened into a generic code between layers.
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum SetupAdmissionError {
    /// The durable setup binding is incomplete, stale or internally invalid.
    #[error(
        "setup binding is not admitted: {0}; recovery: resume the same installation transaction and complete its recorded milestone before admitting an agent"
    )]
    Binding(#[from] InstallationError),
    /// The signed initial configuration snapshot is not admitted.
    #[error("signed initial configuration snapshot is not admitted: {0}")]
    Snapshot(#[from] InitialSnapshotError),
}

/// Sealed, trust-anchor-verified setup binding admitted for authority entry.
///
/// Every authority entrypoint (Kernel/Host admission, daemon/worker dispatch,
/// restart) consumes this same verified binding. A defaults object or cold-
/// composition state cannot substitute for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSetupBinding {
    installation_id: String,
    profile: InstallationProfile,
    runtime_state_roots_digest: PlatformHandle,
    confirmed_owner: PlatformHandle,
    privacy_choice: PrivacyChoice,
    key_references: Vec<SetupKeyReference>,
    configuration_snapshot_ref: PlatformHandle,
    setup_revision: u64,
    snapshot_id: String,
}

impl VerifiedSetupBinding {
    #[allow(clippy::too_many_arguments)]
    fn new(
        installation_id: String,
        profile: InstallationProfile,
        runtime_state_roots_digest: PlatformHandle,
        confirmed_owner: PlatformHandle,
        privacy_choice: PrivacyChoice,
        key_references: Vec<SetupKeyReference>,
        configuration_snapshot_ref: PlatformHandle,
        setup_revision: u64,
        snapshot_id: String,
    ) -> Self {
        Self {
            installation_id,
            profile,
            runtime_state_roots_digest,
            confirmed_owner,
            privacy_choice,
            key_references,
            configuration_snapshot_ref,
            setup_revision,
            snapshot_id,
        }
    }

    /// Returns the verified installation identity.
    #[must_use]
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Returns the verified profile.
    #[must_use]
    pub const fn profile(&self) -> InstallationProfile {
        self.profile
    }

    /// Returns the verified runtime state roots digest.
    #[must_use]
    pub const fn runtime_state_roots_digest(&self) -> &PlatformHandle {
        &self.runtime_state_roots_digest
    }

    /// Returns the verified confirmed owner.
    #[must_use]
    pub const fn confirmed_owner(&self) -> &PlatformHandle {
        &self.confirmed_owner
    }

    /// Returns the verified privacy mode selection.
    #[must_use]
    pub const fn privacy_choice(&self) -> PrivacyChoice {
        self.privacy_choice
    }

    /// Returns the verified non-secret key references.
    #[must_use]
    pub fn key_references(&self) -> &[SetupKeyReference] {
        &self.key_references
    }

    /// Returns the verified final configuration snapshot reference.
    #[must_use]
    pub const fn configuration_snapshot_ref(&self) -> &PlatformHandle {
        &self.configuration_snapshot_ref
    }

    /// Returns the verified setup binding revision.
    #[must_use]
    pub const fn setup_revision(&self) -> u64 {
        self.setup_revision
    }

    /// Returns the verified initial snapshot identity.
    #[must_use]
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
}

/// Validates canonical setup binding JSON without exposing a deserialized
/// binding object to another crate.
pub fn validate_setup_binding_json(bytes: &[u8]) -> Result<(), InstallationError> {
    decode_setup_binding_json(bytes).map(|_| ())
}

/// Decodes canonical setup binding JSON for installation-internal callers.
pub(crate) fn decode_setup_binding_json(bytes: &[u8]) -> Result<SetupBinding, InstallationError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    let version =
        value
            .get("wire_version")
            .ok_or_else(|| InstallationError::MigrationRequired {
                reason: "setup binding envelope predates the required wire discriminator"
                    .to_owned(),
            })?;
    let version: ContractVersion = serde_json::from_value(version.clone()).map_err(|_| {
        InstallationError::MigrationRequired {
            reason: "setup binding envelope has an unsupported wire discriminator".to_owned(),
        }
    })?;
    if version != SETUP_BINDING_WIRE_VERSION {
        return Err(InstallationError::MigrationRequired {
            reason: format!(
                "setup binding envelope wire {version} requires explicit migration to {SETUP_BINDING_WIRE_VERSION}"
            ),
        });
    }
    let envelope: SetupBindingEnvelope =
        serde_json::from_value(value).map_err(|error| InstallationError::CorruptRegistry {
            reason: error.to_string(),
        })?;
    if envelope.wire_version != SETUP_BINDING_WIRE_VERSION {
        return Err(InstallationError::MigrationRequired {
            reason: format!(
                "setup binding envelope wire {} requires explicit migration to {}",
                envelope.wire_version, SETUP_BINDING_WIRE_VERSION
            ),
        });
    }
    envelope.binding.validate()?;
    Ok(envelope.binding)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBindingEnvelope {
    wire_version: ContractVersion,
    binding: SetupBinding,
}
