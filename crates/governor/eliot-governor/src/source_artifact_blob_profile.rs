//! Request-bound source-artifact Blob policy projected from the recovered
//! canonical `PolicyOwner` snapshot.
//!
//! The projection is intentionally opaque and non-Serde. It is issued only
//! from the retained policy readback, preserves its owner/revision/digests,
//! and records the exact Governor admission for which it was read. Callers
//! cannot turn a policy label or a copied domain list into Blob authority.

use eliot_authority::PrincipalRef;
use eliot_contracts::StateFence;
use eliot_protocol::RequestIdentity;
use eliot_receipts::{
    EffectClass, OperationBinding, RequestBinding, SessionBinding, TaskBinding, WorkScopeBinding,
};
use eliot_security_contracts::{EffectCeiling, InstructionTaint, PrivacyClass};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{PolicyOwner, SourceArtifactAdmission};

/// Policy-owned configuration key names used to project one source-artifact
/// Blob profile from the existing canonical Policy snapshot.
///
/// These spellings select the I5.12 policy fields; their values must be
/// explicitly present in the recovered owner snapshot. No domain or policy
/// value is inferred from an admission or supplied as a default here.
pub const SOURCE_ARTIFACT_BLOB_SCOPE_DOMAIN_SETTING: &str = "source_artifact.blob.scope_domain_id";
pub const SOURCE_ARTIFACT_BLOB_ACCESS_DOMAIN_SETTING: &str =
    "source_artifact.blob.access_domain_id";
pub const SOURCE_ARTIFACT_BLOB_CONFIDENTIALITY_DOMAIN_SETTING: &str =
    "source_artifact.blob.confidentiality_domain_id";
pub const SOURCE_ARTIFACT_BLOB_ENCRYPTION_KEY_DOMAIN_SETTING: &str =
    "source_artifact.blob.encryption_key_domain_id";
pub const SOURCE_ARTIFACT_BLOB_RETENTION_DOMAIN_SETTING: &str =
    "source_artifact.blob.retention_domain_id";
pub const SOURCE_ARTIFACT_BLOB_ERASURE_DOMAIN_SETTING: &str =
    "source_artifact.blob.erasure_domain_id";
pub const SOURCE_ARTIFACT_BLOB_PRIVACY_CLASS_SETTING: &str = "source_artifact.blob.privacy_class";
pub const SOURCE_ARTIFACT_BLOB_RETENTION_CLASS_SETTING: &str =
    "source_artifact.blob.retention_class";
pub const SOURCE_ARTIFACT_BLOB_INSTRUCTION_TAINT_SETTING: &str =
    "source_artifact.blob.instruction_taint";
pub const SOURCE_ARTIFACT_BLOB_EFFECT_CEILING_SETTING: &str = "source_artifact.blob.effect_ceiling";

/// Retention classes accepted from the recovered, human-owned source policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceArtifactRetentionClass {
    /// Retain only for the current authenticated session.
    Session,
    /// Retain for the exact admitted task.
    Task,
    /// Retain under the policy owner's durable schedule.
    Durable,
    /// Retain under an explicit legal hold.
    LegalHold,
}

/// Typed semantic policy fields projected for the Blob storage owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceArtifactBlobPolicy {
    privacy_class: PrivacyClass,
    retention_class: SourceArtifactRetentionClass,
    policy_ref: String,
    instruction_taint: InstructionTaint,
    effect_ceiling: EffectCeiling,
}

impl SourceArtifactBlobPolicy {
    /// Explicit policy privacy class.
    #[must_use]
    pub const fn privacy_class(&self) -> PrivacyClass {
        self.privacy_class
    }

    /// Explicit policy retention class.
    #[must_use]
    pub const fn retention_class(&self) -> SourceArtifactRetentionClass {
        self.retention_class
    }

    /// Exact owner snapshot identity used as the Blob policy reference.
    #[must_use]
    pub fn policy_ref(&self) -> &str {
        &self.policy_ref
    }

    /// Explicit policy instruction/data taint.
    #[must_use]
    pub const fn instruction_taint(&self) -> InstructionTaint {
        self.instruction_taint
    }

    /// Explicit policy effect ceiling.
    #[must_use]
    pub const fn effect_ceiling(&self) -> EffectCeiling {
        self.effect_ceiling
    }
}

/// Six explicit residency identities retained from the Policy owner's exact
/// snapshot. Blob derives the content digest from the exact bytes it stages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceArtifactResidencyDomains {
    scope: String,
    access: String,
    confidentiality: String,
    encryption_key: String,
    retention: String,
    erasure: String,
}

impl SourceArtifactResidencyDomains {
    /// Explicit scope domain identity.
    #[must_use]
    pub fn scope_domain_id(&self) -> &str {
        &self.scope
    }

    /// Explicit access domain identity.
    #[must_use]
    pub fn access_domain_id(&self) -> &str {
        &self.access
    }

    /// Explicit confidentiality domain identity.
    #[must_use]
    pub fn confidentiality_domain_id(&self) -> &str {
        &self.confidentiality
    }

    /// Explicit encryption-key domain identity.
    #[must_use]
    pub fn encryption_key_domain_id(&self) -> &str {
        &self.encryption_key
    }

    /// Explicit retention domain identity.
    #[must_use]
    pub fn retention_domain_id(&self) -> &str {
        &self.retention
    }

    /// Explicit erasure domain identity.
    #[must_use]
    pub fn erasure_domain_id(&self) -> &str {
        &self.erasure
    }
}

/// A non-transferable Blob profile issued by a recovered `PolicyOwner` for
/// one exact live source-artifact admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceArtifactBlobProfile {
    policy: SourceArtifactBlobPolicy,
    residency_domains: SourceArtifactResidencyDomains,
    owner_ref: String,
    policy_snapshot_id: String,
    policy_revision: u64,
    policy_snapshot_digest: String,
    policy_readback_digest: String,
    state_fence: StateFence,
    holder: PrincipalRef,
    work_scope: WorkScopeBinding,
    task: TaskBinding,
    session: SessionBinding,
    request: RequestBinding,
    request_identity: RequestIdentity,
    operation: OperationBinding,
    reservation_id: Option<eliot_ors::OperationIdentity>,
}

impl SourceArtifactBlobProfile {
    /// Projects source-artifact policy from this exact recovered Policy
    /// readback. Every setting must be explicitly present and carry the
    /// snapshot's original policy owner identity.
    pub fn issue_for(
        policy_owner: &PolicyOwner,
        admission: &SourceArtifactAdmission,
    ) -> Result<Self, SourceArtifactBlobProfileError> {
        let snapshot = policy_owner.snapshot();
        snapshot
            .validate()
            .map_err(SourceArtifactBlobProfileError::InvalidPolicySnapshot)?;
        if policy_owner.state_fence() != &admission.work_scope().state_fence
            || snapshot.state_fence != admission.work_scope().state_fence
            || snapshot.scope_id != admission.work_scope().scope_id.as_str()
            || snapshot.revision.value() != policy_owner.revision()
            || snapshot.policy_fence.state_fence != admission.work_scope().state_fence
            || snapshot.policy_fence.policy_snapshot_id != snapshot.snapshot_id
        {
            return Err(SourceArtifactBlobProfileError::PolicyBindingMismatch);
        }

        let expected_owner = snapshot.policy_owner.owner_ref.as_str();
        let setting = |key: &'static str| -> Result<&str, SourceArtifactBlobProfileError> {
            let item = snapshot
                .settings
                .iter()
                .find(|setting| setting.key == key)
                .ok_or(SourceArtifactBlobProfileError::Unconfigured { setting_key: key })?;
            if item.owner_ref != expected_owner {
                return Err(SourceArtifactBlobProfileError::SettingOwnerMismatch {
                    setting_key: key,
                });
            }
            Ok(item.value_ref.as_str())
        };
        let domain = |key| -> Result<String, SourceArtifactBlobProfileError> {
            let value = setting(key)?;
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(SourceArtifactBlobProfileError::InvalidSetting { setting_key: key });
            }
            Ok(value.to_owned())
        };
        let parse =
            |key: &'static str| -> Result<serde_json::Value, SourceArtifactBlobProfileError> {
                let value = setting(key)?;
                if value.trim().is_empty() || value.chars().any(char::is_control) {
                    return Err(SourceArtifactBlobProfileError::InvalidSetting {
                        setting_key: key,
                    });
                }
                Ok(serde_json::Value::String(value.to_owned()))
            };

        let policy = SourceArtifactBlobPolicy {
            privacy_class: serde_json::from_value(parse(
                SOURCE_ARTIFACT_BLOB_PRIVACY_CLASS_SETTING,
            )?)
            .map_err(|_| SourceArtifactBlobProfileError::InvalidSetting {
                setting_key: SOURCE_ARTIFACT_BLOB_PRIVACY_CLASS_SETTING,
            })?,
            retention_class: serde_json::from_value(parse(
                SOURCE_ARTIFACT_BLOB_RETENTION_CLASS_SETTING,
            )?)
            .map_err(|_| SourceArtifactBlobProfileError::InvalidSetting {
                setting_key: SOURCE_ARTIFACT_BLOB_RETENTION_CLASS_SETTING,
            })?,
            policy_ref: snapshot.snapshot_id.clone(),
            instruction_taint: serde_json::from_value(parse(
                SOURCE_ARTIFACT_BLOB_INSTRUCTION_TAINT_SETTING,
            )?)
            .map_err(|_| SourceArtifactBlobProfileError::InvalidSetting {
                setting_key: SOURCE_ARTIFACT_BLOB_INSTRUCTION_TAINT_SETTING,
            })?,
            effect_ceiling: serde_json::from_value(parse(
                SOURCE_ARTIFACT_BLOB_EFFECT_CEILING_SETTING,
            )?)
            .map_err(|_| SourceArtifactBlobProfileError::InvalidSetting {
                setting_key: SOURCE_ARTIFACT_BLOB_EFFECT_CEILING_SETTING,
            })?,
        };
        let residency_domains = SourceArtifactResidencyDomains {
            scope: domain(SOURCE_ARTIFACT_BLOB_SCOPE_DOMAIN_SETTING)?,
            access: domain(SOURCE_ARTIFACT_BLOB_ACCESS_DOMAIN_SETTING)?,
            confidentiality: domain(SOURCE_ARTIFACT_BLOB_CONFIDENTIALITY_DOMAIN_SETTING)?,
            encryption_key: domain(SOURCE_ARTIFACT_BLOB_ENCRYPTION_KEY_DOMAIN_SETTING)?,
            retention: domain(SOURCE_ARTIFACT_BLOB_RETENTION_DOMAIN_SETTING)?,
            erasure: domain(SOURCE_ARTIFACT_BLOB_ERASURE_DOMAIN_SETTING)?,
        };
        let profile = Self {
            policy,
            residency_domains,
            owner_ref: snapshot.policy_owner.owner_ref.clone(),
            policy_snapshot_id: snapshot.snapshot_id.clone(),
            policy_revision: policy_owner.revision(),
            policy_snapshot_digest: policy_owner.snapshot_digest().to_owned(),
            policy_readback_digest: policy_owner.canonical_digest().to_owned(),
            state_fence: policy_owner.state_fence().clone(),
            holder: admission.holder().clone(),
            work_scope: admission.work_scope().clone(),
            task: admission.task().clone(),
            session: admission.session().clone(),
            request: admission.request().clone(),
            request_identity: admission.request_identity().clone(),
            operation: admission.operation().clone(),
            reservation_id: admission.reservation_id().cloned(),
        };
        profile.validate_admission_binding(admission)?;
        Ok(profile)
    }

    /// Typed policy inputs for the storage owner.
    #[must_use]
    pub const fn policy(&self) -> &SourceArtifactBlobPolicy {
        &self.policy
    }

    /// Six explicit residency domains for the storage owner.
    #[must_use]
    pub const fn residency_domains(&self) -> &SourceArtifactResidencyDomains {
        &self.residency_domains
    }

    /// Original human policy owner identity.
    #[must_use]
    pub fn owner_ref(&self) -> &str {
        &self.owner_ref
    }

    /// Exact admitted Policy snapshot id.
    #[must_use]
    pub fn policy_snapshot_id(&self) -> &str {
        &self.policy_snapshot_id
    }

    /// Exact durable Policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }

    /// Digest of the admitted canonical Policy snapshot content.
    #[must_use]
    pub fn policy_snapshot_digest(&self) -> &str {
        &self.policy_snapshot_digest
    }

    /// Digest of the original Kernel-served Policy owner readback bytes.
    #[must_use]
    pub fn policy_readback_digest(&self) -> &str {
        &self.policy_readback_digest
    }

    /// Exact State Fence at which the Policy snapshot was admitted.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Rechecks that this policy projection is being consumed beside the
    /// exact admission it was issued for, under the current key lineage and
    /// generation observed by the Blob storage owner.
    pub fn validate_for(
        &self,
        admission: &SourceArtifactAdmission,
        active_key_lineage: &str,
        active_key_generation: u64,
    ) -> Result<(), SourceArtifactBlobProfileError> {
        self.validate_admission_binding(admission)?;
        if active_key_lineage.trim().is_empty()
            || self.residency_domains.encryption_key != active_key_lineage
        {
            return Err(SourceArtifactBlobProfileError::KeyLineageMismatch);
        }
        if active_key_generation == 0
            || active_key_generation
                != admission
                    .work_scope()
                    .state_fence
                    .resource_generation
                    .value()
        {
            return Err(SourceArtifactBlobProfileError::KeyGenerationMismatch);
        }
        Ok(())
    }

    fn validate_admission_binding(
        &self,
        admission: &SourceArtifactAdmission,
    ) -> Result<(), SourceArtifactBlobProfileError> {
        let binding_matches = self.holder == *admission.holder()
            && self.work_scope == *admission.work_scope()
            && self.task == *admission.task()
            && self.session == *admission.session()
            && self.request == *admission.request()
            && self.request_identity == *admission.request_identity()
            && self.operation == *admission.operation()
            && self.reservation_id.as_ref() == admission.reservation_id()
            && self.state_fence == admission.work_scope().state_fence;
        let reservation_matches_effect = match admission.operation().effect {
            EffectClass::Read => self.reservation_id.is_none(),
            EffectClass::ReversibleMutation => self.reservation_id.is_some(),
            _ => false,
        };
        if !binding_matches || !reservation_matches_effect {
            return Err(SourceArtifactBlobProfileError::AdmissionMismatch);
        }
        if self.residency_domains.scope != admission.work_scope().scope_id.as_str() {
            return Err(SourceArtifactBlobProfileError::ScopeDomainMismatch);
        }
        Ok(())
    }
}

/// Typed failures while deriving or consuming the owner-issued Blob profile.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SourceArtifactBlobProfileError {
    /// A required source-artifact policy key is absent from the current owner snapshot.
    #[error("source-artifact policy is unconfigured: {setting_key}")]
    Unconfigured { setting_key: &'static str },
    /// A setting was written by an owner other than the exact Policy owner.
    #[error("source-artifact setting has a foreign owner: {setting_key}")]
    SettingOwnerMismatch { setting_key: &'static str },
    /// A configured field is blank, malformed, or not a recognized typed policy value.
    #[error("source-artifact setting is invalid: {setting_key}")]
    InvalidSetting { setting_key: &'static str },
    /// The retained Policy snapshot failed its own owner validation.
    #[error("retained source-artifact Policy snapshot is invalid: {0}")]
    InvalidPolicySnapshot(#[source] eliot_config::ConfigError),
    /// Policy owner snapshot does not match this exact admitted `WorkScope`/fence/revision.
    #[error("source-artifact Policy snapshot does not bind the admitted WorkScope and fence")]
    PolicyBindingMismatch,
    /// Profile was presented with an admission other than its original one.
    #[error("source-artifact profile does not bind this exact Governor admission")]
    AdmissionMismatch,
    /// The configured scope domain is not the admitted `WorkScope` identity.
    #[error("source-artifact scope domain differs from the admitted WorkScope")]
    ScopeDomainMismatch,
    /// The configured encryption domain does not match the live key lineage.
    #[error("source-artifact encryption-key domain differs from the active Blob key lineage")]
    KeyLineageMismatch,
    /// The current key generation is absent or differs from the admitted State Fence generation.
    #[error("source-artifact Blob key generation differs from the admitted State Fence")]
    KeyGenerationMismatch,
}

impl PolicyOwner {
    /// Issues source-artifact Blob policy from the exact recovered Policy
    /// snapshot and binds it to one original Governor admission.
    pub fn source_artifact_blob_profile(
        &self,
        admission: &SourceArtifactAdmission,
    ) -> Result<SourceArtifactBlobProfile, SourceArtifactBlobProfileError> {
        SourceArtifactBlobProfile::issue_for(self, admission)
    }
}
