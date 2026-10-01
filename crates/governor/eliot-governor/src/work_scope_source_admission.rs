//! Initial WorkScope source admission and canonical snapshot preparation.
//!
//! This module joins a verified signed source approval, an exact-root
//! discovery lease, live Bootstrap source capture, initial WorkScope binding
//! admission, and a fresh WorkScope-owner CAS expectation. It does not resolve
//! a scope, infer an observed workspace, sign user approval, or install a
//! Store row. Those facts come from their respective owners and the owning
//! daemon ingress.

use std::collections::BTreeMap;
use std::path::Path;

use crate::composition::WorkScopeOwnerSnapshotReadback;
use eliot_bootstrap::capture::NormativePairSourceCapture;
use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{ProductId, SourceId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{AuthorityBinding, CausalBinding};
use eliot_security_contracts::{
    CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
    InstructionTaint, IntegrityStatus, QuarantineState, SourceAssurance,
};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationId, ScopeId, SecurityContext, TransitionClass, generated_operation_manifests,
    operation_manifest_set_digest, supported_admission_contract_set_digest,
};
use eliot_workscope::{
    AuthorityBasis, DiscoveryLeaseKey, DiscoveryLeaseRequest, DiscoveryRead, DiscoveryReadLease,
    GoverningSourceAdmission, GoverningSourceCandidate, GoverningSourceRole, GoverningSourceSet,
    NewSourceCandidate, ObservedScopeResources, PrivacyProfile, ScopeBinding, ScopeIdentity,
    SourceAdmissionRequest, SourceCoverage, WorkScopeBindingOwner, WorkScopeBindingSnapshot,
    WorkScopeDescriptor, admit_governing_sources, admit_initial_binding, issue_discovery_lease,
    observed_scope_binding,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Wire/schema revision for the Human-approved normative source closure.
pub const GOVERNING_SOURCE_APPROVAL_SCHEMA: &str = "eliot.governing-source-approval.v1";

/// Closed initial setup effects that a Human explicitly consents to before
/// the existing installation signer signs the setup approval. This list is
/// deliberately narrow: it authorizes the first Policy owner write, the
/// first WorkScope source-admission write, and the exact-root discovery needed
/// to validate that source admission. It does not authorize TaskD dispatch or
/// any external effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InitialSetupEffect {
    /// Create the first canonical Policy owner snapshot from the signed setup
    /// payload after an independent physical-absence read.
    CreatePolicyOwnerSnapshot,
    /// Admit one initial WorkScope source pair under the signed policy.
    AdmitInitialWorkScopeSources,
    /// Read only the exact approved repository root for source validation.
    DiscoverApprovedSourceRoot,
}

/// Explicit, signed consent for the exact one-time bootstrap effects required
/// to install policy and establish the first WorkScope binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InitialSetupMutationConsent {
    /// Closed consent schema revision.
    pub schema_version: String,
    /// Exact closed effect set required for initial configuration. Ordering is
    /// canonical and duplicates or omissions are rejected.
    pub effects: Vec<InitialSetupEffect>,
}

impl InitialSetupMutationConsent {
    /// Constructs the exact effect set only after the caller has collected an
    /// affirmative Human confirmation in the trusted setup interaction.
    pub fn from_explicit_confirmation(confirmed: bool) -> Result<Self, WorkScopeSourceAdmissionError> {
        if !confirmed {
            return Err(WorkScopeSourceAdmissionError::InitialSetupConsentMissing);
        }
        let consent = Self {
            schema_version: "eliot.initial-setup-mutation-consent.v1".to_owned(),
            effects: vec![
                InitialSetupEffect::CreatePolicyOwnerSnapshot,
                InitialSetupEffect::AdmitInitialWorkScopeSources,
                InitialSetupEffect::DiscoverApprovedSourceRoot,
            ],
        };
        consent.validate()?;
        Ok(consent)
    }

    /// Refuses any broadened, partial, reordered, or legacy consent.
    pub fn validate(&self) -> Result<(), WorkScopeSourceAdmissionError> {
        if self.schema_version != "eliot.initial-setup-mutation-consent.v1"
            || self.effects
                != [
                    InitialSetupEffect::CreatePolicyOwnerSnapshot,
                    InitialSetupEffect::AdmitInitialWorkScopeSources,
                    InitialSetupEffect::DiscoverApprovedSourceRoot,
                ]
        {
            return Err(WorkScopeSourceAdmissionError::InitialSetupConsentMissing);
        }
        Ok(())
    }
}

/// The exact source document approved for one governing normative role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovedNormativeSource {
    /// Exact source manifest path from the accepted pair receipt.
    pub source_ref: String,
    /// Exact entry document path from the accepted pair receipt.
    pub entry_ref: String,
    /// Exact compatibility map path from the accepted pair receipt.
    pub compatibility_ref: String,
    /// SHA-256 of the reconstructed normalized source bytes.
    pub content_sha256: String,
    /// Explicitly approved privacy classification for this source.
    pub privacy_class: eliot_security_contracts::PrivacyClass,
}

/// Explicit first-run Human approval of the exact normative source pair.
///
/// This record is only authority-bearing after it is included in the signed
/// initial configuration payload and read back through that payload's
/// existing verifier. It is not an approval signature or an identity
/// assertion by itself. Its source rows are checked against a fresh
/// `NormativePairSourceCapture` at the WorkScope admission boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GoverningSourceApproval {
    /// Closed approval schema revision.
    pub schema_version: String,
    /// Authenticated Human principal that explicitly approved this closure.
    pub approver_principal_ref: String,
    /// Product identity covered by the approval.
    pub product_id: ProductId,
    /// Source identity covered by the approval.
    pub source_id: SourceId,
    /// Canonical explicit repository root identity covered by the approval.
    pub explicit_root_identity: String,
    /// Exact state fence at which the approval was signed.
    pub state_fence: StateFence,
    /// Explicitly approved WorkScope privacy boundary.
    pub privacy: PrivacyProfile,
    /// Explicitly approved privacy class for the WorkScope binding itself.
    pub scope_privacy_class: eliot_security_contracts::PrivacyClass,
    /// Accepted pair key from `docs/normative-pair.toml`.
    pub pair_key: String,
    /// Approved Architecture document identity and classification.
    pub architecture: ApprovedNormativeSource,
    /// Approved Implementation document identity and classification.
    pub implementation: ApprovedNormativeSource,
    /// Human-confirmed initial setup effects, covered by the same existing
    /// InitialSnapshotSigner signature as this source approval.
    pub initial_setup_consent: InitialSetupMutationConsent,
}

impl GoverningSourceApproval {
    /// Construct the value presented for Human confirmation during setup.
    ///
    /// Callers must obtain `approver_principal_ref`, product/source, root and
    /// privacy selections from the authenticated setup interaction. The
    /// returned value has no authority until the existing trusted
    /// `InitialSnapshotSigner` signs it as part of the initial config payload.
    pub fn from_setup_confirmation(
        approver_principal_ref: impl Into<String>,
        product_id: ProductId,
        source_id: SourceId,
        explicit_root_identity: impl Into<String>,
        state_fence: StateFence,
        privacy: PrivacyProfile,
        scope_privacy_class: eliot_security_contracts::PrivacyClass,
        architecture_privacy: eliot_security_contracts::PrivacyClass,
        implementation_privacy: eliot_security_contracts::PrivacyClass,
        initial_setup_consent: InitialSetupMutationConsent,
        capture: &NormativePairSourceCapture,
    ) -> Result<Self, WorkScopeSourceAdmissionError> {
        let approval = Self {
            schema_version: GOVERNING_SOURCE_APPROVAL_SCHEMA.to_owned(),
            approver_principal_ref: approver_principal_ref.into(),
            product_id,
            source_id,
            explicit_root_identity: explicit_root_identity.into(),
            state_fence,
            privacy,
            scope_privacy_class,
            pair_key: capture.receipt.pair_key.clone(),
            architecture: ApprovedNormativeSource {
                source_ref: capture.architecture.source_ref.clone(),
                entry_ref: capture.architecture.entry_ref.clone(),
                compatibility_ref: capture.architecture.compatibility_ref.clone(),
                content_sha256: capture.architecture.content_sha256.clone(),
                privacy_class: architecture_privacy,
            },
            implementation: ApprovedNormativeSource {
                source_ref: capture.implementation.source_ref.clone(),
                entry_ref: capture.implementation.entry_ref.clone(),
                compatibility_ref: capture.implementation.compatibility_ref.clone(),
                content_sha256: capture.implementation.content_sha256.clone(),
                privacy_class: implementation_privacy,
            },
            initial_setup_consent,
        };
        approval.validate()?;
        Ok(approval)
    }

    /// Validate the complete signed approval's structure.
    pub fn validate(&self) -> Result<(), WorkScopeSourceAdmissionError> {
        if self.schema_version != GOVERNING_SOURCE_APPROVAL_SCHEMA
            || self.approver_principal_ref.trim().is_empty()
            || self.approver_principal_ref.chars().any(char::is_control)
            || self.explicit_root_identity.trim().is_empty()
            || self.explicit_root_identity.chars().any(char::is_control)
            || !Path::new(&self.explicit_root_identity).is_absolute()
            || self.pair_key.trim().is_empty()
            || self.pair_key.chars().any(char::is_control)
        {
            return Err(WorkScopeSourceAdmissionError::InvalidSourceApproval);
        }
        self.state_fence
            .validate()
            .map_err(|_| WorkScopeSourceAdmissionError::InvalidSourceApproval)?;
        self.initial_setup_consent.validate()?;
        self.privacy
            .validate()
            .map_err(|_| WorkScopeSourceAdmissionError::InvalidSourceApproval)?;
        if !self.privacy.admits(self.scope_privacy_class) {
            return Err(WorkScopeSourceAdmissionError::InvalidSourceApproval);
        }
        validate_approved_document(&self.architecture)?;
        validate_approved_document(&self.implementation)?;
        if self.architecture.source_ref == self.implementation.source_ref
            || !self.privacy.admits(self.architecture.privacy_class)
            || !self.privacy.admits(self.implementation.privacy_class)
        {
            return Err(WorkScopeSourceAdmissionError::InvalidSourceApproval);
        }
        Ok(())
    }

    /// Re-join this signed approval to the exact live setup and source inputs.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_live_binding(
        &self,
        capture: &NormativePairSourceCapture,
        explicit_root_identity: &str,
        product_id: &ProductId,
        source_id: &SourceId,
        privacy: &PrivacyProfile,
        scope_privacy_class: eliot_security_contracts::PrivacyClass,
        state_fence: &StateFence,
        authenticated_approver_principal_ref: &str,
    ) -> Result<(), WorkScopeSourceAdmissionError> {
        self.validate_live_context(
            explicit_root_identity,
            product_id,
            source_id,
            privacy,
            scope_privacy_class,
            state_fence,
            authenticated_approver_principal_ref,
        )?;
        let architecture_matches = self.architecture.source_ref == capture.architecture.source_ref
            && self.architecture.entry_ref == capture.architecture.entry_ref
            && self.architecture.compatibility_ref == capture.architecture.compatibility_ref
            && self.architecture.content_sha256 == capture.architecture.content_sha256;
        let implementation_matches = self.implementation.source_ref
            == capture.implementation.source_ref
            && self.implementation.entry_ref == capture.implementation.entry_ref
            && self.implementation.compatibility_ref == capture.implementation.compatibility_ref
            && self.implementation.content_sha256 == capture.implementation.content_sha256;
        if self.pair_key != capture.receipt.pair_key
            || !architecture_matches
            || !implementation_matches
            || self.architecture.content_sha256 != capture.receipt.pair.architecture_sha256
            || self.implementation.content_sha256 != capture.receipt.pair.implementation_sha256
            || self.explicit_root_identity != explicit_root_identity
            || &self.product_id != product_id
            || &self.source_id != source_id
            || &self.privacy != privacy
            || self.scope_privacy_class != scope_privacy_class
            || &self.state_fence != state_fence
            || self.approver_principal_ref != authenticated_approver_principal_ref
        {
            return Err(WorkScopeSourceAdmissionError::SourceApprovalBindingMismatch);
        }
        Ok(())
    }

    /// Validate the signed setup approval against the admitted request before
    /// issuing the exact-root discovery lease. This deliberately does not read
    /// source bytes; those reads are legal only after the lease exists.
    #[allow(clippy::too_many_arguments)]
    fn validate_live_context(
        &self,
        explicit_root_identity: &str,
        product_id: &ProductId,
        source_id: &SourceId,
        privacy: &PrivacyProfile,
        scope_privacy_class: eliot_security_contracts::PrivacyClass,
        state_fence: &StateFence,
        authenticated_approver_principal_ref: &str,
    ) -> Result<(), WorkScopeSourceAdmissionError> {
        self.validate()?;
        if self.explicit_root_identity != explicit_root_identity
            || &self.product_id != product_id
            || &self.source_id != source_id
            || &self.privacy != privacy
            || self.scope_privacy_class != scope_privacy_class
            || &self.state_fence != state_fence
            || self.approver_principal_ref != authenticated_approver_principal_ref
        {
            return Err(WorkScopeSourceAdmissionError::SourceApprovalBindingMismatch);
        }
        Ok(())
    }

    /// Build candidate parameters for one approved role from the exact live
    /// capture. The returned claim is only a claim; admission is always
    /// resolved by `admit_governing_sources` against the signed Human owner.
    #[allow(clippy::too_many_arguments)]
    fn candidate_parameters(
        &self,
        capture: &NormativePairSourceCapture,
        state_fence: &StateFence,
        scope_ref: &str,
        generation: u64,
        document: &ApprovedNormativeSource,
        role: GoverningSourceRole,
    ) -> Result<NewSourceCandidate, WorkScopeSourceAdmissionError> {
        let captured = match role {
            GoverningSourceRole::Architecture => &capture.architecture,
            GoverningSourceRole::Implementation => &capture.implementation,
            _ => return Err(WorkScopeSourceAdmissionError::SourceApprovalBindingMismatch),
        };
        if captured.source_ref != document.source_ref
            || captured.content_sha256 != document.content_sha256
            || state_fence.resource_generation.value() != generation
        {
            return Err(WorkScopeSourceAdmissionError::SourceApprovalBindingMismatch);
        }
        Ok(NewSourceCandidate {
            source_ref: document.source_ref.clone(),
            digest: document.content_sha256.clone(),
            role,
            applicable_scope_ref: scope_ref.to_owned(),
            applicable_generation: generation,
            assurance: SourceAssurance {
                source_ref: document.source_ref.clone(),
                provenance_ref: format!("normative-pair:{}", capture.receipt.pair_key),
                integrity: IntegrityStatus::Verified,
                freshness: FreshnessStatus::Current,
                competence: CompetenceLevel::Unknown,
                independence: IndependenceLevel::Unknown,
                privacy_class: document.privacy_class,
                instruction_taint: InstructionTaint::DataOnly,
                allowed_epistemic_use: vec![EpistemicUse::Observation],
                allowed_effects: vec![EffectCeiling::NoExternalEffect],
                required_verifier: None,
                quarantine: QuarantineState::ReviewRequired,
                state_fence: state_fence.clone(),
            },
            domains: Vec::new(),
            claim: Some(AuthorityBasis::HumanOwner {
                owner_ref: self.approver_principal_ref.clone(),
            }),
        })
    }

    /// Issues a bounded, exact-root discovery lease and resolves the signed
    /// approval's source rows through `from_discovery_lease`. Authority still
    /// flows through WorkScope's ordinary Human-claim admission API.
    #[allow(clippy::too_many_arguments)]
    fn admit_signed_candidates_for_discovery(
        &self,
        capture: &NormativePairSourceCapture,
        lease: &eliot_workscope::DiscoveryReadLease,
        explicit_root_identity: &str,
        product_id: &ProductId,
        source_id: &SourceId,
        lease_key: &DiscoveryLeaseKey,
        privacy: &PrivacyProfile,
        scope_privacy_class: eliot_security_contracts::PrivacyClass,
        state_fence: &StateFence,
        authenticated_approver_principal_ref: &str,
        scope_ref: &str,
        generation: u64,
        now: u64,
        expires_at: u64,
    ) -> Result<GoverningSourceSet, WorkScopeSourceAdmissionError> {
        self.validate_live_binding(
            capture,
            explicit_root_identity,
            product_id,
            source_id,
            privacy,
            scope_privacy_class,
            state_fence,
            authenticated_approver_principal_ref,
        )?;
        if now > expires_at || expires_at == 0 {
            return Err(WorkScopeSourceAdmissionError::SourceAdmission(
                "source discovery lease is expired".to_owned(),
            ));
        }
        lease_key
            .validate()
            .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))?;
        if lease_key.root_filesystem_identity_ref != explicit_root_identity {
            return Err(WorkScopeSourceAdmissionError::SourceAdmission(
                "discovery lease root differs from the verified source root".to_owned(),
            ));
        }
        if !lease.key_matches(
            &lease_key.proposer_ref,
            &lease_key.session_ref,
            &lease_key.host_ref,
            &lease_key.root_filesystem_identity_ref,
        ) {
            return Err(WorkScopeSourceAdmissionError::SourceAdmission(
                "source discovery lease key does not match the authenticated setup".to_owned(),
            ));
        }
        let candidates = [
            (&self.architecture, GoverningSourceRole::Architecture),
            (&self.implementation, GoverningSourceRole::Implementation),
        ]
        .into_iter()
        .map(|(document, role)| {
            let params = self.candidate_parameters(
                capture,
                state_fence,
                scope_ref,
                generation,
                document,
                role,
            )?;
            GoverningSourceCandidate::from_discovery_lease(
                params,
                lease,
                explicit_root_identity,
                now,
            )
            .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
        admit_approved_candidates(
            candidates,
            scope_ref,
            generation,
            &self.approver_principal_ref,
            state_fence,
            now,
            expires_at,
            &self.architecture,
            &self.implementation,
        )
    }

    /// Resolve signed-approval candidates through a short-lived,
    /// exact-root discovery lease and WorkScope's ordinary admission API.
    #[allow(clippy::too_many_arguments)]
    fn derive_work_scope_sources(
        &self,
        capture: &NormativePairSourceCapture,
        lease: &eliot_workscope::DiscoveryReadLease,
        explicit_root_identity: &str,
        product_id: &ProductId,
        source_id: &SourceId,
        lease_key: &DiscoveryLeaseKey,
        privacy: &PrivacyProfile,
        scope_privacy_class: eliot_security_contracts::PrivacyClass,
        state_fence: &StateFence,
        authenticated_approver_principal_ref: &str,
        scope_ref: &str,
        generation: u64,
        now: u64,
        expires_at: u64,
    ) -> Result<GoverningSourceSet, WorkScopeSourceAdmissionError> {
        self.validate_live_binding(
            capture,
            explicit_root_identity,
            product_id,
            source_id,
            privacy,
            scope_privacy_class,
            state_fence,
            authenticated_approver_principal_ref,
        )?;
        self.admit_signed_candidates_for_discovery(
            capture,
            lease,
            explicit_root_identity,
            product_id,
            source_id,
            lease_key,
            privacy,
            scope_privacy_class,
            state_fence,
            authenticated_approver_principal_ref,
            scope_ref,
            generation,
            now,
            expires_at,
        )
    }

    /// Serialize this approval as canonical bytes for the existing signed
    /// InitialSnapshotPayload field.
    pub fn canonical_json(&self) -> Result<String, WorkScopeSourceAdmissionError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|error| {
            WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string())
        })?;
        String::from_utf8(bytes)
            .map_err(|error| WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string()))
    }

    /// Decode the approval only from the payload exposed by the sealed
    /// initial-config verifier. The Human principal must equal the owner
    /// principal already covered by that verified setup payload.
    pub fn from_verified_initial_snapshot(
        snapshot: &eliot_config::initial_snapshot::VerifiedInitialConfigSnapshot,
    ) -> Result<Self, WorkScopeSourceAdmissionError> {
        let payload = snapshot.payload();
        let approval_json = payload
            .governing_source_approval_json
            .as_deref()
            .ok_or(WorkScopeSourceAdmissionError::SourceApprovalMissing)?;
        let approval: Self = serde_json::from_str(approval_json).map_err(|error| {
            WorkScopeSourceAdmissionError::SourceApprovalEncoding(error.to_string())
        })?;
        approval.validate()?;
        if approval.approver_principal_ref != payload.owner_ref
            || approval.state_fence != payload.snapshot.state_fence
        {
            return Err(WorkScopeSourceAdmissionError::SourceApprovalBindingMismatch);
        }
        if approval.canonical_json()? != approval_json {
            return Err(WorkScopeSourceAdmissionError::SourceApprovalEncoding(
                "approval JSON is not canonical".to_owned(),
            ));
        }
        Ok(approval)
    }
}

fn validate_approved_document(
    document: &ApprovedNormativeSource,
) -> Result<(), WorkScopeSourceAdmissionError> {
    for value in [
        &document.source_ref,
        &document.entry_ref,
        &document.compatibility_ref,
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(WorkScopeSourceAdmissionError::InvalidSourceApproval);
        }
    }
    if !is_sha256(&document.content_sha256) {
        return Err(WorkScopeSourceAdmissionError::InvalidSourceApproval);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn admit_approved_candidates(
    candidates: Vec<GoverningSourceCandidate>,
    scope_ref: &str,
    generation: u64,
    required_owner_ref: &str,
    state_fence: &StateFence,
    now: u64,
    expires_at: u64,
    architecture: &ApprovedNormativeSource,
    implementation: &ApprovedNormativeSource,
) -> Result<GoverningSourceSet, WorkScopeSourceAdmissionError> {
    if candidates.len() != 2 || now > expires_at || expires_at == 0 {
        return Err(WorkScopeSourceAdmissionError::SourceAdmission(
            "source admission is incomplete or expired".to_owned(),
        ));
    }
    let admission = admit_governing_sources(SourceAdmissionRequest {
        scope_ref: scope_ref.to_owned(),
        generation,
        candidates,
        precedences: Vec::new(),
        required_owner_ref: required_owner_ref.to_owned(),
        proven_current_bindings: Vec::new(),
        proven_contracts: Vec::new(),
        absence_reason_ref: None,
        state_fence: state_fence.clone(),
        expires_at,
    })
    .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))?;
    admission
        .require_live(now)
        .and_then(|()| admission.require_admitted_authority())
        .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))?;
    require_exact_admitted_pair(
        &admission,
        required_owner_ref,
        generation,
        state_fence,
        architecture,
        implementation,
    )?;
    Ok(admission.admitted)
}

fn require_exact_admitted_pair(
    admission: &GoverningSourceAdmission,
    required_owner_ref: &str,
    generation: u64,
    state_fence: &StateFence,
    architecture: &ApprovedNormativeSource,
    implementation: &ApprovedNormativeSource,
) -> Result<(), WorkScopeSourceAdmissionError> {
    if admission.coverage != SourceCoverage::Complete
        || admission.conflict.is_some()
        || !admission.preserved.is_empty()
        || admission.admitted.sources.len() != 2
    {
        return Err(WorkScopeSourceAdmissionError::SourceAdmission(
            "both approved source roles must have complete, conflict-free admission".to_owned(),
        ));
    }
    let matches = |role, document: &ApprovedNormativeSource| {
        admission
            .admitted
            .sources
            .iter()
            .filter(|source| {
                source.role == role
                    && source.source_ref == document.source_ref
                    && source.digest == document.content_sha256
                    && source.applicable_generation == generation
                    && source.authority_basis
                        == Some(AuthorityBasis::HumanOwner {
                            owner_ref: required_owner_ref.to_owned(),
                        })
                    && source.assurance.source_ref == document.source_ref
                    && source.assurance.state_fence == *state_fence
                    && source.assurance.integrity == IntegrityStatus::Verified
                    && source.assurance.freshness == FreshnessStatus::Current
                    && source.assurance.privacy_class == document.privacy_class
                    && source.assurance.competence == CompetenceLevel::Unknown
                    && source.assurance.independence == IndependenceLevel::Unknown
                    && source.assurance.instruction_taint == InstructionTaint::DataOnly
                    && source.assurance.allowed_epistemic_use.len() == 1
                    && source.assurance.allowed_epistemic_use[0] == EpistemicUse::Observation
                    && source.assurance.allowed_effects.len() == 1
                    && source.assurance.allowed_effects[0] == EffectCeiling::NoExternalEffect
                    && source.assurance.quarantine == QuarantineState::ReviewRequired
            })
            .count()
            == 1
    };
    if !matches(GoverningSourceRole::Architecture, architecture)
        || !matches(GoverningSourceRole::Implementation, implementation)
    {
        return Err(WorkScopeSourceAdmissionError::SourceAdmission(
            "admitted source rows differ from the signed architecture/implementation pair"
                .to_owned(),
        ));
    }
    Ok(())
}

/// A source approval extracted from a trust-anchor-verified initial snapshot.
/// Its private fields prevent callers from promoting an unverified JSON value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGoverningSourceApproval {
    approval: GoverningSourceApproval,
    signed_snapshot_digest: String,
}

/// Non-serializable proof that the signed approval and exact request admitted
/// one bounded source-discovery read before source observation began.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialWorkScopeSourceDiscoveryLease {
    lease: DiscoveryReadLease,
    authenticated_approver_principal_ref: String,
    issued_at: u64,
}

/// Initial-bind authority and its exact committed Policy operation parent as
/// carried by the authenticated Kernel claim. The receipt is checked against
/// `causal` at the WorkScope producer boundary; it is never replaced with a
/// genesis value or an attempt-derived projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialWorkScopeAdmissionAuthority {
    pub authority: AuthorityBinding,
    pub causal: CausalBinding,
    pub policy_receipt: eliot_store_api::WriteReceipt,
}

impl InitialWorkScopeAdmissionAuthority {
    fn validate_for(&self, fence: &StateFence) -> Result<(), WorkScopeSourceAdmissionError> {
        self.policy_receipt
            .validate()
            .map_err(|_| WorkScopeSourceAdmissionError::PolicyReceiptMismatch)?;
        let receipt = self
            .policy_receipt
            .envelope
            .as_ref()
            .ok_or(WorkScopeSourceAdmissionError::PolicyReceiptMismatch)?;
        let policy_causal = &receipt.core.causal;
        let parent = &receipt.identity.receipt_id;
        let expected_sequence = policy_causal
            .transaction_sequence
            .value()
            .checked_add(1)
            .ok_or(WorkScopeSourceAdmissionError::PolicyReceiptMismatch)?;
        if self.policy_receipt.status != eliot_store_api::WriteReceiptStatus::Committed
            || self.policy_receipt.state_fence != *fence
            || policy_causal.state_fence != *fence
            || self.causal.state_fence != *fence
            || self.causal.transaction_sequence.value() != expected_sequence
            || self.causal.parent_receipt_id.as_ref() != Some(parent)
            || self.causal.predecessor_receipt_ids.as_slice() != [parent]
            || self.authority.state_fence != *fence
            || !fence
                .authority_epoch
                .is_same_authority(&self.authority.authority_epoch)
            || !eliot_store_api::effect_is_at_most(
                EffectClass::ReversibleMutation,
                self.authority.allowed_effect,
            )
        {
            return Err(WorkScopeSourceAdmissionError::PolicyReceiptMismatch);
        }
        Ok(())
    }
}

/// Issues the exact-root, one-read discovery lease before the Bootstrap
/// parser opens governing-source bytes.
pub fn issue_initial_work_scope_source_discovery_lease(
    identity: &RequestIdentity,
    approval: &VerifiedGoverningSourceApproval,
    explicit_root_identity: &str,
    lease_key: &DiscoveryLeaseKey,
    now: u64,
) -> Result<InitialWorkScopeSourceDiscoveryLease, WorkScopeSourceAdmissionError> {
    identity
        .validate()
        .map_err(|_| WorkScopeSourceAdmissionError::FenceMismatch)?;
    let fence = &identity.request.state_fence;
    if identity.request.metadata.state_fence != *fence
        || identity.deadline_unix_ms == 0
        || now > identity.deadline_unix_ms
    {
        return Err(WorkScopeSourceAdmissionError::FenceMismatch);
    }
    let request_session = identity
        .request
        .metadata
        .session_id
        .as_ref()
        .ok_or_else(|| {
            WorkScopeSourceAdmissionError::SourceAdmission(
                "initial source admission requires an authenticated request session".to_owned(),
            )
        })?;
    lease_key
        .validate()
        .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))?;
    if lease_key.proposer_ref != identity.request.metadata.request_id.as_str()
        || lease_key.session_ref != request_session.as_str()
        || lease_key.root_filesystem_identity_ref != explicit_root_identity
    {
        return Err(WorkScopeSourceAdmissionError::SourceAdmission(
            "discovery lease key differs from the authenticated request or approved root"
                .to_owned(),
        ));
    }
    let signed_approval = approval.approval();
    signed_approval.validate_live_context(
        explicit_root_identity,
        &identity.request.metadata.product_id,
        &identity.request.metadata.source_id,
        &signed_approval.privacy,
        signed_approval.scope_privacy_class,
        fence,
        &lease_key.host_ref,
    )?;
    let allowed_reads = vec![DiscoveryRead::GoverningSourceCandidates];
    let consumption_limit = u32::try_from(allowed_reads.len()).map_err(|_| {
        WorkScopeSourceAdmissionError::SourceAdmission(
            "source discovery lease read count is invalid".to_owned(),
        )
    })?;
    let lease = issue_discovery_lease(&DiscoveryLeaseRequest {
        proposer_ref: lease_key.proposer_ref.clone(),
        session_ref: lease_key.session_ref.clone(),
        host_ref: lease_key.host_ref.clone(),
        candidate_root_ref: explicit_root_identity.to_owned(),
        root_filesystem_identity_ref: lease_key.root_filesystem_identity_ref.clone(),
        allowed_reads,
        consumption_limit,
        deadline: identity.deadline_unix_ms,
    })
    .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))?;
    if !lease.key_matches(
        &lease_key.proposer_ref,
        &lease_key.session_ref,
        &lease_key.host_ref,
        &lease_key.root_filesystem_identity_ref,
    ) {
        return Err(WorkScopeSourceAdmissionError::SourceAdmission(
            "issued discovery lease does not match the authenticated request".to_owned(),
        ));
    }
    lease
        .authorize(DiscoveryRead::GoverningSourceCandidates, now)
        .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))?;
    Ok(InitialWorkScopeSourceDiscoveryLease {
        lease,
        authenticated_approver_principal_ref: lease_key.host_ref.clone(),
        issued_at: now,
    })
}

impl VerifiedGoverningSourceApproval {
    /// Parses and joins the approval embedded in the sealed setup snapshot.
    pub fn from_verified_initial_snapshot(
        snapshot: &eliot_config::initial_snapshot::VerifiedInitialConfigSnapshot,
    ) -> Result<Self, WorkScopeSourceAdmissionError> {
        let approval = GoverningSourceApproval::from_verified_initial_snapshot(snapshot)?;
        let signed_snapshot_digest = snapshot.envelope_digest().to_owned();
        if !is_sha256(&signed_snapshot_digest) {
            return Err(WorkScopeSourceAdmissionError::SourceApprovalEncoding(
                "verified snapshot has an invalid envelope digest".to_owned(),
            ));
        }
        Ok(Self {
            approval,
            signed_snapshot_digest,
        })
    }

    /// The exact Human approval whose containing setup payload was verified.
    #[must_use]
    pub const fn approval(&self) -> &GoverningSourceApproval {
        &self.approval
    }

    /// Digest of the trust-anchor-verified signed initial snapshot envelope.
    #[must_use]
    pub fn signed_snapshot_digest(&self) -> &str {
        &self.signed_snapshot_digest
    }

    /// Derives the closed WorkScope source set from signed approval and a
    /// fresh byte-verified normative capture.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_work_scope_sources(
        &self,
        capture: &NormativePairSourceCapture,
        lease: &eliot_workscope::DiscoveryReadLease,
        explicit_root_identity: &str,
        product_id: &ProductId,
        source_id: &SourceId,
        lease_key: &DiscoveryLeaseKey,
        privacy: &PrivacyProfile,
        scope_privacy_class: eliot_security_contracts::PrivacyClass,
        state_fence: &StateFence,
        scope_ref: &str,
        generation: u64,
        now: u64,
        expires_at: u64,
    ) -> Result<GoverningSourceSet, WorkScopeSourceAdmissionError> {
        self.approval.derive_work_scope_sources(
            capture,
            lease,
            explicit_root_identity,
            product_id,
            source_id,
            lease_key,
            privacy,
            scope_privacy_class,
            state_fence,
            &self.approval.approver_principal_ref,
            scope_ref,
            generation,
            now,
            expires_at,
        )
    }
}

/// Fully prepared initial owner snapshot and the ordinary canonical write
/// transition that persists it.
#[derive(Clone, Debug)]
pub struct PreparedWorkScopeSourceAdmission {
    /// Initial owner candidate to install only after canonical Store readback.
    pub owner: WorkScopeBindingOwner,
    /// Exact source-capture-enriched owner snapshot encoded in the transition.
    pub snapshot: WorkScopeBindingSnapshot,
    /// Canonical envelope admitted by the Governor.
    pub envelope: CanonicalWriteEnvelope,
    /// Immutable transition prepared from `envelope`.
    pub transition: eliot_store_api::PreparedTransition,
    /// The exact authority and causal inputs checked against the request fence.
    pub authority_binding: AuthorityBinding,
    /// The exact causal binding checked against the request fence.
    pub causal_binding: CausalBinding,
    /// Receipt-domain scope binding using the request's admitted ProductId.
    pub receipt_work_scope_binding: eliot_receipts::WorkScopeBinding,
    /// Canonical JSON projection of `receipt_work_scope_binding`.
    pub receipt_work_scope_binding_json: String,
    /// SHA-256 of the canonical receipt scope-binding projection.
    pub receipt_work_scope_binding_sha256: String,
}

impl PreparedWorkScopeSourceAdmission {
    /// Accepts only the exact committed receipt produced by applying this
    /// transition with the Kernel-retained authority and Policy parent.
    ///
    /// This rejects a Store response that committed the mutation under a
    /// different authority, genesis causal chain, fence, request, operation,
    /// or WorkScope binding. The caller must run this before installing the
    /// prepared owner or reporting the BindScope operation as complete.
    pub fn validate_write_receipt(
        &self,
        receipt: &eliot_store_api::WriteReceipt,
    ) -> Result<(), WorkScopeSourceAdmissionError> {
        receipt
            .validate()
            .map_err(|_| WorkScopeSourceAdmissionError::CommittedReceiptMismatch)?;
        let envelope = receipt
            .envelope
            .as_ref()
            .ok_or(WorkScopeSourceAdmissionError::CommittedReceiptMismatch)?;
        if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
            || receipt.operation_id != self.transition.identity.operation_id
            || receipt.idempotency_key != self.transition.identity.idempotency_key
            || receipt.state_fence != self.transition.state_fence
            || envelope.core.request.metadata != self.envelope.request
            || envelope.core.operation.operation_id != self.transition.identity.operation_id
            || envelope.core.authority != self.authority_binding
            || envelope.core.causal != self.causal_binding
            || envelope.core.work_scope != self.receipt_work_scope_binding
        {
            return Err(WorkScopeSourceAdmissionError::CommittedReceiptMismatch);
        }
        Ok(())
    }

    /// Confirms the post-commit named owner read is exactly this prepared
    /// snapshot at its incremented owner revision and current fence.
    pub fn validate_owner_readback(
        &self,
        readback: &WorkScopeOwnerSnapshotReadback,
    ) -> Result<(), WorkScopeSourceAdmissionError> {
        let WorkScopeOwnerSnapshotReadback::Bound(owner) = readback else {
            return Err(WorkScopeSourceAdmissionError::OwnerReadbackMismatch);
        };
        let expected_bytes = canonical_json_bytes(&self.snapshot)
            .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?;
        let expected_digest = sha256_hex(&expected_bytes);
        if owner.state_fence != self.snapshot.state_fence
            || owner.owner_revision != self.snapshot.owner_revision
            || owner.snapshot.state_fence != self.snapshot.state_fence
            || owner.snapshot.owner_revision != self.snapshot.owner_revision
            || owner.value_digest != expected_digest
            || owner.snapshot != self.snapshot
        {
            return Err(WorkScopeSourceAdmissionError::OwnerReadbackMismatch);
        }
        Ok(())
    }
}

/// Refusal while preparing an initial WorkScope source-admission transition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkScopeSourceAdmissionError {
    /// The one-time Human-approved initial mutation set is missing or widened.
    #[error("initial Policy and WorkScope mutations lack exact Human setup consent")]
    InitialSetupConsentMissing,
    /// A supplied identity, authority, causal, binding, or CAS fence differed.
    #[error("WorkScope source admission inputs do not share the exact request fence")]
    FenceMismatch,
    /// Initial admission was attempted over an already bound owner row.
    #[error("initial WorkScope source admission requires an empty baseline owner")]
    OwnerAlreadyExists,
    /// The empty owner row lacks a nonzero revision or Store digest.
    #[error("empty WorkScope owner readback has an invalid revision or Store digest")]
    InvalidOwnerReadback,
    /// The Kernel-carried authority or committed Policy causal parent differs.
    #[error("initial WorkScope authority does not follow the exact committed Policy receipt")]
    PolicyReceiptMismatch,
    /// The owner revision overflowed while advancing the admitted snapshot.
    #[error("WorkScope owner revision overflowed")]
    OwnerRevisionOverflow,
    /// The source capture could not be rendered as canonical JSON.
    #[error("normative pair source capture serialization failed: {0}")]
    CaptureSerialization(String),
    /// The exact approved normative sources could not be freshly recaptured.
    #[error("normative pair source capture failed: {0}")]
    SourceCapture(String),
    /// The signed approval does not have the closed source-approval shape.
    #[error("governing source approval is malformed")]
    InvalidSourceApproval,
    /// The signed source approval differs from current authenticated inputs.
    #[error("governing source approval does not bind the current request and source pair")]
    SourceApprovalBindingMismatch,
    /// The verified setup payload does not include a Human source approval.
    #[error("verified initial configuration has no governing source approval")]
    SourceApprovalMissing,
    /// The signed source approval JSON is absent, malformed, or noncanonical.
    #[error("governing source approval encoding is invalid: {0}")]
    SourceApprovalEncoding(String),
    /// The initial scope, source closure, or matched-guard admission refused.
    #[error("initial WorkScope binding admission refused: {0}")]
    InitialAdmission(String),
    /// Existing governing-source candidate admission refused or was incomplete.
    #[error("WorkScope governing-source admission refused: {0}")]
    SourceAdmission(String),
    /// The source-capture-enriched snapshot failed owner validation.
    #[error("WorkScope source-admission snapshot is invalid: {0}")]
    Snapshot(String),
    /// The canonical transition could not be constructed or validated.
    #[error("canonical WorkScope source-admission transition is invalid: {0}")]
    Transition(String),
    /// Store committed the row without the exact authority/causal/scope bindings.
    #[error("WorkScope write receipt differs from the admitted authority or Policy parent")]
    CommittedReceiptMismatch,
    /// Fresh named WorkScope readback differs from the exact prepared snapshot.
    #[error("fresh WorkScope owner readback differs from the committed snapshot")]
    OwnerReadbackMismatch,
}

/// Creates a source-admission snapshot from genuine initial-scope inputs and
/// prepares its normal canonical `RecordWorkScopeSnapshot` transition.
///
/// The function re-runs initial binding admission and computes the matched
/// guard itself. It never accepts caller-created source statuses, authority
/// bases, guard receipts, or source capture. `approval` can only be
/// constructed from the trust-anchor-verified first-run config snapshot. The
/// caller must issue `lease` before this function reads source bytes. The
/// caller performs the bounded explicit-root workspace observation first;
/// this function then captures the exact observed root through the
/// Bootstrap parser under that lease, and joins those bytes against the signed
/// approval before deriving the WorkScope source set. `lease_key` must come
/// from the authenticated Kernel peer projection; this function binds its
/// request, session, host principal, and root components to the verified
/// `RequestIdentity` and observed root.
/// `operation_id` is the exact admitted Store operation identity retained by
/// the authenticated Task Controller attempt; this producer never aliases it
/// to the transport `RequestId`.
///
/// `owner_readback` must be the exact-fence named `owner/work_scope` read.
/// This initial-admission function accepts only an empty baseline row; a bound
/// owner must use its dedicated update/admission flow. The Store operation
/// receives the exact empty-row revision and provider digest and performs the
/// CAS.
#[allow(
    clippy::too_many_arguments,
    reason = "this one owner boundary joins every independently owned admission input without hiding authority in a generic bundle"
)]
pub fn prepare_initial_work_scope_source_admission(
    identity: &RequestIdentity,
    operation_id: &OperationId,
    admission_authority: &InitialWorkScopeAdmissionAuthority,
    descriptor: &WorkScopeDescriptor,
    observed_resources: &ObservedScopeResources,
    governing_source_generation: u64,
    approval: &VerifiedGoverningSourceApproval,
    owner_readback: &WorkScopeOwnerSnapshotReadback,
    lease_key: &DiscoveryLeaseKey,
    lease: &InitialWorkScopeSourceDiscoveryLease,
    owner_clock: impl Fn() -> u64,
) -> Result<PreparedWorkScopeSourceAdmission, WorkScopeSourceAdmissionError> {
    identity
        .validate()
        .map_err(|_| WorkScopeSourceAdmissionError::FenceMismatch)?;
    let fence = &identity.request.state_fence;
    admission_authority.validate_for(fence)?;
    let authority = &admission_authority.authority;
    let causal = &admission_authority.causal;
    if identity.request.metadata.state_fence != *fence
        || authority.state_fence != *fence
        || causal.state_fence != *fence
        || !fence
            .authority_epoch
            .is_same_authority(&authority.authority_epoch)
        || !eliot_store_api::effect_is_at_most(
            EffectClass::ReversibleMutation,
            authority.allowed_effect,
        )
        || descriptor.state_fence != *fence
        || descriptor.generation.resource_generation != fence.resource_generation
        || observed_resources.generation.resource_generation != fence.resource_generation
        || governing_source_generation != fence.resource_generation.value()
    {
        return Err(WorkScopeSourceAdmissionError::FenceMismatch);
    }
    let approved = approval.approval();
    if descriptor.privacy != approved.privacy {
        return Err(WorkScopeSourceAdmissionError::SourceApprovalBindingMismatch);
    }
    let (binding, observed) = derive_initial_scope_bindings(
        descriptor,
        observed_resources,
        approved.scope_privacy_class,
        governing_source_generation,
    )?;
    let request_session = identity
        .request
        .metadata
        .session_id
        .as_ref()
        .ok_or_else(|| {
            WorkScopeSourceAdmissionError::SourceAdmission(
                "initial source admission requires an authenticated request session".to_owned(),
            )
        })?;
    lease_key
        .validate()
        .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))?;
    if lease_key.proposer_ref != identity.request.metadata.request_id.as_str()
        || lease_key.session_ref != request_session.as_str()
        || lease_key.root_filesystem_identity_ref != binding.scope.root_identity
    {
        return Err(WorkScopeSourceAdmissionError::SourceAdmission(
            "discovery lease key differs from the authenticated request or approved root"
                .to_owned(),
        ));
    }
    if lease.lease.deadline != identity.deadline_unix_ms
        || lease.lease.candidate_root_ref != binding.scope.root_identity
        || lease.lease.allowed_reads != [DiscoveryRead::GoverningSourceCandidates]
        || lease.lease.consumption_limit != 1
        || lease.authenticated_approver_principal_ref != lease_key.host_ref
        || !lease.lease.key_matches(
            &lease_key.proposer_ref,
            &lease_key.session_ref,
            &lease_key.host_ref,
            &lease_key.root_filesystem_identity_ref,
        )
    {
        return Err(WorkScopeSourceAdmissionError::SourceAdmission(
            "source discovery lease differs from its admitted request or read scope".to_owned(),
        ));
    }
    // Read the normative pair only after the caller has issued the exact-root
    // lease and supplied the observed workspace identity. The timestamp is
    // sampled from the owner clock after all parser I/O completes.
    let capture = eliot_bootstrap::capture::capture_normative_pair_sources(Path::new(
        &binding.scope.root_identity,
    ))
    .map_err(|error| WorkScopeSourceAdmissionError::SourceCapture(error.to_string()))?;
    approved.validate_live_binding(
        &capture,
        &binding.scope.root_identity,
        &identity.request.metadata.product_id,
        &identity.request.metadata.source_id,
        &approved.privacy,
        approved.scope_privacy_class,
        fence,
        &lease.authenticated_approver_principal_ref,
    )?;
    let now_after_source_reads = owner_clock();
    if now_after_source_reads < lease.issued_at
        || now_after_source_reads > identity.deadline_unix_ms
    {
        return Err(WorkScopeSourceAdmissionError::SourceAdmission(
            "source observation clock is outside the active request lease".to_owned(),
        ));
    }
    lease
        .lease
        .authorize(
            DiscoveryRead::GoverningSourceCandidates,
            now_after_source_reads,
        )
        .map_err(|error| WorkScopeSourceAdmissionError::SourceAdmission(error.to_string()))?;
    let sources = approval.derive_work_scope_sources(
        &capture,
        &lease.lease,
        &binding.scope.root_identity,
        &identity.request.metadata.product_id,
        &identity.request.metadata.source_id,
        lease_key,
        &approved.privacy,
        approved.scope_privacy_class,
        fence,
        &binding.scope.scope_ref,
        governing_source_generation,
        now_after_source_reads,
        identity.deadline_unix_ms,
    )?;
    let (expected_revision, expected_digest) = match owner_readback {
        WorkScopeOwnerSnapshotReadback::Empty {
            state_fence,
            owner_revision,
            value_digest,
        } if state_fence == fence && *owner_revision > 0 && is_sha256(value_digest) => {
            (*owner_revision, value_digest.clone())
        }
        WorkScopeOwnerSnapshotReadback::Empty { state_fence, .. } if state_fence != fence => {
            return Err(WorkScopeSourceAdmissionError::FenceMismatch);
        }
        WorkScopeOwnerSnapshotReadback::Empty { .. } => {
            return Err(WorkScopeSourceAdmissionError::InvalidOwnerReadback);
        }
        WorkScopeOwnerSnapshotReadback::Bound(owner) => {
            if owner.state_fence != *fence {
                return Err(WorkScopeSourceAdmissionError::FenceMismatch);
            }
            return Err(WorkScopeSourceAdmissionError::OwnerAlreadyExists);
        }
    };
    let owner_revision = expected_revision
        .checked_add(1)
        .ok_or(WorkScopeSourceAdmissionError::OwnerRevisionOverflow)?;

    // The same discovery-lease-backed admission that resolved the Human
    // approval proves the source closure used for this owner guard and stored
    // capture. No status is copied from the caller.
    let final_owner = admit_initial_binding(
        descriptor,
        owner_revision,
        fence,
        &binding,
        &observed,
        &sources,
        &approved.privacy,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;
    let final_snapshot = final_owner
        .read_current(fence)
        .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;

    let capture_bytes = canonical_json_bytes(&capture)
        .map_err(|error| WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string()))?;
    let capture_json = String::from_utf8(capture_bytes.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string()))?;
    let capture_sha256 = sha256_hex(&capture_bytes);
    let product_id = identity.request.metadata.product_id.clone();
    let snapshot = WorkScopeBindingSnapshot::new_with_normative_pair_source_capture_for_product(
        fence.clone(),
        owner_revision,
        final_snapshot.binding.clone(),
        final_snapshot.guard_receipt.clone(),
        sources.clone(),
        approved.privacy.clone(),
        product_id.clone(),
        capture_json,
        capture_sha256,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?;
    let owner = WorkScopeBindingOwner::new(snapshot.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?;

    let receipt_work_scope_binding = eliot_receipts::WorkScopeBinding {
        scope_id: eliot_receipts::WorkScopeId::new(binding.scope.scope_ref.clone())
            .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?,
        product_id,
        resource_generation: fence.resource_generation,
        state_fence: fence.clone(),
    };
    let receipt_binding_bytes = canonical_json_bytes(&receipt_work_scope_binding)
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let receipt_work_scope_binding_json = String::from_utf8(receipt_binding_bytes.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let receipt_work_scope_binding_sha256 = sha256_hex(&receipt_binding_bytes);

    let snapshot_json = String::from_utf8(
        canonical_json_bytes(&snapshot)
            .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::Snapshot(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        "expected_work_scope_revision".to_owned(),
        Value::String(expected_revision.to_string()),
    );
    parameters.insert(
        "expected_work_scope_digest".to_owned(),
        Value::String(expected_digest),
    );
    parameters.insert("snapshot_json".to_owned(), Value::String(snapshot_json));
    let operation_manifest_digest = operation_manifest_set_digest(
        &generated_operation_manifests()
            .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let admission_contract_set_digest = supported_admission_contract_set_digest()
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let scope_id = ScopeId::new(binding.scope.scope_ref.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest,
        operation_manifest_digest,
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::RecordWorkScopeSnapshot,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: Vec::new(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: Vec::new(),
    };
    let transition = envelope
        .prepare()
        .map_err(|error| WorkScopeSourceAdmissionError::Transition(error.to_string()))?;
    if transition.state_fence != *fence || transition.scope_id != envelope.scope_id {
        return Err(WorkScopeSourceAdmissionError::FenceMismatch);
    }

    Ok(PreparedWorkScopeSourceAdmission {
        owner,
        snapshot,
        envelope,
        transition,
        authority_binding: authority.clone(),
        causal_binding: causal.clone(),
        receipt_work_scope_binding,
        receipt_work_scope_binding_json,
        receipt_work_scope_binding_sha256,
    })
}

/// Derives the expected and observed initial bindings from the authenticated
/// descriptor and one live explicit-root observation. It never chooses among
/// multiple observed workspaces or descriptor instances.
fn derive_initial_scope_bindings(
    descriptor: &WorkScopeDescriptor,
    observed: &ObservedScopeResources,
    privacy_class: eliot_security_contracts::PrivacyClass,
    governing_source_generation: u64,
) -> Result<(ScopeBinding, ScopeBinding), WorkScopeSourceAdmissionError> {
    descriptor
        .validate()
        .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;
    observed
        .validate()
        .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;
    if observed.kind != descriptor.kind || observed.instances.len() != 1 {
        return Err(WorkScopeSourceAdmissionError::InitialAdmission(
            "explicit root must identify exactly one descriptor-compatible workspace instance"
                .to_owned(),
        ));
    }
    let observed_instance = &observed.instances[0];
    let mut matching_instances = descriptor.instances.iter().filter(|instance| {
        instance.instance_ref == observed_instance.instance_ref
            && instance.root_identity == observed_instance.root_identity
            && instance.generation == observed_instance.generation
    });
    let instance = matching_instances.next().ok_or_else(|| {
        WorkScopeSourceAdmissionError::InitialAdmission(
            "observed explicit root is not an exact descriptor instance".to_owned(),
        )
    })?;
    if matching_instances.next().is_some() {
        return Err(WorkScopeSourceAdmissionError::InitialAdmission(
            "descriptor has multiple identical workspace instances".to_owned(),
        ));
    }
    let expected = ScopeBinding {
        scope: ScopeIdentity {
            scope_ref: descriptor.scope_ref.clone(),
            kind: descriptor.kind,
            lineage_ref: descriptor
                .lineage
                .as_ref()
                .map(|lineage| lineage.lineage_ref.clone()),
            instance_ref: instance.instance_ref.clone(),
            root_identity: instance.root_identity.clone(),
            generation: instance.generation,
        },
        privacy_class,
        governing_source_generation,
    };
    let observed_binding = observed_scope_binding(
        &expected,
        observed,
        privacy_class,
        governing_source_generation,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;
    Ok((expected, observed_binding))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
