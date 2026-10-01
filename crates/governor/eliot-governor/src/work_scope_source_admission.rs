//! Initial WorkScope source admission and canonical snapshot preparation.
//!
//! This module joins the authenticated request and authority fence, a real
//! initial WorkScope binding admission, the exact Bootstrap source capture,
//! and a fresh WorkScope-owner CAS expectation. It does not resolve a scope,
//! infer an observed workspace, admit source candidates, or install a Store
//! row. Those facts come from their respective owners and are supplied by the
//! owning daemon ingress.

use std::collections::BTreeMap;
use std::path::Path;

use eliot_bootstrap::capture::NormativePairSourceCapture;
use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{ProductId, SourceId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_protocol::RequestIdentity;
use eliot_receipts::{AuthorityBinding, CausalBinding};
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, NamedMutationOperation, NamedMutationRequest,
    OperationId, ScopeId, SecurityContext, TransitionClass,
    generated_operation_manifests, operation_manifest_set_digest,
    supported_admission_contract_set_digest,
};
use crate::composition::WorkScopeOwnerSnapshotReadback;
use eliot_workscope::{
    AuthorityBasis, GoverningSource, GoverningSourceRole, GoverningSourceSet,
    ObservedScopeResources, PrivacyProfile, ScopeBinding, ScopeIdentity, SourceStatus,
    WorkScopeBindingOwner, WorkScopeBindingSnapshot, WorkScopeDescriptor,
    admit_initial_binding, observed_scope_binding,
};
use eliot_security_contracts::{
    CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, InstructionTaint,
    IndependenceLevel, IntegrityStatus, QuarantineState, SourceAssurance,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Wire/schema revision for the Human-approved normative source closure.
pub const GOVERNING_SOURCE_APPROVAL_SCHEMA: &str = "eliot.governing-source-approval.v1";

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
        self.validate()?;
        let architecture_matches = self.architecture.source_ref == capture.architecture.source_ref
            && self.architecture.entry_ref == capture.architecture.entry_ref
            && self.architecture.compatibility_ref == capture.architecture.compatibility_ref
            && self.architecture.content_sha256 == capture.architecture.content_sha256;
        let implementation_matches = self.implementation.source_ref
            == capture.implementation.source_ref
            && self.implementation.entry_ref == capture.implementation.entry_ref
            && self.implementation.compatibility_ref
                == capture.implementation.compatibility_ref
            && self.implementation.content_sha256 == capture.implementation.content_sha256;
        if self.pair_key != capture.receipt.pair_key
            || !architecture_matches
            || !implementation_matches
            || self.architecture.content_sha256
                != capture.receipt.pair.architecture_sha256
            || self.implementation.content_sha256
                != capture.receipt.pair.implementation_sha256
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

    /// Build the two-source WorkScope closure authorized by this verified
    /// approval and the exact current normative capture.
    #[allow(clippy::too_many_arguments)]
    fn derive_work_scope_sources(
        &self,
        capture: &NormativePairSourceCapture,
        explicit_root_identity: &str,
        product_id: &ProductId,
        source_id: &SourceId,
        privacy: &PrivacyProfile,
        scope_privacy_class: eliot_security_contracts::PrivacyClass,
        state_fence: &StateFence,
        authenticated_approver_principal_ref: &str,
        scope_ref: &str,
        generation: u64,
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
        if state_fence.resource_generation.value() != generation {
            return Err(WorkScopeSourceAdmissionError::FenceMismatch);
        }
        let source = |document: &ApprovedNormativeSource, role, provenance: &str| {
            GoverningSource {
                source_ref: document.source_ref.clone(),
                role,
                assurance: SourceAssurance {
                    source_ref: document.source_ref.clone(),
                    provenance_ref: provenance.to_owned(),
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
                applicable_generation: generation,
                status: SourceStatus::Admitted,
                domains: Vec::new(),
                digest: document.content_sha256.clone(),
                authority_basis: Some(AuthorityBasis::HumanOwner {
                    owner_ref: self.approver_principal_ref.clone(),
                }),
            }
        };
        GoverningSourceSet::new(
            scope_ref,
            generation,
            vec![
                source(
                    &self.architecture,
                    GoverningSourceRole::Architecture,
                    &self.pair_key,
                ),
                source(
                    &self.implementation,
                    GoverningSourceRole::Implementation,
                    &self.pair_key,
                ),
            ],
            Vec::new(),
        )
        .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))
    }

    /// Serialize this approval as canonical bytes for the existing signed
    /// InitialSnapshotPayload field.
    pub fn canonical_json(&self) -> Result<String, WorkScopeSourceAdmissionError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string()))?;
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
        let approval: Self = serde_json::from_str(approval_json)
            .map_err(|error| {
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

/// A source approval extracted from a trust-anchor-verified initial snapshot.
/// Its private fields prevent callers from promoting an unverified JSON value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGoverningSourceApproval {
    approval: GoverningSourceApproval,
    signed_snapshot_digest: String,
}

impl VerifiedGoverningSourceApproval {
    /// Parses and joins the approval embedded in the sealed setup snapshot.
    pub fn from_verified_initial_snapshot(
        snapshot: &eliot_config::initial_snapshot::VerifiedInitialConfigSnapshot,
    ) -> Result<Self, WorkScopeSourceAdmissionError> {
        let approval = GoverningSourceApproval::from_verified_initial_snapshot(snapshot)?;
        let signed_snapshot_digest = snapshot
            .envelope_digest()
            .to_owned();
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
        explicit_root_identity: &str,
        product_id: &ProductId,
        source_id: &SourceId,
        privacy: &PrivacyProfile,
        scope_privacy_class: eliot_security_contracts::PrivacyClass,
        state_fence: &StateFence,
        scope_ref: &str,
        generation: u64,
    ) -> Result<GoverningSourceSet, WorkScopeSourceAdmissionError> {
        self.approval.derive_work_scope_sources(
            capture,
            explicit_root_identity,
            product_id,
            source_id,
            privacy,
            scope_privacy_class,
            state_fence,
            &self.approval.approver_principal_ref,
            scope_ref,
            generation,
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

/// Refusal while preparing an initial WorkScope source-admission transition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkScopeSourceAdmissionError {
    /// A supplied identity, authority, causal, binding, or CAS fence differed.
    #[error("WorkScope source admission inputs do not share the exact request fence")]
    FenceMismatch,
    /// Initial admission was attempted over an already bound owner row.
    #[error("initial WorkScope source admission requires an empty baseline owner")]
    OwnerAlreadyExists,
    /// The empty owner row lacks a nonzero revision or Store digest.
    #[error("empty WorkScope owner readback has an invalid revision or Store digest")]
    InvalidOwnerReadback,
    /// The owner revision overflowed while advancing the admitted snapshot.
    #[error("WorkScope owner revision overflowed")]
    OwnerRevisionOverflow,
    /// The source capture could not be rendered as canonical JSON.
    #[error("normative pair source capture serialization failed: {0}")]
    CaptureSerialization(String),
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
    /// The source-capture-enriched snapshot failed owner validation.
    #[error("WorkScope source-admission snapshot is invalid: {0}")]
    Snapshot(String),
    /// The canonical transition could not be constructed or validated.
    #[error("canonical WorkScope source-admission transition is invalid: {0}")]
    Transition(String),
}

/// Creates a source-admission snapshot from genuine initial-scope inputs and
/// prepares its normal canonical `RecordWorkScopeSnapshot` transition.
///
/// The function re-runs initial binding admission and computes the matched
/// guard itself. It never accepts caller-created source statuses, authority
/// bases, or guard receipts. `approval` can only be constructed from the
/// trust-anchor-verified first-run config snapshot; the current
/// `NormativePairSourceCapture` is joined against that signed approval before
/// the WorkScope source set is derived.
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
    authority: &AuthorityBinding,
    causal: &CausalBinding,
    descriptor: &WorkScopeDescriptor,
    observed_resources: &ObservedScopeResources,
    governing_source_generation: u64,
    approval: &VerifiedGoverningSourceApproval,
    capture: &NormativePairSourceCapture,
    owner_readback: &WorkScopeOwnerSnapshotReadback,
) -> Result<PreparedWorkScopeSourceAdmission, WorkScopeSourceAdmissionError> {
    identity
        .validate()
        .map_err(|_| WorkScopeSourceAdmissionError::FenceMismatch)?;
    let fence = &identity.request.state_fence;
    if identity.request.metadata.state_fence != *fence
        || authority.state_fence != *fence
        || causal.state_fence != *fence
        || !fence.authority_epoch.is_same_authority(&authority.authority_epoch)
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
    let sources = approval.derive_work_scope_sources(
        capture,
        &binding.scope.root_identity,
        &identity.request.metadata.product_id,
        &identity.request.metadata.source_id,
        &approved.privacy,
        approved.scope_privacy_class,
        fence,
        &binding.scope.scope_ref,
        governing_source_generation,
    )?;
    let (expected_revision, expected_digest) = match owner_readback {
        WorkScopeOwnerSnapshotReadback::Empty {
            state_fence,
            owner_revision,
            value_digest,
        } if state_fence == fence
            && *owner_revision > 0
            && is_sha256(value_digest) => (*owner_revision, value_digest.clone()),
        WorkScopeOwnerSnapshotReadback::Empty { state_fence, .. }
            if state_fence != fence =>
        {
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

    // The same source set that proved the initial MATCHED guard is retained
    // with the capture; callers cannot guard one closure and persist another.
    let initially_admitted = admit_initial_binding(
        descriptor,
        owner_revision,
        fence,
        &binding,
        &observed,
        &sources,
        &approved.privacy,
    )
    .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;
    let initial_snapshot = initially_admitted
        .read_current(fence)
        .map_err(|error| WorkScopeSourceAdmissionError::InitialAdmission(error.to_string()))?;

    let capture_bytes = canonical_json_bytes(capture)
        .map_err(|error| WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string()))?;
    let capture_json = String::from_utf8(capture_bytes.clone())
        .map_err(|error| WorkScopeSourceAdmissionError::CaptureSerialization(error.to_string()))?;
    let capture_sha256 = sha256_hex(&capture_bytes);
    let product_id = identity.request.metadata.product_id.clone();
    let snapshot = WorkScopeBindingSnapshot::new_with_normative_pair_source_capture_for_product(
        fence.clone(),
        owner_revision,
        initial_snapshot.binding.clone(),
        initial_snapshot.guard_receipt.clone(),
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
    parameters.insert(
        "snapshot_json".to_owned(),
        Value::String(snapshot_json),
    );
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
