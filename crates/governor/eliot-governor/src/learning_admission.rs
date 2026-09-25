//! Governor-issued learning admission permits and tickets (I12.24, #1869).
//!
//! Owner-issued, digest-bound, fence-checked admission for learning-overlay
//! and reusable-candidate influence. This module follows the established
//! Kernel `DispatchPermit` pattern (`I10-08-02`): the owner mints; the
//! consumer validates against the current fence and epochs before use;
//! missing, expired, or mismatched admission is refused
//! (`STALE_STATE_FENCE`, `STALE_AUTHORITY_EPOCH`) and never refreshed
//! silently.
//!
//! Two shapes, one meaning, split by travel:
//!
//! - [`LearningAdmissionPermit`] is the opaque in-process handle: private
//!   fields, no `Serialize` impl. Legacy permits are constructed only by
//!   [`issue_learning_admission`]; behavioral permits are constructed only by
//!   the post-commit/readback issuance seam after live checks against the
//!   [`Governor`] owner. External crates cannot forge one.
//! - [`LearningAdmissionTicket`] (contract type, serializable) is the wire
//!   twin for process boundaries the opaque handle cannot cross
//!   (out-of-process host dispatch, guest envelope). It carries the exact
//!   same bound fields and the exact same digest, minted by
//!   [`issue_learning_ticket`] under the exact same live checks. Record-bound
//!   behavioral permits are minted only by the post-commit/readback seam and
//!   carry authenticated durability evidence. See the ticket contract docs for
//!   the honest boundary statement: digest recomputation detects tampering,
//!   transplanting, and rotation, while wall-clock expiry and stale-together
//!   replay remain native/contour responsibilities.
//!
//! [`VerifiedLearningAdmission`] is lifetime-bound to the verified permit
//! and constructible only via [`verify_learning_admission`], which rebinds
//! the permit to the *current* owner epoch/generation and the presented
//! fence. Epoch rotation or fence drift invalidates old permits.
//!
//! The module is stateless: no registry, no second scheduler, no durable
//! writes. Permit lifetime is bounded by epoch/fence/overlay expiry; there is
//! no wall-clock field here (the crate carries no clock dependency) and no
//! one-shot nonce (no registry to consume it). Overlay wall-clock expiry is
//! enforced by the retrieval gate holding the overlay record.

use eliot_context_contracts::{
    LEARNING_RECORD_TICKET_SCHEMA_VERSION, LEARNING_TICKET_SCHEMA_VERSION, LearningAdmissionTicket,
    LearningRecordAdmissionTicket, learning_record_ticket_digest, learning_ticket_digest,
};
use eliot_contracts::{LearningRecordKind, StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Governor, GovernorState};
use eliot_store_api::{
    LearningRecordIdentity, NamedReadOperation, NamedReadResponse, WriteReceipt,
    WriteReceiptStatus, canonical_json_bytes, sha256_hex,
};

/// Stable identity of this admission contract.
pub const LEARNING_ADMISSION_CONTRACT: &str = "eliot.governor.learning-admission";
/// Wire revision of the claim shape accepted by issuance.
pub const LEARNING_ADMISSION_SCHEMA_VERSION: u32 = LEARNING_TICKET_SCHEMA_VERSION;

/// Requester-supplied learning admission claim: the request, never proof.
///
/// Binds the source campaign, the target task, the exact [`StateFence`] the
/// influence was admitted under, at least one influence subject (overlay
/// and/or reusable candidate), and the revalidation refs from I12.24 (scope,
/// authority, retention, evaluator, rollback).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningAdmissionClaim {
    pub schema_version: u32,
    pub source_campaign_id: String,
    pub target_task_id: String,
    pub fence: StateFence,
    pub overlay_id: Option<String>,
    pub candidate_id: Option<String>,
    pub scope_ref: String,
    pub authority_ref: String,
    pub retention_ref: String,
    pub evaluator_ref: String,
    pub rollback_ref: String,
}

impl LearningAdmissionClaim {
    /// Shape validation only; owner checks happen at issuance.
    pub fn validate(&self) -> Result<(), LearningAdmissionError> {
        if self.schema_version != LEARNING_ADMISSION_SCHEMA_VERSION {
            return Err(LearningAdmissionError::UnsupportedSchema {
                version: self.schema_version,
            });
        }
        for (field, value) in [
            ("source_campaign_id", &self.source_campaign_id),
            ("target_task_id", &self.target_task_id),
            ("scope_ref", &self.scope_ref),
            ("authority_ref", &self.authority_ref),
            ("retention_ref", &self.retention_ref),
            ("evaluator_ref", &self.evaluator_ref),
            ("rollback_ref", &self.rollback_ref),
        ] {
            if value.trim().is_empty() {
                return Err(LearningAdmissionError::MissingField(field));
            }
        }
        if self
            .overlay_id
            .as_ref()
            .is_none_or(|id| id.trim().is_empty())
            && self
                .candidate_id
                .as_ref()
                .is_none_or(|id| id.trim().is_empty())
        {
            return Err(LearningAdmissionError::NoInfluenceSubject);
        }
        self.fence
            .validate()
            .map_err(|_| LearningAdmissionError::InvalidFence)?;
        Ok(())
    }
}

/// Exact record binding attached to a behavioral learning admission.
///
/// The older [`LearningAdmissionClaim`] remains available for context
/// admission compatibility. Behavioral learning effects must use this binding
/// and the record-bound issuance/verification functions below; a caller-owned
/// boolean or an unbound influence ticket can never make a record effective.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningRecordAdmissionBinding {
    /// Closed learning record kind.
    pub record_kind: LearningRecordKind,
    /// Exact record handle.
    pub record_handle: String,
    /// Exact immutable digest of the canonical record document bytes.
    pub record_digest: String,
    /// Exact canonical scope identity.
    pub scope_id: String,
    /// Exact State Fence under which the record may affect behavior.
    pub state_fence: StateFence,
    /// Absolute expiry deadline in Unix milliseconds.
    pub expires_at_unix_ms: u64,
}

impl LearningRecordAdmissionBinding {
    /// Build a binding from the canonical store identity.
    #[must_use]
    pub fn from_identity(identity: &LearningRecordIdentity) -> Self {
        Self {
            record_kind: identity.record_kind,
            record_handle: identity.handle.clone(),
            record_digest: identity.record_digest.clone(),
            scope_id: identity.scope_id.clone(),
            state_fence: identity.state_fence.clone(),
            expires_at_unix_ms: identity.expires_at_unix_ms,
        }
    }

    fn validate(&self) -> Result<(), LearningAdmissionError> {
        for (field, value) in [
            ("record_handle", &self.record_handle),
            ("record_digest", &self.record_digest),
            ("scope_id", &self.scope_id),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(LearningAdmissionError::MissingField(field));
            }
        }
        if self.record_digest.len() != 64
            || !self
                .record_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(LearningAdmissionError::RecordIdentityMismatch);
        }
        self.state_fence
            .validate()
            .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
        if self.expires_at_unix_ms == 0 {
            return Err(LearningAdmissionError::MissingField("expires_at_unix_ms"));
        }
        Ok(())
    }
}

/// Authenticated durability evidence required before behavioral learning
/// admission. The receipt and exact named readback are retained privately; a
/// producer's self-provenance or a bare claim cannot construct this value.
#[derive(Clone, Debug, PartialEq)]
pub struct LearningRecordDurabilityEvidence {
    identity: LearningRecordIdentity,
    receipt: WriteReceipt,
    readback: NamedReadResponse,
    digest: String,
}

impl LearningRecordDurabilityEvidence {
    /// Bind a committed receipt and an exact same-fence named readback to one
    /// immutable record identity.
    pub fn from_authenticated_readback(
        identity: &LearningRecordIdentity,
        receipt: &WriteReceipt,
        readback: &NamedReadResponse,
    ) -> Result<Self, LearningAdmissionError> {
        identity
            .validate()
            .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?;
        receipt
            .validate()
            .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?;
        receipt
            .require_reconciliation_envelope()
            .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?;
        if receipt.status != WriteReceiptStatus::Committed
            || receipt.state_fence != identity.state_fence
        {
            return Err(LearningAdmissionError::DurabilityEvidenceMismatch);
        }
        readback
            .validate()
            .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?;
        if readback.operation != NamedReadOperation::GetLearningRecordRange
            || readback.state_fence != identity.state_fence
        {
            return Err(LearningAdmissionError::DurabilityEvidenceMismatch);
        }
        let payload = readback
            .payload
            .as_object()
            .ok_or(LearningAdmissionError::DurabilityEvidenceMismatch)?;
        let end_of_stream = payload
            .get("end_of_stream")
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        let total_matched = payload
            .get("total_matched")
            .and_then(serde_json::Value::as_u64)
            .ok_or(LearningAdmissionError::DurabilityEvidenceMismatch)?;
        let truncated = payload
            .get("truncated")
            .and_then(serde_json::Value::as_bool)
            != Some(false);
        let has_next_cursor = payload
            .get("next_cursor")
            .is_some_and(|cursor| !cursor.is_null());
        let records = payload
            .get("records")
            .and_then(serde_json::Value::as_array)
            .ok_or(LearningAdmissionError::DurabilityEvidenceMismatch)?;
        let matched_total = payload
            .get("matched_total")
            .and_then(serde_json::Value::as_u64)
            .ok_or(LearningAdmissionError::DurabilityEvidenceMismatch)?;
        let record_count = u64::try_from(records.len())
            .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?;
        if !end_of_stream
            || total_matched == 0
            || truncated
            || has_next_cursor
            || matched_total != total_matched
            || record_count != total_matched
        {
            return Err(LearningAdmissionError::DurabilityEvidenceMismatch);
        }
        let identity_fence_value = serde_json::to_value(&identity.state_fence)
            .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?;
        let expected_scope_digest = eliot_store_api::learning_scope_digest(&identity.scope_id)
            .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?;
        let expected_fence_digest =
            eliot_store_api::learning_fence_digest(&identity.state_fence)
                .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?;
        let exact = records.iter().any(|record| {
            let Some(record) = record.as_object() else {
                return false;
            };
            record
                .get("record_kind")
                .and_then(serde_json::Value::as_str)
                == Some(identity.record_kind.as_str())
                && record.get("handle").and_then(serde_json::Value::as_str)
                    == Some(identity.handle.as_str())
                && record
                    .get("record_digest")
                    .and_then(serde_json::Value::as_str)
                    == Some(identity.record_digest.as_str())
                && record.get("scope_id").and_then(serde_json::Value::as_str)
                    == Some(identity.scope_id.as_str())
                && record
                    .get("record_json")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|document| {
                        eliot_store_api::learning_record_document_digest(document)
                            .is_ok_and(|digest| digest == identity.record_digest)
                    })
                && record
                    .get("scope_digest")
                    .and_then(serde_json::Value::as_str)
                    == Some(expected_scope_digest.as_str())
                && record
                    .get("fence_digest")
                    .and_then(serde_json::Value::as_str)
                    == Some(expected_fence_digest.as_str())
                && record
                    .get("expires_at_unix_ms")
                    .and_then(serde_json::Value::as_u64)
                    == Some(identity.expires_at_unix_ms)
                && record.get("state_fence") == Some(&identity_fence_value)
        });
        if !exact {
            return Err(LearningAdmissionError::DurabilityEvidenceMismatch);
        }
        let digest = sha256_hex(
            &canonical_json_bytes(&serde_json::json!({
                "receipt": receipt,
                "readback": readback,
                "identity": identity,
            }))
            .map_err(|_| LearningAdmissionError::DurabilityEvidenceMismatch)?,
        );
        Ok(Self {
            identity: identity.clone(),
            receipt: receipt.clone(),
            readback: readback.clone(),
            digest,
        })
    }

    /// Exact durable identity to which this evidence is bound.
    #[must_use]
    pub fn identity(&self) -> &LearningRecordIdentity {
        &self.identity
    }

    /// Exact authenticated receipt retained for reconciliation.
    #[must_use]
    pub fn receipt(&self) -> &WriteReceipt {
        &self.receipt
    }

    /// Exact total-proven named readback retained for admission carriage.
    #[must_use]
    pub fn readback(&self) -> &NamedReadResponse {
        &self.readback
    }

    /// Digest carried into the behavioral admission receipt.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearningRecordAdmissionClaim {
    /// Existing campaign/task/owner admission claim.
    pub admission: LearningAdmissionClaim,
    /// Exact record binding required for behavioral effect.
    pub record: LearningRecordAdmissionBinding,
}

impl LearningRecordAdmissionClaim {
    /// Validate both the owner claim and exact record binding.
    pub fn validate(&self) -> Result<(), LearningAdmissionError> {
        self.admission.validate()?;
        self.record.validate()?;
        if self.admission.scope_ref.trim() != self.record.scope_id.trim() {
            return Err(LearningAdmissionError::RecordIdentityMismatch);
        }
        let handle_matches = |subject: Option<&String>| {
            subject.is_some_and(|subject| subject.trim() == self.record.record_handle.trim())
        };
        let subject_matches = match self.record.record_kind {
            LearningRecordKind::Overlay => handle_matches(self.admission.overlay_id.as_ref()),
            LearningRecordKind::Delta | LearningRecordKind::Candidate => {
                handle_matches(self.admission.candidate_id.as_ref())
            }
            LearningRecordKind::Closure
            | LearningRecordKind::ActivationReceipt
            | LearningRecordKind::ViewRef => {
                handle_matches(self.admission.overlay_id.as_ref())
                    || handle_matches(self.admission.candidate_id.as_ref())
            }
        };
        if !subject_matches {
            return Err(LearningAdmissionError::RecordIdentityMismatch);
        }
        Ok(())
    }
}

/// Fail-closed learning admission errors. Stale epoch, stale fence, and
/// digest mismatch are distinct refusals; none refreshes silently.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LearningAdmissionError {
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("unsupported claim schema version: {version}")]
    UnsupportedSchema { version: u32 },
    #[error("claim binds neither an overlay nor a reusable candidate")]
    NoInfluenceSubject,
    #[error("claim fence is invalid")]
    InvalidFence,
    #[error("governor is not in an admitting state")]
    GovernorNotAdmitting,
    #[error("claim epoch is not the live authority epoch")]
    StaleAuthorityEpoch,
    #[error("claim generation is not the live resource generation")]
    GenerationMismatch,
    #[error("admission digest does not match live owner state: tampered or stale epoch")]
    DigestMismatch,
    #[error("presented fence does not exactly match the admitted fence")]
    StaleStateFence,
    #[error("learning admission has no exact record binding")]
    MissingRecordBinding,
    #[error("learning admission record identity does not match the committed record")]
    RecordIdentityMismatch,
    #[error("learning admission has expired")]
    AdmissionExpired,
    #[error(
        "behavioral learning admission requires a committed receipt or exact total-proven readback"
    )]
    MissingDurabilityEvidence,
    #[error("learning durability evidence does not match the exact record identity")]
    DurabilityEvidenceMismatch,
}

/// Owner-issued learning admission permit (opaque in-process handle).
///
/// Wraps the wire [`LearningAdmissionTicket`] in a private field with no
/// `Serialize` impl: a permit is in-process owner evidence, not
/// caller-owned data. All getters delegate to the bound ticket, so the
/// permit digest and any ticket minted for the same claim are identical by
/// construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearningAdmissionPermit {
    ticket: LearningAdmissionTicket,
    record_binding: Option<LearningRecordAdmissionBinding>,
    durability_digest: Option<String>,
}

impl LearningAdmissionPermit {
    pub fn source_campaign_id(&self) -> &str {
        &self.ticket.source_campaign_id
    }
    pub fn target_task_id(&self) -> &str {
        &self.ticket.target_task_id
    }
    pub fn fence(&self) -> &StateFence {
        &self.ticket.fence
    }
    pub fn overlay_id(&self) -> Option<&str> {
        self.ticket.overlay_id.as_deref()
    }
    pub fn candidate_id(&self) -> Option<&str> {
        self.ticket.candidate_id.as_deref()
    }
    pub fn scope_ref(&self) -> &str {
        &self.ticket.scope_ref
    }
    pub fn authority_ref(&self) -> &str {
        &self.ticket.authority_ref
    }
    pub fn retention_ref(&self) -> &str {
        &self.ticket.retention_ref
    }
    pub fn evaluator_ref(&self) -> &str {
        &self.ticket.evaluator_ref
    }
    pub fn rollback_ref(&self) -> &str {
        &self.ticket.rollback_ref
    }
    pub fn digest(&self) -> &str {
        &self.ticket.digest
    }
    /// The bound wire ticket. Exposed so owner-side flows can transport the
    /// exact minted artifact across process boundaries; possession of the
    /// ticket alone authorizes nothing without live verification.
    pub fn ticket(&self) -> &LearningAdmissionTicket {
        &self.ticket
    }

    /// Exact record binding, when this permit was issued for behavioral
    /// learning rather than the legacy context-only contour.
    pub fn record_binding(&self) -> Option<&LearningRecordAdmissionBinding> {
        self.record_binding.as_ref()
    }

    /// Digest of the authenticated commit/readback evidence bound at
    /// issuance. Legacy influence permits have no such binding.
    #[must_use]
    pub fn durability_digest(&self) -> Option<&str> {
        self.durability_digest.as_deref()
    }

    /// Mint the exact wire twin from this already owner-issued permit.
    pub fn record_ticket(&self) -> Result<LearningRecordAdmissionTicket, LearningAdmissionError> {
        let binding = self
            .record_binding()
            .ok_or(LearningAdmissionError::MissingRecordBinding)?;
        if binding.state_fence != *self.fence() {
            return Err(LearningAdmissionError::RecordIdentityMismatch);
        }
        let mut ticket = LearningRecordAdmissionTicket {
            schema_version: LEARNING_RECORD_TICKET_SCHEMA_VERSION,
            source_campaign_id: self.source_campaign_id().to_owned(),
            target_task_id: self.target_task_id().to_owned(),
            fence: self.fence().clone(),
            record_kind: binding.record_kind.clone(),
            record_handle: binding.record_handle.clone(),
            record_digest: binding.record_digest.clone(),
            scope_id: binding.scope_id.clone(),
            expires_at_unix_ms: binding.expires_at_unix_ms,
            authority_ref: self.authority_ref().to_owned(),
            retention_ref: self.retention_ref().to_owned(),
            evaluator_ref: self.evaluator_ref().to_owned(),
            rollback_ref: self.rollback_ref().to_owned(),
            digest: String::new(),
        };
        ticket.digest = learning_record_ticket_digest(&ticket)
            .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
        Ok(ticket)
    }
}

/// States in which the Governor owner admits learning influence.
fn admitting(state: GovernorState) -> bool {
    matches!(
        state,
        GovernorState::Starting | GovernorState::Ready | GovernorState::Degraded
    )
}

fn trim_owned(value: &str) -> String {
    value.trim().to_string()
}

fn trim_optional(value: Option<&String>) -> Option<String> {
    value
        .as_ref()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
}

/// Live owner checks shared by permit and ticket minting.
fn check_live_admission(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
) -> Result<(), LearningAdmissionError> {
    claim.validate()?;
    if !admitting(governor.snapshot().state) {
        return Err(LearningAdmissionError::GovernorNotAdmitting);
    }
    let live_epoch = &governor.config().authority_epoch;
    let live_generation = governor.config().resource_generation;
    if !claim.fence.authority_epoch.is_same_authority(live_epoch) {
        return Err(LearningAdmissionError::StaleAuthorityEpoch);
    }
    if claim.fence.resource_generation != live_generation {
        return Err(LearningAdmissionError::GenerationMismatch);
    }
    Ok(())
}

fn mint_ticket(
    claim: &LearningAdmissionClaim,
) -> Result<LearningAdmissionTicket, LearningAdmissionError> {
    let mut ticket = LearningAdmissionTicket {
        schema_version: LEARNING_TICKET_SCHEMA_VERSION,
        source_campaign_id: trim_owned(&claim.source_campaign_id),
        target_task_id: trim_owned(&claim.target_task_id),
        fence: claim.fence.clone(),
        overlay_id: trim_optional(claim.overlay_id.as_ref()),
        candidate_id: trim_optional(claim.candidate_id.as_ref()),
        scope_ref: trim_owned(&claim.scope_ref),
        authority_ref: trim_owned(&claim.authority_ref),
        retention_ref: trim_owned(&claim.retention_ref),
        evaluator_ref: trim_owned(&claim.evaluator_ref),
        rollback_ref: trim_owned(&claim.rollback_ref),
        digest: String::new(),
    };
    ticket.digest =
        learning_ticket_digest(&ticket).map_err(|_| LearningAdmissionError::InvalidFence)?;
    Ok(ticket)
}

/// Mint a learning admission permit after live owner checks.
///
/// Refuses unless the Governor is admitting, the claim fence carries the
/// live authority epoch and generation, and the claim shape validates. The
/// returned permit is bound to the live epoch: rotation invalidates it.
pub fn issue_learning_admission(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
) -> Result<LearningAdmissionPermit, LearningAdmissionError> {
    check_live_admission(governor, claim)?;
    Ok(LearningAdmissionPermit {
        ticket: mint_ticket(claim)?,
        record_binding: None,
        durability_digest: None,
    })
}

/// Mint the serializable wire twin of a permit after the same live checks.
///
/// The ticket carries the exact bound fields and digest a permit would;
/// transport it across process boundaries and verify with live state plus
/// [`eliot_context_contracts::ticket_fresh_for`] (or re-verify owner-side
/// with [`verify_learning_ticket`]). Minting is owner-only; verification is
/// recomputation any holder performs.
pub fn issue_learning_ticket(
    governor: &Governor,
    claim: &LearningAdmissionClaim,
) -> Result<LearningAdmissionTicket, LearningAdmissionError> {
    check_live_admission(governor, claim)?;
    mint_ticket(claim)
}

/// Mint an owner-issued permit bound to one exact learning record identity.
///
/// This is the only issuance path accepted by behavioral learning
/// effectiveness. The opaque permit carries the binding privately; callers
/// cannot replace it after issuance.
pub fn issue_learning_record_admission(
    _governor: &Governor,
    _claim: &LearningRecordAdmissionClaim,
) -> Result<LearningAdmissionPermit, LearningAdmissionError> {
    // Legacy self-issued record admission is intentionally hard-refused.
    // Behavioral owners must use `issue_learning_record_admission_after_commit`.
    Err(LearningAdmissionError::MissingDurabilityEvidence)
}

/// Mint behavioral admission only after authenticated durability evidence.
pub fn issue_learning_record_admission_after_commit(
    governor: &Governor,
    claim: &LearningRecordAdmissionClaim,
    evidence: &LearningRecordDurabilityEvidence,
) -> Result<LearningAdmissionPermit, LearningAdmissionError> {
    check_live_admission(governor, &claim.admission)?;
    claim.validate()?;
    let claim_identity = LearningRecordIdentity {
        record_kind: claim.record.record_kind,
        handle: claim.record.record_handle.clone(),
        record_digest: claim.record.record_digest.clone(),
        scope_id: claim.record.scope_id.clone(),
        state_fence: claim.record.state_fence.clone(),
        expires_at_unix_ms: claim.record.expires_at_unix_ms,
    };
    if claim.record.state_fence != claim.admission.fence
        || evidence.identity() != &claim_identity
        || evidence.receipt().state_fence != claim.record.state_fence
        || evidence.readback().state_fence != claim.record.state_fence
    {
        return Err(LearningAdmissionError::RecordIdentityMismatch);
    }
    Ok(LearningAdmissionPermit {
        ticket: mint_ticket(&claim.admission)?,
        record_binding: Some(claim.record.clone()),
        durability_digest: Some(evidence.digest().to_owned()),
    })
}

/// Mint the serializable exact-record twin of a record-bound permit.
pub fn issue_learning_record_ticket(
    _governor: &Governor,
    _claim: &LearningRecordAdmissionClaim,
) -> Result<LearningRecordAdmissionTicket, LearningAdmissionError> {
    Err(LearningAdmissionError::MissingDurabilityEvidence)
}

/// Mint a record ticket only from an evidence-bound behavioral permit.
pub fn issue_learning_record_ticket_after_commit(
    governor: &Governor,
    claim: &LearningRecordAdmissionClaim,
    evidence: &LearningRecordDurabilityEvidence,
) -> Result<LearningRecordAdmissionTicket, LearningAdmissionError> {
    let permit = issue_learning_record_admission_after_commit(governor, claim, evidence)?;
    permit.record_ticket()
}

/// Opaque proof that one exact durable record is behaviorally effective
/// under the live Governor owner. It is a receipt, not a caller boolean.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorLearningEffectivenessReceipt {
    identity: LearningRecordIdentity,
    permit_digest: String,
    durability_digest: String,
    receipt_digest: String,
}

impl GovernorLearningEffectivenessReceipt {
    /// Exact record identity bound by this receipt.
    #[must_use]
    pub fn identity(&self) -> &LearningRecordIdentity {
        &self.identity
    }

    /// Governor permit digest carried by the receipt.
    #[must_use]
    pub fn permit_digest(&self) -> &str {
        &self.permit_digest
    }

    /// Authenticated durability-evidence digest carried by the receipt.
    #[must_use]
    pub fn durability_digest(&self) -> &str {
        &self.durability_digest
    }

    /// Digest over the complete effectiveness receipt.
    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

/// Verify durable evidence, issue the exact record-bound permit, and return an
/// opaque Governor effectiveness receipt.
pub fn admit_learning_record_after_commit(
    governor: &Governor,
    claim: &LearningRecordAdmissionClaim,
    evidence: &LearningRecordDurabilityEvidence,
    current_fence: &StateFence,
    now_unix_ms: u64,
) -> Result<
    (
        LearningAdmissionPermit,
        GovernorLearningEffectivenessReceipt,
    ),
    LearningAdmissionError,
> {
    let permit = issue_learning_record_admission_after_commit(governor, claim, evidence)?;
    verify_learning_record_admission(
        governor,
        &permit,
        current_fence,
        &LearningRecordIdentity {
            record_kind: claim.record.record_kind,
            handle: claim.record.record_handle.clone(),
            record_digest: claim.record.record_digest.clone(),
            scope_id: claim.record.scope_id.clone(),
            state_fence: claim.record.state_fence.clone(),
            expires_at_unix_ms: claim.record.expires_at_unix_ms,
        },
        now_unix_ms,
    )?;
    let identity = LearningRecordIdentity {
        record_kind: claim.record.record_kind,
        handle: claim.record.record_handle.clone(),
        record_digest: claim.record.record_digest.clone(),
        scope_id: claim.record.scope_id.clone(),
        state_fence: claim.record.state_fence.clone(),
        expires_at_unix_ms: claim.record.expires_at_unix_ms,
    };
    let permit_digest = permit.digest().to_owned();
    let durability_digest = evidence.digest().to_owned();
    let receipt_digest = sha256_hex(
        &canonical_json_bytes(&serde_json::json!({
            "domain": "eliot.governor.learning-effectiveness.v1",
            "identity": identity,
            "permit_digest": permit_digest,
            "durability_digest": durability_digest,
        }))
        .map_err(|_| LearningAdmissionError::DigestMismatch)?,
    );
    Ok((
        permit,
        GovernorLearningEffectivenessReceipt {
            identity,
            permit_digest,
            durability_digest,
            receipt_digest,
        },
    ))
}

///
/// This check is intentionally separate from legacy influence verification:
/// a valid owner permit without the exact record binding is not sufficient
/// for behavioral effect.
pub fn verify_learning_record_admission<'a>(
    governor: &Governor,
    permit: &'a LearningAdmissionPermit,
    current_fence: &StateFence,
    identity: &LearningRecordIdentity,
    now_unix_ms: u64,
) -> Result<VerifiedLearningAdmission<'a>, LearningAdmissionError> {
    identity
        .validate()
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
    let binding = permit
        .record_binding()
        .ok_or(LearningAdmissionError::MissingRecordBinding)?;
    if permit.durability_digest().is_none_or(str::is_empty) {
        return Err(LearningAdmissionError::MissingDurabilityEvidence);
    }
    let expected = LearningRecordAdmissionBinding::from_identity(identity);
    if binding != &expected {
        return Err(LearningAdmissionError::RecordIdentityMismatch);
    }
    if binding.expires_at_unix_ms <= now_unix_ms {
        return Err(LearningAdmissionError::AdmissionExpired);
    }
    let verified = verify_learning_admission(governor, permit, current_fence)?;
    Ok(VerifiedLearningAdmission {
        permit: verified.permit(),
        record_identity: Some(identity.clone()),
    })
}

/// Verify the exact wire record ticket against live owner state and time.
pub fn verify_learning_record_ticket(
    governor: &Governor,
    ticket: &LearningRecordAdmissionTicket,
    current_fence: &StateFence,
    identity: &LearningRecordIdentity,
    now_unix_ms: u64,
) -> Result<(), LearningAdmissionError> {
    identity
        .validate()
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
    if ticket.record_kind != identity.record_kind
        || ticket.record_handle != identity.handle
        || ticket.record_digest != identity.record_digest
        || ticket.scope_id != identity.scope_id
        || ticket.expires_at_unix_ms != identity.expires_at_unix_ms
        || ticket.fence != identity.state_fence
    {
        return Err(LearningAdmissionError::RecordIdentityMismatch);
    }
    if !admitting(governor.snapshot().state) {
        return Err(LearningAdmissionError::GovernorNotAdmitting);
    }
    ticket
        .validate()
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
    let recomputed = learning_record_ticket_digest(ticket)
        .map_err(|_| LearningAdmissionError::RecordIdentityMismatch)?;
    if recomputed != ticket.digest {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    let live_epoch = &governor.config().authority_epoch;
    let live_generation = governor.config().resource_generation;
    if !ticket.fence.authority_epoch.is_same_authority(live_epoch)
        || ticket.fence.resource_generation != live_generation
    {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    if !fences_match_exact(current_fence, &ticket.fence) {
        return Err(LearningAdmissionError::StaleStateFence);
    }
    if ticket.expires_at_unix_ms <= now_unix_ms {
        return Err(LearningAdmissionError::AdmissionExpired);
    }
    Ok(())
}

/// Lifetime-bound verified handle: proof that `permit` was re-bound to the
/// current owner state and `current_fence`.
///
/// The private field means only this module constructs it, and only via
/// [`verify_learning_admission`]. It borrows the permit: verification cannot
/// outlive the evidence it verified. No `Serialize` impl by design.
#[derive(Debug)]
pub struct VerifiedLearningAdmission<'a> {
    permit: &'a LearningAdmissionPermit,
    record_identity: Option<LearningRecordIdentity>,
}

impl<'a> VerifiedLearningAdmission<'a> {
    /// The verified permit. All bound values read through here are
    /// owner-authenticated for the fence verified alongside.
    pub fn permit(&self) -> &'a LearningAdmissionPermit {
        self.permit
    }

    /// Exact durable record identity, when this handle was issued through
    /// the record-bound admission path. Legacy influence-only verification
    /// returns `None` and is never sufficient for behavioral learning.
    pub fn record_identity(&self) -> Option<&LearningRecordIdentity> {
        self.record_identity.as_ref()
    }
}

/// Rebind a presented permit to the current owner state and fence.
///
/// Refuses with `DigestMismatch` when the digest does not recompute (tampered
/// fields) or the bound epoch/generation is not live (rotation), and with
/// `StaleStateFence` when only the presented fence drifted. Refuses when the
/// Governor is not admitting.
pub fn verify_learning_admission<'a>(
    governor: &Governor,
    permit: &'a LearningAdmissionPermit,
    current_fence: &StateFence,
) -> Result<VerifiedLearningAdmission<'a>, LearningAdmissionError> {
    if !admitting(governor.snapshot().state) {
        return Err(LearningAdmissionError::GovernorNotAdmitting);
    }
    let live_epoch = &governor.config().authority_epoch;
    let live_generation = governor.config().resource_generation;
    let recomputed =
        learning_ticket_digest(&permit.ticket).map_err(|_| LearningAdmissionError::InvalidFence)?;
    if recomputed != permit.ticket.digest {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    if !permit
        .ticket
        .fence
        .authority_epoch
        .is_same_authority(live_epoch)
        || permit.ticket.fence.resource_generation != live_generation
    {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    if !fences_match_exact(current_fence, &permit.ticket.fence) {
        return Err(LearningAdmissionError::StaleStateFence);
    }
    let record_identity = permit
        .record_binding()
        .map(|binding| LearningRecordIdentity {
            record_kind: binding.record_kind,
            handle: binding.record_handle.clone(),
            record_digest: binding.record_digest.clone(),
            scope_id: binding.scope_id.clone(),
            state_fence: binding.state_fence.clone(),
            expires_at_unix_ms: binding.expires_at_unix_ms,
        });
    Ok(VerifiedLearningAdmission {
        permit,
        record_identity,
    })
}

/// Rebind a presented wire ticket to the current owner state and fence.
///
/// Owner-side counterpart of the pure [`eliot_context_contracts::ticket_fresh_for`]
/// check: same verdicts, plus the admitting-state gate. Prefer this
/// wherever a live [`Governor`] is in scope.
pub fn verify_learning_ticket(
    governor: &Governor,
    ticket: &LearningAdmissionTicket,
    current_fence: &StateFence,
) -> Result<(), LearningAdmissionError> {
    if !admitting(governor.snapshot().state) {
        return Err(LearningAdmissionError::GovernorNotAdmitting);
    }
    ticket
        .validate()
        .map_err(|_| LearningAdmissionError::InvalidFence)?;
    let recomputed =
        learning_ticket_digest(ticket).map_err(|_| LearningAdmissionError::InvalidFence)?;
    if recomputed != ticket.digest {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    let live_epoch = &governor.config().authority_epoch;
    let live_generation = governor.config().resource_generation;
    if !ticket.fence.authority_epoch.is_same_authority(live_epoch)
        || ticket.fence.resource_generation != live_generation
    {
        return Err(LearningAdmissionError::DigestMismatch);
    }
    if !fences_match_exact(current_fence, &ticket.fence) {
        return Err(LearningAdmissionError::StaleStateFence);
    }
    Ok(())
}
