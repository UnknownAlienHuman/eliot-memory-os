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
//!   fields, no `Serialize` impl. Only [`issue_learning_admission`] can
//!   construct it, and only after live admission checks against the
//!   [`Governor`] owner. External crates cannot forge one.
//! - [`LearningAdmissionTicket`] (contract type, serializable) is the wire
//!   twin for process boundaries the opaque handle cannot cross
//!   (out-of-process host dispatch, guest envelope). It carries the exact
//!   same bound fields and the exact same digest, minted by
//!   [`issue_learning_ticket`] under the exact same live checks. See the
//!   ticket contract docs for the honest boundary statement: digest
//!   recomputation detects tampering, transplanting, and rotation, while
//!   wall-clock expiry and stale-together replay remain native/contour
//!   responsibilities.
//!
//! [`VerifiedLearningAdmission`] is lifetime-bound to the verified permit
//! and constructible only via [`verify_learning_admission`], which rebinds
//! the permit to the *current* owner epoch/generation and the presented
//! fence. Epoch rotation or fence drift invalidates old permits.
//!
//! Cross-task carryover is a **second** admission, never a reinterpretation
//! of the first (I12.24:295: "Cross-task carryover requires a new governed
//! admission that revalidates scope, authority, retention, evaluator, and
//! rollback"). [`LearningAdmissionPermit::issue_cross_task_admission`] mints
//! that second admission for the foreign target task through the same
//! [`issue_learning_admission`] live checks and returns the owner-issued
//! [`CrossTaskAdmissionRecord`] a consumer binds to;
//! [`LearningAdmissionPermit::verify_cross_task_admission`] re-verifies both
//! permits through the same [`verify_learning_admission`] live checks and
//! re-checks the record's revalidated values against the cross-task permit.
//! Its step set is factored so a consumer that already holds two
//! [`VerifiedLearningAdmission`] handles can re-check a presented record
//! without re-deriving the identity digest:
//! [`LearningAdmissionPermit::verify_cross_task_record`] runs the record rules
//! alone and is not an alternative authorization path, because a
//! [`VerifiedLearningAdmission`] is obtainable only from live owner state.
//! Distinctness there is structural, not nominal: an admission that
//! revalidates the local admission's own target task, or that mints an
//! identical digest, is refused with a typed
//! [`CrossTaskAdmissionError`]. A record alone authorizes nothing — it is
//! inert without both owner-issued permits and the live owner state that
//! verifies them.
//!
//! The module is stateless: no registry, no second scheduler, no durable
//! writes. Permit lifetime is bounded by epoch/fence/overlay expiry; there is
//! no wall-clock field here (the crate carries no clock dependency) and no
//! one-shot nonce (no registry to consume it). Overlay wall-clock expiry is
//! enforced by the retrieval gate holding the overlay record.

use eliot_context_contracts::{
    LEARNING_TICKET_SCHEMA_VERSION, LearningAdmissionTicket, canonical_digest,
    learning_ticket_digest,
};
use eliot_contracts::{StateFence, fences_match_exact};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Governor, GovernorState};

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
}

/// Digest domain of the cross-task admission identity (#1869/A3).
///
/// Purpose-separated from the learning-ticket digest domain declared by
/// `eliot_context_contracts`: a cross-task admission identity is a digest
/// *of two issuance digests*, so it can never be one of them, and it is
/// recomputable by any holder of both verified permits. Built from
/// owner-minted digests only — never from display text, `Debug` output, or a
/// caller field.
const CROSS_TASK_ADMISSION_DIGEST_DOMAIN: &str = "eliot.governor.learning-admission.cross-task.v1";

/// Fail-closed refusals of the distinct cross-task admission path
/// (#1869/A3, I12.24:295).
///
/// A separate type from [`LearningAdmissionError`] on purpose: the shared
/// owner path keeps its exact variant set, and the cross-task rules add only
/// cross-task-specific refusals. Every shared refusal travels as the typed
/// [`CrossTaskAdmissionError::OwnerAdmission`] source instead of being
/// collapsed into a generic code or display string, so no consumer loses the
/// distinction between "not admitting", "stale epoch", "generation drift",
/// "digest mismatch" and "fence drift".
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CrossTaskAdmissionError {
    /// The shared owner admission/verification path refused.
    #[error("shared learning admission path refused the cross-task admission: {0}")]
    OwnerAdmission(#[source] LearningAdmissionError),
    /// A cross-task input is blank, whitespace-only, or carries a control
    /// character, so it cannot be admitted as a revalidated value.
    #[error("cross-task admission field is not usable text: {0}")]
    UnusableField(&'static str),
    /// The revalidation claim names a different source campaign than the
    /// local admission, so it is not a carryover of this learning.
    #[error("cross-task claim revalidates a different source campaign")]
    SourceCampaignMismatch,
    /// The revalidation claim binds a different overlay/candidate subject
    /// than the local admission.
    #[error("cross-task claim revalidates a different influence subject")]
    InfluenceSubjectMismatch,
    /// The cross-task admission did not produce a *distinct* admission: its
    /// ticket digest equals the local admission's, so it binds exactly the
    /// fields the local one already binds.
    #[error("cross-task revalidation did not produce a distinct admission")]
    NotDistinctAdmission,
    /// The cross-task claim revalidates the local admission's own target
    /// task, so it is not a carryover to another task at all.
    #[error("cross-task claim does not name a different target task")]
    TargetNotForeign,
    /// The presented record's owner-issued identity or its bound issuance
    /// digests do not match the two verified permits.
    #[error("cross-task admission record does not match the owner-issued identity")]
    RecordMismatch,
    /// A revalidated value in the presented record does not equal the value
    /// the cross-task permit binds. `field` names which one.
    #[error("cross-task admission record does not revalidate the owner-issued value: {field}")]
    RevalidationMismatch { field: &'static str },
    /// The presented record declares an unsupported schema version.
    #[error("unsupported cross-task admission record version: {version}")]
    UnsupportedRecordVersion { version: u32 },
    /// The owner-issued identity could not be computed over its canonical
    /// encoding.
    #[error("cross-task admission identity could not be computed")]
    IdentityNotComputable,
}

/// Owner-issued record of one distinct cross-task admission (I12.24:295).
///
/// This is the A3 evidence a consumer binds its cross-task admission
/// identity to: `admission_id` is a purpose-tagged canonical digest over the
/// two owner-issued ticket digests, so it is recomputable from the verified
/// permits and cannot be spelled from bare strings. Every other field is
/// copied from the cross-task permit the owner minted, never from the
/// requester: the five revalidated values (scope, authority, retention,
/// evaluator, rollback) are mandatory, non-blank, individually inspectable
/// fields, and the two digests bind them (plus the target task, campaign,
/// subjects, fence, epoch and generation) transitively.
///
/// Wire form, like [`LearningAdmissionTicket`]: it is transported and
/// persisted, never treated as authority. It means nothing until
/// [`LearningAdmissionPermit::verify_cross_task_admission`] re-verifies both
/// owner-issued permits against live owner state and confirms these fields
/// against the cross-task permit. There is no expiry field: overlay and
/// candidate wall-clock expiry belongs to the consumer's retrieval gate, not
/// to admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossTaskAdmissionRecord {
    /// Wire revision of this record shape.
    pub schema_version: u32,
    /// Owner-issued identity of the cross-task admission: the canonical
    /// digest of `source_admission_digest` and `cross_task_admission_digest`
    /// under the cross-task purpose tag.
    pub admission_id: String,
    /// Digest of the local admission the carryover starts from.
    pub source_admission_digest: String,
    /// Digest of the distinct cross-task admission minted for the foreign
    /// target task.
    pub cross_task_admission_digest: String,
    pub source_campaign_id: String,
    pub target_task_id: String,
    /// Revalidated scope for the target task.
    pub scope_ref: String,
    /// Revalidated decision authority for the target task.
    pub authority_ref: String,
    /// Revalidated retention material for the target task.
    pub retention_ref: String,
    /// Revalidated evaluator for the target task.
    pub evaluator_ref: String,
    /// Revalidated rollback path for the target task.
    pub rollback_ref: String,
}

impl CrossTaskAdmissionRecord {
    /// Shape validation of a presented record: supported version and usable
    /// text in every field, so a blank or control-character record is refused
    /// before it is compared with owner evidence.
    ///
    /// The two digests carry no separate format rule: they are compared by
    /// equality against digests the owner recomputes, so a malformed digest
    /// simply matches nothing.
    pub fn validate(&self) -> Result<(), CrossTaskAdmissionError> {
        if self.schema_version != LEARNING_ADMISSION_SCHEMA_VERSION {
            return Err(CrossTaskAdmissionError::UnsupportedRecordVersion {
                version: self.schema_version,
            });
        }
        for (field, value) in [
            ("record.admission_id", self.admission_id.as_str()),
            (
                "record.source_admission_digest",
                self.source_admission_digest.as_str(),
            ),
            (
                "record.cross_task_admission_digest",
                self.cross_task_admission_digest.as_str(),
            ),
            (
                "record.source_campaign_id",
                self.source_campaign_id.as_str(),
            ),
            ("record.target_task_id", self.target_task_id.as_str()),
            ("record.scope_ref", self.scope_ref.as_str()),
            ("record.authority_ref", self.authority_ref.as_str()),
            ("record.retention_ref", self.retention_ref.as_str()),
            ("record.evaluator_ref", self.evaluator_ref.as_str()),
            ("record.rollback_ref", self.rollback_ref.as_str()),
        ] {
            if is_unusable_text(value) {
                return Err(CrossTaskAdmissionError::UnusableField(field));
            }
        }
        Ok(())
    }
}

/// Text rule for cross-task admission inputs: blank, whitespace-only, or
/// control-character values are refused rather than trimmed into something
/// else. Same rule the wire ticket enforces in
/// `LearningAdmissionTicket::validate`; applied here on the cross-task path
/// only, so no existing admission behaviour changes.
fn is_unusable_text(value: &str) -> bool {
    value.trim().is_empty() || value.chars().any(char::is_control)
}

/// Refuse unusable revalidation text before any cross-task permit is minted.
fn check_revalidation_text(claim: &LearningAdmissionClaim) -> Result<(), CrossTaskAdmissionError> {
    for (field, value) in [
        (
            "revalidation.source_campaign_id",
            Some(claim.source_campaign_id.as_str()),
        ),
        (
            "revalidation.target_task_id",
            Some(claim.target_task_id.as_str()),
        ),
        ("revalidation.scope_ref", Some(claim.scope_ref.as_str())),
        (
            "revalidation.authority_ref",
            Some(claim.authority_ref.as_str()),
        ),
        (
            "revalidation.retention_ref",
            Some(claim.retention_ref.as_str()),
        ),
        (
            "revalidation.evaluator_ref",
            Some(claim.evaluator_ref.as_str()),
        ),
        (
            "revalidation.rollback_ref",
            Some(claim.rollback_ref.as_str()),
        ),
        ("revalidation.overlay_id", claim.overlay_id.as_deref()),
        ("revalidation.candidate_id", claim.candidate_id.as_deref()),
    ] {
        if value.is_some_and(is_unusable_text) {
            return Err(CrossTaskAdmissionError::UnusableField(field));
        }
    }
    Ok(())
}

/// The one cross-task distinctness rule, applied identically at issuance and
/// at verification so the two cannot drift.
///
/// Four independent facts must hold for a carryover to be a *cross-task*
/// admission rather than the local admission wearing another name:
///
/// - the same source campaign (a carryover of *this* campaign's learning);
/// - the same influence subject (the overlay/candidate being carried);
/// - a different ticket digest — the structural proof. The ticket digest
///   binds every bound field, so equal digests mean the two admissions bind
///   identical fields and the "cross-task" admission is the local one;
/// - a different target task — the same fact stated in the contract's own
///   vocabulary: the revalidation must name another task.
///
/// The target comparison is evaluated *after* the digest comparison because
/// the digest check states the structural fact rather than its symptom: a
/// revalidation identical to the local claim in every field names the same
/// task and mints the same digest, and the digest check is what proves the
/// two admissions are one. The target check still fires on its own when a
/// revalidation keeps the local target task but differs elsewhere, so the
/// same-task case is refused either way.
fn check_cross_task_distinct(
    local: &LearningAdmissionPermit,
    cross_task: &LearningAdmissionPermit,
) -> Result<(), CrossTaskAdmissionError> {
    if cross_task.source_campaign_id() != local.source_campaign_id() {
        return Err(CrossTaskAdmissionError::SourceCampaignMismatch);
    }
    if cross_task.overlay_id() != local.overlay_id()
        || cross_task.candidate_id() != local.candidate_id()
    {
        return Err(CrossTaskAdmissionError::InfluenceSubjectMismatch);
    }
    if cross_task.digest() == local.digest() {
        return Err(CrossTaskAdmissionError::NotDistinctAdmission);
    }
    if cross_task.target_task_id() == local.target_task_id() {
        return Err(CrossTaskAdmissionError::TargetNotForeign);
    }
    Ok(())
}

/// Canonical preimage of the cross-task admission identity: explicit field
/// order, versioned domain, both issuance digests as canonical input.
#[derive(Serialize)]
struct CrossTaskAdmissionIdentity<'a> {
    domain: &'static str,
    contract: &'static str,
    schema_version: u32,
    source_admission_digest: &'a str,
    cross_task_admission_digest: &'a str,
}

/// Owner-issued identity of one cross-task admission.
///
/// A pure recomputation over the two owner-issued digests, so any holder of
/// both permits reaches the same value and a caller cannot supply one that
/// does not match. Because the two ticket digests already bind every field of
/// their admissions, this identity transitively binds the source campaign, the
/// foreign target task, the five revalidated refs, the subjects, the fence,
/// the authority epoch and the resource generation.
fn cross_task_admission_identity(
    local: &LearningAdmissionPermit,
    cross_task: &LearningAdmissionPermit,
) -> Result<String, CrossTaskAdmissionError> {
    canonical_digest(&CrossTaskAdmissionIdentity {
        domain: CROSS_TASK_ADMISSION_DIGEST_DOMAIN,
        contract: LEARNING_ADMISSION_CONTRACT,
        schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
        source_admission_digest: local.digest(),
        cross_task_admission_digest: cross_task.digest(),
    })
    .map_err(|_| CrossTaskAdmissionError::IdentityNotComputable)
}

/// Owner-issued learning admission permit (opaque in-process handle).
///
/// Wraps the wire [`LearningAdmissionTicket`] in a private field with no
/// `Serialize` impl: a permit is in-process owner evidence, not
/// caller-owned data. All getters delegate to the bound ticket, so the
/// permit digest and any ticket minted for the same claim are identical by
/// construction.
///
/// One permit admits one task. Carrying the same learning to *another* task
/// needs a second, distinct permit; both issuance and re-verification of that
/// pair live on this type
/// ([`LearningAdmissionPermit::issue_cross_task_admission`],
/// [`LearningAdmissionPermit::verify_cross_task_admission`]) because the
/// local permit is the anchor a carryover starts from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LearningAdmissionPermit {
    ticket: LearningAdmissionTicket,
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

    /// Issue the distinct cross-task admission that carries this admission's
    /// learning to another task (I12.24:295, #1869/A3).
    ///
    /// Returns the newly minted cross-task permit together with the
    /// owner-issued [`CrossTaskAdmissionRecord`] a consumer binds its
    /// cross-task admission identity to. `revalidation` is the owner's
    /// revalidation of scope, authority, retention, evaluator and rollback
    /// for the foreign target task: it is a claim, never proof, and its five
    /// revalidated values must all be present and usable.
    ///
    /// The cross-task permit is minted through the same
    /// [`issue_learning_admission`] live checks as any other admission — no
    /// bypass, no revalidation mode on the owner — so the Governor must be
    /// admitting and the claim's fence must carry the live authority epoch
    /// and resource generation. It is then required to be *distinct* from
    /// this admission (see the distinctness rule): same source campaign, same
    /// influence subject, different ticket digest, different target task. A
    /// revalidation that would re-admit this same learning to this same task
    /// is refused, never accepted as a "cross-task" admission.
    ///
    /// Refusal order: unusable revalidation text first (so a malformed claim
    /// mints nothing), then the shared live owner checks, then distinctness.
    ///
    /// The local permit's own freshness is not re-decided here: the
    /// revalidation claim must carry the live authority epoch and resource
    /// generation like any other admission, and
    /// [`LearningAdmissionPermit::verify_cross_task_admission`] re-verifies
    /// both permits against live owner state before any consumer may act on
    /// the record.
    pub fn issue_cross_task_admission(
        &self,
        governor: &Governor,
        revalidation: &LearningAdmissionClaim,
    ) -> Result<(LearningAdmissionPermit, CrossTaskAdmissionRecord), CrossTaskAdmissionError> {
        check_revalidation_text(revalidation)?;
        let cross_task = issue_learning_admission(governor, revalidation)
            .map_err(CrossTaskAdmissionError::OwnerAdmission)?;
        check_cross_task_distinct(self, &cross_task)?;
        let record = CrossTaskAdmissionRecord {
            schema_version: LEARNING_ADMISSION_SCHEMA_VERSION,
            admission_id: cross_task_admission_identity(self, &cross_task)?,
            source_admission_digest: self.digest().to_string(),
            cross_task_admission_digest: cross_task.digest().to_string(),
            source_campaign_id: cross_task.source_campaign_id().to_string(),
            target_task_id: cross_task.target_task_id().to_string(),
            scope_ref: cross_task.scope_ref().to_string(),
            authority_ref: cross_task.authority_ref().to_string(),
            retention_ref: cross_task.retention_ref().to_string(),
            evaluator_ref: cross_task.evaluator_ref().to_string(),
            rollback_ref: cross_task.rollback_ref().to_string(),
        };
        Ok((cross_task, record))
    }

    /// Re-check a presented cross-task record against two permits the caller
    /// has ALREADY re-bound to live owner state, without consulting a
    /// [`Governor`] again.
    ///
    /// This is steps 1 and 3-5 of [`Self::verify_cross_task_admission`] and
    /// nothing else, factored out so a consumer that already holds two
    /// [`VerifiedLearningAdmission`] handles can re-check the record without
    /// re-deriving the identity digest — and therefore cannot drift from the
    /// single definition of it. The rules are unchanged: shape, distinctness,
    /// `admission_id` recomputed from the two issuance digests, the record's
    /// two digests equal to the two permits' digests, and the record's
    /// revalidated values equal to the values the cross-task permit binds,
    /// field by field.
    ///
    /// This is NOT a second authorization path. A
    /// [`VerifiedLearningAdmission`] is constructible only by
    /// [`verify_learning_admission`] against a live [`Governor`], so a caller
    /// that reaches this method has already paid the live owner checks for BOTH
    /// permits — the method adds distinctness and record binding, never
    /// freshness. Where live state must be re-read at the point of use, use
    /// [`Self::verify_cross_task_admission`], which does both.
    pub fn verify_cross_task_record<'a>(
        &self,
        cross_task: &'a LearningAdmissionPermit,
        presented: &'a CrossTaskAdmissionRecord,
    ) -> Result<&'a CrossTaskAdmissionRecord, CrossTaskAdmissionError> {
        presented.validate()?;
        check_cross_task_distinct(self, cross_task)?;
        if presented.admission_id != cross_task_admission_identity(self, cross_task)?
            || presented.source_admission_digest != self.digest()
            || presented.cross_task_admission_digest != cross_task.digest()
        {
            return Err(CrossTaskAdmissionError::RecordMismatch);
        }
        for (field, revalidated, bound) in [
            (
                "source_campaign_id",
                presented.source_campaign_id.as_str(),
                cross_task.source_campaign_id(),
            ),
            (
                "target_task_id",
                presented.target_task_id.as_str(),
                cross_task.target_task_id(),
            ),
            (
                "scope_ref",
                presented.scope_ref.as_str(),
                cross_task.scope_ref(),
            ),
            (
                "authority_ref",
                presented.authority_ref.as_str(),
                cross_task.authority_ref(),
            ),
            (
                "retention_ref",
                presented.retention_ref.as_str(),
                cross_task.retention_ref(),
            ),
            (
                "evaluator_ref",
                presented.evaluator_ref.as_str(),
                cross_task.evaluator_ref(),
            ),
            (
                "rollback_ref",
                presented.rollback_ref.as_str(),
                cross_task.rollback_ref(),
            ),
        ] {
            if revalidated != bound {
                return Err(CrossTaskAdmissionError::RevalidationMismatch { field });
            }
        }
        Ok(presented)
    }

    /// Re-verify a cross-task admission and return the record a consumer may
    /// act on.
    ///
    /// Both admissions are re-bound to live owner state through the same
    /// [`verify_learning_admission`] checks, each against the fence of its own
    /// task: `local_fence` for this admission's task and `cross_task_fence`
    /// for the foreign target task's. The presented `record` is then held to
    /// the same rules as issuance:
    ///
    /// 1. shape — supported version and usable text in every field;
    /// 2. live owner verification of both permits (admitting state, digest
    ///    recomputation, live epoch/generation, exact fence);
    /// 3. the cross-task distinctness rule;
    /// 4. `admission_id` recomputed from the two verified digests, and the
    ///    record's two digests equal to the two permits' digests;
    /// 5. the record's revalidated values equal to the values the cross-task
    ///    permit binds, field by field, with the field named in the refusal.
    ///
    /// The returned borrow is the presented record, kept alive only as long as
    /// the evidence verified: a record alone, or a record presented without
    /// both owner-issued permits, authorizes nothing and cannot be obtained
    /// from here.
    ///
    /// What this does not claim: that the owner reviewed each revalidated
    /// value for the target task. The Governor can only admit the claim it is
    /// handed, under the live epoch/generation/fence and the authority ref it
    /// binds. A consumer that needs a revalidated value to match its own
    /// policy must compare that value itself, which is exactly what the
    /// returned record exposes.
    pub fn verify_cross_task_admission<'a>(
        &'a self,
        governor: &Governor,
        cross_task: &'a LearningAdmissionPermit,
        presented: &'a CrossTaskAdmissionRecord,
        local_fence: &StateFence,
        cross_task_fence: &StateFence,
    ) -> Result<&'a CrossTaskAdmissionRecord, CrossTaskAdmissionError> {
        verify_learning_admission(governor, self, local_fence)
            .map_err(CrossTaskAdmissionError::OwnerAdmission)?;
        verify_learning_admission(governor, cross_task, cross_task_fence)
            .map_err(CrossTaskAdmissionError::OwnerAdmission)?;
        self.verify_cross_task_record(cross_task, presented)
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

/// Lifetime-bound verified handle: proof that `permit` was re-bound to the
/// current owner state and `current_fence`.
///
/// The private field means only this module constructs it, and only via
/// [`verify_learning_admission`]. It borrows the permit: verification cannot
/// outlive the evidence it verified. No `Serialize` impl by design.
#[derive(Debug)]
pub struct VerifiedLearningAdmission<'a> {
    permit: &'a LearningAdmissionPermit,
}

impl<'a> VerifiedLearningAdmission<'a> {
    /// The verified permit. All bound values read through here are
    /// owner-authenticated for the fence verified alongside.
    pub fn permit(&self) -> &'a LearningAdmissionPermit {
        self.permit
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
    Ok(VerifiedLearningAdmission { permit })
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
