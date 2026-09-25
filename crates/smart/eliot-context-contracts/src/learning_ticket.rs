//! Governor-minted learning admission ticket, wire form (I12.24, #1869).
//!
//! [`LearningAdmissionTicket`] is the serializable twin of the owner-held
//! admission: the Governor owner mints it after live admission checks, and
//! any holder can verify its integrity by recomputing
//! [`learning_ticket_digest`] and its freshness via [`ticket_fresh_for`].
//! It crosses process boundaries (host dispatch, guest envelope) where the
//! opaque in-process permit cannot travel.
//!
//! Honest security statement (read before relying on this):
//!
//! - The digest binds every bound field, so post-issuance tampering,
//!   cross-campaign/task transplanting, and subject substitution are
//!   detected by recomputation — no secrets, no registry.
//! - Forging a ticket from scratch for *currently valid* parameters is
//!   equivalent to legitimate issuance, because the issuance checks ARE the
//!   admission policy (live epoch/generation/fence/shape). What forgery
//!   cannot do is backdate (live-epoch recompute fails after rotation),
//!   drift fences (exact-match fails), widen subjects, or mint during a
//!   non-admitting owner state.
//! - Wall-clock expiry is NOT enforceable from the digest or inside the
//!   clockless guest; it is enforced by native gates and the host contour.
//!   Stale-together full-compilation replays pass structural checks and rely
//!   on contour fence freshness (I14.14 generation fencing).

use eliot_contracts::{
    EpochId, LearningRecordKind, ResourceGeneration, StateFence, fences_match_exact,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContextError, validate_digest, validate_text};

/// Schema version of the ticket wire shape.
pub const LEARNING_TICKET_SCHEMA_VERSION: u32 = 1;
/// Digest domain separator (APPENDIX-P: canonical hashes use normalized
/// versioned serialization).
pub const LEARNING_TICKET_DIGEST_DOMAIN: &str = "eliot.smart.context.learning-ticket.v1";

/// Owner-minted learning admission ticket (serializable wire form).
///
/// Field-for-field identical in meaning to the owner-held permit; the
/// `digest` binds them all. Minted only by the Governor owner after live
/// admission checks; verified by recomputation plus live-state binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningAdmissionTicket {
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
    pub digest: String,
}

impl LearningAdmissionTicket {
    /// Shape validation only; issuance and freshness happen owner-side.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != LEARNING_TICKET_SCHEMA_VERSION {
            return Err(ContextError::InvalidField("learning_ticket.schema_version"));
        }
        validate_text(
            &self.source_campaign_id,
            "learning_ticket.source_campaign_id",
        )?;
        validate_text(&self.target_task_id, "learning_ticket.target_task_id")?;
        validate_text(&self.scope_ref, "learning_ticket.scope_ref")?;
        validate_text(&self.authority_ref, "learning_ticket.authority_ref")?;
        validate_text(&self.retention_ref, "learning_ticket.retention_ref")?;
        validate_text(&self.evaluator_ref, "learning_ticket.evaluator_ref")?;
        validate_text(&self.rollback_ref, "learning_ticket.rollback_ref")?;
        if self
            .overlay_id
            .as_ref()
            .is_none_or(|id| id.trim().is_empty())
            && self
                .candidate_id
                .as_ref()
                .is_none_or(|id| id.trim().is_empty())
        {
            return Err(ContextError::MissingField("learning_ticket.subject"));
        }
        self.fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        validate_digest(&self.digest, "learning_ticket.digest")?;
        Ok(())
    }
}

/// Canonical digest input: explicit field order, versioned domain. The
/// fence enters through its canonical tuple encoding, never a scalar.
#[derive(Serialize)]
struct TicketDigestInput<'a> {
    domain: &'static str,
    schema_version: u32,
    source_campaign_id: &'a str,
    target_task_id: &'a str,
    fence: &'a StateFence,
    overlay_id: Option<&'a str>,
    candidate_id: Option<&'a str>,
    scope_ref: &'a str,
    authority_ref: &'a str,
    retention_ref: &'a str,
    evaluator_ref: &'a str,
    rollback_ref: &'a str,
}

/// Compute the binding digest for a ticket's fields.
///
/// Pure canonical encoding (same family as [`crate::canonical_digest`]);
/// policy lives with the minting/verifying owner, never here.
pub fn learning_ticket_digest(ticket: &LearningAdmissionTicket) -> Result<String, ContextError> {
    let input = TicketDigestInput {
        domain: LEARNING_TICKET_DIGEST_DOMAIN,
        schema_version: ticket.schema_version,
        source_campaign_id: ticket.source_campaign_id.trim(),
        target_task_id: ticket.target_task_id.trim(),
        fence: &ticket.fence,
        overlay_id: ticket.overlay_id.as_deref(),
        candidate_id: ticket.candidate_id.as_deref(),
        scope_ref: ticket.scope_ref.trim(),
        authority_ref: ticket.authority_ref.trim(),
        retention_ref: ticket.retention_ref.trim(),
        evaluator_ref: ticket.evaluator_ref.trim(),
        rollback_ref: ticket.rollback_ref.trim(),
    };
    let bytes = eliot_contracts::canonical_json_bytes(&input)
        .map_err(|_| ContextError::InvalidField("learning_ticket.canonical"))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

/// Pure freshness/binding check of a ticket against trusted live state.
///
/// Returns true only when the digest recomputes (untampered), the epoch is
/// the live authority, the generation matches, and the presented fence
/// exactly matches the admitted fence. Mirrors the [`fences_match_exact`]
/// precedent: comparison only, no policy. The caller supplies live state
/// from the owner (native) or the admitted dispatch contour — never from
/// the requester.
pub fn ticket_fresh_for(
    ticket: &LearningAdmissionTicket,
    live_epoch: &EpochId,
    live_generation: ResourceGeneration,
    current_fence: &StateFence,
) -> bool {
    if ticket.schema_version != LEARNING_TICKET_SCHEMA_VERSION {
        return false;
    }
    let Ok(recomputed) = learning_ticket_digest(ticket) else {
        return false;
    };
    if recomputed != ticket.digest {
        return false;
    }
    if !ticket.fence.authority_epoch.is_same_authority(live_epoch) {
        return false;
    }
    if ticket.fence.resource_generation != live_generation {
        return false;
    }
    fences_match_exact(current_fence, &ticket.fence)
}

/// Schema version for the exact learning-record admission ticket.
pub const LEARNING_RECORD_TICKET_SCHEMA_VERSION: u32 = 1;
/// Digest domain for the exact learning-record admission ticket.
pub const LEARNING_RECORD_TICKET_DIGEST_DOMAIN: &str =
    "eliot.smart.context.learning-record-ticket.v1";

/// Wire admission for one exact learning-record identity.
///
/// This is deliberately separate from the older influence-only ticket: the
/// older shape remains a compatibility contour for context admission, while
/// behavioral learning effects require this record-, scope-, fence-, and
/// expiry-bound twin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningRecordAdmissionTicket {
    /// Exact ticket schema revision.
    pub schema_version: u32,
    /// Source campaign identity.
    pub source_campaign_id: String,
    /// Target task identity.
    pub target_task_id: String,
    /// Exact admission State Fence.
    pub fence: StateFence,
    /// Closed learning record kind.
    pub record_kind: LearningRecordKind,
    /// Exact record handle.
    pub record_handle: String,
    /// Exact immutable record digest.
    pub record_digest: String,
    /// Exact canonical scope identity.
    pub scope_id: String,
    /// Absolute expiry deadline in Unix milliseconds.
    pub expires_at_unix_ms: u64,
    /// Governor authority reference.
    pub authority_ref: String,
    /// Retention-policy reference.
    pub retention_ref: String,
    /// Evaluator reference.
    pub evaluator_ref: String,
    /// Rollback reference.
    pub rollback_ref: String,
    /// Digest over every preceding field.
    pub digest: String,
}

impl LearningRecordAdmissionTicket {
    /// Validate shape and the closed record-kind vocabulary.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != LEARNING_RECORD_TICKET_SCHEMA_VERSION {
            return Err(ContextError::InvalidField(
                "learning_record_ticket.schema_version",
            ));
        }
        for (field, value) in [
            (
                "learning_record_ticket.source_campaign_id",
                &self.source_campaign_id,
            ),
            (
                "learning_record_ticket.target_task_id",
                &self.target_task_id,
            ),
            ("learning_record_ticket.record_handle", &self.record_handle),
            ("learning_record_ticket.scope_id", &self.scope_id),
            ("learning_record_ticket.authority_ref", &self.authority_ref),
            ("learning_record_ticket.retention_ref", &self.retention_ref),
            ("learning_record_ticket.evaluator_ref", &self.evaluator_ref),
            ("learning_record_ticket.rollback_ref", &self.rollback_ref),
        ] {
            validate_text(value, field)?;
            if value.trim() != value {
                return Err(ContextError::InvalidField(field));
            }
        }
        // `LearningRecordKind` is the closed shared enum; no string match is
        // needed or accepted here.
        validate_digest(&self.record_digest, "learning_record_ticket.record_digest")?;
        self.fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        if self.expires_at_unix_ms == 0 {
            return Err(ContextError::InvalidField(
                "learning_record_ticket.expires_at_unix_ms",
            ));
        }
        validate_digest(&self.digest, "learning_record_ticket.digest")?;
        Ok(())
    }
}

#[derive(Serialize)]
struct RecordTicketDigestInput<'a> {
    domain: &'static str,
    schema_version: u32,
    source_campaign_id: &'a str,
    target_task_id: &'a str,
    fence: &'a StateFence,
    record_kind: LearningRecordKind,
    record_handle: &'a str,
    record_digest: &'a str,
    scope_id: &'a str,
    expires_at_unix_ms: u64,
    authority_ref: &'a str,
    retention_ref: &'a str,
    evaluator_ref: &'a str,
    rollback_ref: &'a str,
}

/// Compute the exact record-admission ticket digest.
pub fn learning_record_ticket_digest(
    ticket: &LearningRecordAdmissionTicket,
) -> Result<String, ContextError> {
    let input = RecordTicketDigestInput {
        domain: LEARNING_RECORD_TICKET_DIGEST_DOMAIN,
        schema_version: ticket.schema_version,
        source_campaign_id: ticket.source_campaign_id.trim(),
        target_task_id: ticket.target_task_id.trim(),
        fence: &ticket.fence,
        record_kind: ticket.record_kind,
        record_handle: ticket.record_handle.trim(),
        record_digest: ticket.record_digest.trim(),
        scope_id: ticket.scope_id.trim(),
        expires_at_unix_ms: ticket.expires_at_unix_ms,
        authority_ref: ticket.authority_ref.trim(),
        retention_ref: ticket.retention_ref.trim(),
        evaluator_ref: ticket.evaluator_ref.trim(),
        rollback_ref: ticket.rollback_ref.trim(),
    };
    let bytes = eliot_contracts::canonical_json_bytes(&input)
        .map_err(|_| ContextError::InvalidField("learning_record_ticket.canonical"))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

/// Check exact record-ticket integrity, live authority, fence, and expiry.
pub fn learning_record_ticket_fresh_for(
    ticket: &LearningRecordAdmissionTicket,
    live_epoch: &EpochId,
    live_generation: ResourceGeneration,
    current_fence: &StateFence,
    now_unix_ms: u64,
) -> bool {
    if ticket.validate().is_err() {
        return false;
    }
    let Ok(recomputed) = learning_record_ticket_digest(ticket) else {
        return false;
    };
    recomputed == ticket.digest
        && ticket.fence.authority_epoch.is_same_authority(live_epoch)
        && ticket.fence.resource_generation == live_generation
        && fences_match_exact(current_fence, &ticket.fence)
        && ticket.expires_at_unix_ms > now_unix_ms
}
