//! `RoleAcquisition` → typed candidate-stage input conversion (issue #1862).
//!
//! [`RoleAcquisition`] carries one role's raw owner payload together with the
//! retained read identity that read was bound to; the candidate stage
//! (`eliot_context_candidates::construct_context_candidates`) accepts one typed
//! input family per role and interprets no payload itself. This module is the
//! single conversion edge between the two, and it lives in the Governor because
//! the Governor owns the acquisition and already depends on all three contracts
//! it has to join — the payload's owner record, the read owner's retained
//! identity, and the candidate crate's typed inputs. It adds no dependency edge
//! of its own.
//!
//! Conversion discipline, unchanged from the acquisition discipline above it:
//!
//! - a role whose source was not read converts to `None`, so the candidate stage
//!   reports the slot `Missing` and an optional failure stays scoped;
//! - a role whose owner conversion does not exist stays a typed refusal. A
//!   payload that cannot be honestly converted is never mapped to an empty or
//!   partial member to make a path reachable;
//! - a payload that is not the owner record for that role is refused, and the
//!   role's recorded disposition is re-derived from the payload itself rather
//!   than believed as a verdict about it;
//! - the converted record must bind THIS acquisition and THIS compilation: the
//!   retained read identity must name the role's own closed operation, and the
//!   admitted record must carry the compilation's work scope and State Fence.
//!
//! Only the epistemic role has such a record today.
//! `GetCurrentEpistemicPosition` returns the store's admitted
//! `EpistemicPositionReadback`, whose `positions` already ARE
//! `CurrentEpistemicPosition` values minted from the external receipt by
//! `eliot_store_api::epistemic_revision::EpistemicCommit::readback`. Nothing is
//! interpreted, re-derived or constructed here: the decoder selects, validates
//! and binds a record its owner already admitted. The other three bound roles
//! keep their typed refusals, because the handlers behind them return retained
//! authority-record envelopes rather than the typed families their slots name —
//! a bounded activation result, a verified attention projection and a
//! dimensioned evidence envelope are owner decisions this crate may not make on
//! their behalf.

use eliot_context_candidates::{EpistemicInput, ProjectionState};
use eliot_context_contracts::ContextBinding;
use eliot_epistemic_contracts::{CurrentEpistemicPosition, Currentness};
use eliot_store_api::{NamedReadOperation, ScopeId};
use thiserror::Error;

use crate::context_inputs::{
    ROLE_EPISTEMIC_POSITION, RoleAcquisition, bounded_reason, decode_epistemic_payload,
};

/// Existing owner of the typed record the epistemic role converts into.
///
/// Named here so a refusal reports the owner that must extend the conversion,
/// never this composition.
pub const EPISTEMIC_ROLE_OWNER: &str = "eliot-epistemic-contracts";

/// Typed refusals of one role's owner conversion.
///
/// Every variant keeps the role label and the owner of the missing or refused
/// record, so a caller can tell an absent conversion apart from a conversion
/// that ran and said no. Nothing is flattened to a boolean and no refused
/// payload is substituted with an empty member.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RoleInputError {
    /// The role records a readable source but carries no payload to convert.
    #[error("packet role {role} is readable but carries no payload to convert")]
    PayloadAbsent {
        /// Governor role label.
        role: &'static str,
        /// Owner of the typed record this role converts into.
        owner: &'static str,
    },
    /// The role's payload is not the owner record this role converts from.
    #[error("packet role {role} payload is not the {owner} record: {detail}")]
    PayloadNotOwnerRecord {
        /// Governor role label.
        role: &'static str,
        /// Owner of the typed record this role converts into.
        owner: &'static str,
        /// Bounded reason the payload is not that record.
        detail: String,
    },
    /// The owner's own validator refused the decoded record.
    #[error("packet role {role} record was refused by {owner}: {detail}")]
    OwnerRefused {
        /// Governor role label.
        role: &'static str,
        /// Owner of the typed record this role converts into.
        owner: &'static str,
        /// Bounded reason the owner refused the record.
        detail: String,
    },
    /// The role's own disposition is degraded or non-current.
    #[error("packet role {role} is not an authoritative current read: {detail}")]
    NotCurrent {
        /// Governor role label.
        role: &'static str,
        /// Owner of the typed record this role converts into.
        owner: &'static str,
        /// Bounded reason the role is not an authoritative current read.
        detail: String,
    },
    /// The decoded record does not bind this acquisition or this compilation.
    #[error("packet role {role} record is not bound to this read or compilation: {detail}")]
    NotBound {
        /// Governor role label.
        role: &'static str,
        /// Owner of the typed record this role converts into.
        owner: &'static str,
        /// Bounded reason the record does not bind.
        detail: String,
    },
}

/// Converts the acquired epistemic role into the candidate stage's typed input.
///
/// The conversion is the owner's own record, read and bound — never built:
///
/// 1. a role whose source was not read is `None` (the candidate stage then
///    reports the slot `Missing`), exactly as an unreadable optional role is
///    scoped today, and a role whose own disposition is degraded or non-current
///    is refused rather than promoted;
/// 2. a complete role's payload is re-decoded through the existing
///    `decode_epistemic_payload` classifier, so the retained disposition is
///    re-derived from the payload's own content rather than believed. A payload
///    that is not an admitted position readback is refused, and a role that
///    claims a completed read while carrying no payload is refused;
/// 3. the retained read identity must name this role's own closed operation and
///    this compilation's work scope and State Fence. An absent identity, another
///    operation, another scope or another fence is refused — a matching
///    disposition proves nothing about which read produced the payload;
/// 4. the decoded readback must carry exactly one current admitted position.
///    Zero current positions and more than one are different facts and neither is
///    resolved by picking a row: `EpistemicInput` holds one position, so an
///    ambiguous readback would be a silent substitution;
/// 5. the selected position is validated by its own owner's validator, then
///    bound to the compilation's work scope and State Fence.
///
/// The returned `measurements` are empty on purpose. A member measurement is a
/// *supplied* record naming the serializer that measured the member's bytes
/// (`MeasurementRef`), and no route issues one; the candidate stage refuses the
/// missing measurement itself (`ContextError::MissingField`) rather than this
/// decoder inventing a serializer identity. Manufacturing that record here would
/// be the substitution this module exists to prevent.
pub fn decode_epistemic_role(
    role: &RoleAcquisition,
    binding: &ContextBinding,
) -> Result<Option<EpistemicInput>, RoleInputError> {
    match &role.state {
        // Only an authoritative completed read is converted. A degraded or
        // non-current disposition is never promoted into a present member: the
        // candidate stage derives its availability from the position's own
        // currentness, so converting a role that already answered "partial" or
        // "stale" would erase the read owner's verdict instead of carrying it.
        ProjectionState::Complete => {}
        ProjectionState::Partial { reason } | ProjectionState::Stale { reason } => {
            return Err(RoleInputError::NotCurrent {
                role: ROLE_EPISTEMIC_POSITION,
                owner: EPISTEMIC_ROLE_OWNER,
                detail: bounded_reason(
                    "a degraded or stale role is never promoted to an admitted position",
                    reason.as_str(),
                ),
            });
        }
        ProjectionState::KnownEmpty
        | ProjectionState::Unavailable { .. }
        | ProjectionState::Unknown { .. }
        | ProjectionState::Missing
        | ProjectionState::Blocked { .. } => return Ok(None),
    }
    let payload = role.payload.as_ref().ok_or(RoleInputError::PayloadAbsent {
        role: ROLE_EPISTEMIC_POSITION,
        owner: EPISTEMIC_ROLE_OWNER,
    })?;
    let (decoded, readback) = decode_epistemic_payload(payload);
    if !matches!(&decoded, ProjectionState::Complete) {
        return Err(RoleInputError::PayloadNotOwnerRecord {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason(
                "payload does not decode to an admitted position readback",
                format!("{decoded:?}"),
            ),
        });
    }
    let readback = readback.ok_or(RoleInputError::PayloadNotOwnerRecord {
        role: ROLE_EPISTEMIC_POSITION,
        owner: EPISTEMIC_ROLE_OWNER,
        detail: bounded_reason(
            "readable position role decoded without an admitted readback",
            "absent",
        ),
    })?;
    require_epistemic_read_identity(role, binding)?;
    let position = current_position(&readback.positions)?;
    position
        .validate()
        .map_err(|error| RoleInputError::OwnerRefused {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason("admitted position failed its own validator", error),
        })?;
    if position.admission.scope != binding.scope_id.as_str() {
        return Err(RoleInputError::NotBound {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason(
                "admitted position names another work scope",
                position.admission.scope.as_str(),
            ),
        });
    }
    if position.admission.fence != binding.state_fence {
        return Err(RoleInputError::NotBound {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason(
                "admitted position was admitted under another State Fence",
                format!("{:?}", position.admission.fence),
            ),
        });
    }
    Ok(Some(EpistemicInput {
        position: position.clone(),
        measurements: Vec::new(),
    }))
}

/// Binds one retained read identity to this role's own operation and to this
/// compilation's scope and State Fence.
///
/// The identity is content, not provenance metadata: the disposition says the
/// role was readable, and only the retained identity says which closed
/// operation, scope and fence actually produced the payload this decoder is
/// about to convert.
fn require_epistemic_read_identity(
    role: &RoleAcquisition,
    binding: &ContextBinding,
) -> Result<(), RoleInputError> {
    let identity = role.identity.as_ref().ok_or(RoleInputError::NotBound {
        role: ROLE_EPISTEMIC_POSITION,
        owner: EPISTEMIC_ROLE_OWNER,
        detail: bounded_reason(
            "a readable position role must retain its read identity",
            "absent",
        ),
    })?;
    if identity.operation() != NamedReadOperation::GetCurrentEpistemicPosition {
        return Err(RoleInputError::NotBound {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason(
                "retained read identity answers another operation",
                format!("{:?}", identity.operation()),
            ),
        });
    }
    if identity.scope_id().map(ScopeId::as_str) != Some(binding.scope_id.as_str()) {
        return Err(RoleInputError::NotBound {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason(
                "retained read identity answers another work scope",
                format!("{:?}", identity.scope_id().map(ScopeId::as_str)),
            ),
        });
    }
    if identity.state_fence() != &binding.state_fence {
        return Err(RoleInputError::NotBound {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason(
                "retained read identity was served under another State Fence",
                format!("{:?}", identity.state_fence()),
            ),
        });
    }
    Ok(())
}

/// Selects the single current admitted position of one decoded readback.
///
/// `EpistemicInput` carries exactly one position, so "the first current row" is
/// not a selection rule: a readback with no current position and a readback
/// with several are both refusals, because either one would have to be resolved
/// by choosing a row rather than by reading the owner's verdict.
fn current_position(
    positions: &[CurrentEpistemicPosition],
) -> Result<&CurrentEpistemicPosition, RoleInputError> {
    let mut current = positions
        .iter()
        .filter(|position| position.currentness == Currentness::Current);
    let Some(position) = current.next() else {
        return Err(RoleInputError::OwnerRefused {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason(
                "admitted readback carries no current position",
                format!("{} position(s) read", positions.len()),
            ),
        });
    };
    if current.next().is_some() {
        return Err(RoleInputError::OwnerRefused {
            role: ROLE_EPISTEMIC_POSITION,
            owner: EPISTEMIC_ROLE_OWNER,
            detail: bounded_reason(
                "admitted readback carries more than one current position",
                format!("{} position(s) read", positions.len()),
            ),
        });
    }
    Ok(position)
}
