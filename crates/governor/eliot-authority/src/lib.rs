//! Pure G-01 authority contracts.
//!
//! This crate evaluates immutable authority lineage and effect admission. It
//! performs no I/O, reads no clock, activates no live authority, and exposes no
//! effect executor.

#![forbid(unsafe_code)]

mod activation;
mod break_glass;
mod effects;
mod grants;
mod leases;

pub use activation::{
    GrantActivationRequest, GrantRevocationRequest, IntroductionActivationRequest,
    IntroductionRevocationRequest, P07AuthorityPort, P07PortError, UnavailableP07AuthorityPort,
};
pub use break_glass::{
    BreakGlassAuthorization, BreakGlassAuthorizationId, BreakGlassPermit, BreakGlassState,
};
pub use effects::{
    ActionContract, AuthorizedEffect, EffectAuthorizer, EffectOutcome, EffectReceipt,
    ProposedEffect,
};
pub use grants::{
    AuthoritySet, CapabilityGrant, CapabilityIntroduction, EffectiveCapabilityPath,
    EffectiveCapabilitySnapshot, GrantGraph, GrantId, GrantStatus, IntroductionId,
    IntroductionStatus, LogicalTime, PrincipalRef, ReceiptObligation, SnapshotId,
};
pub use leases::{ActionLease, CapabilityToken, LeaseId, TokenId};

use std::{error::Error, fmt};

/// A fail-closed pure authority validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityError {
    InvalidField(&'static str),
    DuplicateGrant(GrantId),
    MissingParent(GrantId),
    GrantCycle(GrantId),
    GrantNotNarrower(GrantId),
    GrantInactive(GrantId),
    GrantRevoked(GrantId),
    NoEffectivePath,
    SupportingPathMissing,
    FenceMismatch,
    EpochMismatch,
    Expired,
    Revoked,
    Consumed,
    UseBudgetExhausted,
    UnauthorizedOperation,
    UnauthorizedResource,
    EffectCeilingExceeded,
    IdentityConflict,
    InvalidLifecycleTransition,
    ReceiptMismatch,
    P07Unavailable,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(formatter, "invalid authority field: {field}"),
            Self::DuplicateGrant(id) => write!(formatter, "duplicate grant: {id}"),
            Self::MissingParent(id) => write!(formatter, "missing parent grant: {id}"),
            Self::GrantCycle(id) => write!(formatter, "grant cycle includes: {id}"),
            Self::GrantNotNarrower(id) => {
                write!(formatter, "grant is not a strict narrowing: {id}")
            }
            Self::GrantInactive(id) => write!(formatter, "grant is not active: {id}"),
            Self::GrantRevoked(id) => write!(formatter, "grant is revoked: {id}"),
            Self::NoEffectivePath => formatter.write_str("no effective authority path"),
            Self::SupportingPathMissing => formatter.write_str("supporting grant path is missing"),
            Self::FenceMismatch => formatter.write_str("StateFence mismatch"),
            Self::EpochMismatch => formatter.write_str("AuthorityEpoch mismatch"),
            Self::Expired => formatter.write_str("authority expired"),
            Self::Revoked => formatter.write_str("authority revoked"),
            Self::Consumed => formatter.write_str("one-shot authority already consumed"),
            Self::UseBudgetExhausted => formatter.write_str("authority use budget exhausted"),
            Self::UnauthorizedOperation => formatter.write_str("operation is not authorized"),
            Self::UnauthorizedResource => formatter.write_str("resource is not authorized"),
            Self::EffectCeilingExceeded => formatter.write_str("effect ceiling exceeded"),
            Self::IdentityConflict => formatter.write_str("idempotency identity conflict"),
            Self::InvalidLifecycleTransition => formatter.write_str("invalid lifecycle transition"),
            Self::ReceiptMismatch => {
                formatter.write_str("effect receipt does not match authorization")
            }
            Self::P07Unavailable => formatter.write_str("P-07 activation port is unavailable"),
        }
    }
}

impl Error for AuthorityError {}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), AuthorityError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(AuthorityError::InvalidField(field));
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), AuthorityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(AuthorityError::InvalidField(field));
    }
    Ok(())
}
