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
mod mechanical_subset;
mod quarantine_evidence;
mod revocation_history;
mod root_transition;

pub use root_transition::{
    AdmittedRootTransition, AdmittedRootTransitionRecord, ROOT_TRANSITION_OPERATION_KIND,
    ROOT_TRANSITION_RECEIPT_SCHEMA, ROOT_TRANSITION_RECEIPT_VERSION,
    RootTransitionActivationReceipt, RootTransitionActivationRequest, RootTransitionDisposition,
    RootTransitionRecord, grant_commitment,
};

pub use activation::{
    GrantActivationRequest, GrantRevocationRequest, IntroductionActivationRequest,
    IntroductionRevocationRequest, P07AuthorityPort, P07PortError, P07RefusalCause,
    P07RefusalDirective, UnavailableP07AuthorityPort,
};
pub use break_glass::{
    BreakGlassAuthorization, BreakGlassAuthorizationId, BreakGlassPermit, BreakGlassState,
};
pub use effects::{
    ActionContract, AuthorizedEffect, AuthorizedEffectRecoveryRecord, CompiledEffect,
    ContestedEffectAnnotation, DependentEffectState, EFFECT_AUTHORIZER_RECOVERY_SCHEMA,
    EFFECT_AUTHORIZER_RECOVERY_VERSION, EffectAuthorizer, EffectAuthorizerRecoverySnapshot,
    EffectOutcome, EffectReceipt, ImpactClass, ProposedEffect, SealedEffectDispatch,
};
pub use grants::{
    AuthoritySet, AuthorizedCrossRootMember, CapabilityGrant, CapabilityIntroduction,
    CrossRootRelationDisposition, EffectiveCapabilityPath, EffectiveCapabilitySnapshot,
    GRANT_GRAPH_RECOVERY_SCHEMA, GRANT_GRAPH_RECOVERY_VERSION, GrantClosureDelegation,
    GrantClosureMemberRef, GrantGraph, GrantGraphRecoverySnapshot, GrantId, GrantRecoveryRecord,
    GrantStatus, IntroductionId, IntroductionStatus, LEGACY_GRANT_GRAPH_RECOVERY_VERSION,
    LogicalTime, PrincipalRef, QuarantinedCrossRootRecord, QuarantinedCrossRootRelation,
    QuarantinedFrontierMember, ReceiptObligation, RevocationClosureState, RevocationClosureVerdict,
    SnapshotId,
};
pub use leases::{ActionLease, CapabilityToken, LeaseId, TokenId};
pub use mechanical_subset::{
    ApprovalReference, AuthorityUseSite, CanonicalSourceCommitment,
    MECHANICAL_SUBSET_DIGEST_DOMAIN, MECHANICAL_SUBSET_SCHEMA, MECHANICAL_SUBSET_VERSION,
    MechanicalAdmission, MechanicalAuthoritySubset, MechanicalSubsetConstraints,
};
pub use quarantine_evidence::{
    CrossRootQuarantineEvidence, QUARANTINE_EVIDENCE_OPERATION_KIND, QUARANTINE_EVIDENCE_SCHEMA,
    QUARANTINE_EVIDENCE_VERSION, QuarantineDisposition, QuarantineEnforcementRef,
    QuarantineEvidenceStatus, UnresolvedEffectDisposition, VerifiedQuarantineBinding,
};
pub use revocation_history::{
    AuthorityRevocationClosureEvidence, GrantRestoreOutcome, REVOCATION_HISTORY_EVIDENCE_VERSION,
    RevocationEvidenceDisposition, RevocationHistoryError, RevocationHistoryEvidence,
    SuppressedGrant, SuppressionCause, ValidatedRevocationClosure,
};

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
    /// The use site names a data/observation class outside the committed
    /// ceiling set. Distinct from an unauthorized operation or resource so a
    /// data-class refusal is never reported as a missing route.
    UnauthorizedDataClass,
    EffectCeilingExceeded,
    IdentityConflict,
    /// Admitted transition evidence no longer matches CURRENT owner state, or
    /// a transition operation was presented without a committed mechanical
    /// disposition. The named field says which readback clause refused, so a
    /// stale crossing is distinguishable from a malformed one.
    StaleTransitionEvidence(&'static str),
    /// The mechanical owner answered for this exact operation identity that
    /// the commit outcome is UNKNOWN: the operation may or may not have
    /// committed, and the acknowledgement was lost.
    ///
    /// This is deliberately not [`Self::StaleTransitionEvidence`]. An unknown
    /// outcome is not stale evidence, and reporting it as such invites the
    /// one action the contract forbids — discarding the operation and
    /// presenting the work again under a FRESH identity, which cannot
    /// conflict with the first attempt and can double-apply it. The outcome
    /// stays unknown here, the operation is retained under its original
    /// operation identity and idempotency key, and the way out is exact
    /// reconciliation against the owner's own record of that identity.
    UnreconciledTransitionEvidence(&'static str),
    /// Quarantine evidence no longer matches CURRENT owner state: revoked,
    /// stale, unreadable, or missing its durable receipt readback. The named
    /// field says which readback clause refused, so a stale quarantine is
    /// distinguishable from a malformed one.
    StaleQuarantineEvidence(&'static str),
    /// A stored effect authorization no longer matches the dispatch presented
    /// at the effect boundary, or its current standing was withdrawn. The
    /// named field says which join refused, so an absent or substituted
    /// authorization is distinguishable from a contested one.
    StaleEffectAuthority(&'static str),
    InvalidLifecycleTransition,
    ReceiptMismatch,
    P07Unavailable,
    /// The bounded influence evaluator refused a typed request, snapshot, or
    /// continuation; the cause is preserved for recovery diagnostics.
    BoundedRevocation(eliot_influence::InfluenceError),
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
            Self::UnauthorizedDataClass => formatter.write_str("data class is not authorized"),
            Self::EffectCeilingExceeded => formatter.write_str("effect ceiling exceeded"),
            Self::IdentityConflict => formatter.write_str("idempotency identity conflict"),
            Self::StaleTransitionEvidence(field) => write!(
                formatter,
                "stale or uncommitted root-transition evidence: {field}"
            ),
            Self::UnreconciledTransitionEvidence(field) => write!(
                formatter,
                "root-transition commit outcome is unknown and unproven: {field}; \
                 reconcile this exact operation identity, never re-present a fresh one"
            ),
            Self::StaleQuarantineEvidence(field) => {
                write!(formatter, "stale or unproven quarantine evidence: {field}")
            }
            Self::StaleEffectAuthority(field) => {
                write!(formatter, "stale effect authority: {field}")
            }
            Self::InvalidLifecycleTransition => formatter.write_str("invalid lifecycle transition"),
            Self::ReceiptMismatch => {
                formatter.write_str("effect receipt does not match authorization")
            }
            Self::P07Unavailable => formatter.write_str("P-07 activation port is unavailable"),
            Self::BoundedRevocation(error) => {
                write!(formatter, "bounded revocation refused: {error}")
            }
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
