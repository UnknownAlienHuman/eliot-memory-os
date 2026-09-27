use std::{error::Error, fmt};

use eliot_receipts::AuthorityBinding;
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};
use serde::{Deserialize, Serialize};

use crate::{
    GrantId, IntroductionId, RootTransitionActivationReceipt, RootTransitionActivationRequest,
    SnapshotId,
};

/// Typed G-01 request presented to the P-07 activation boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantActivationRequest {
    pub grant_id: GrantId,
    pub snapshot_id: SnapshotId,
    pub binding: AuthorityBinding,
}

/// Typed G-01 request presented to the P-07 revocation boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRevocationRequest {
    pub grant_id: GrantId,
    pub snapshot_id: SnapshotId,
    pub binding: AuthorityBinding,
}

/// Typed G-01 introduction request presented to P-07 for activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntroductionActivationRequest {
    pub introduction_id: IntroductionId,
    pub snapshot_id: SnapshotId,
    pub binding: AuthorityBinding,
}

/// Typed G-01 introduction request presented to P-07 for fencing/revocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntroductionRevocationRequest {
    pub introduction_id: IntroductionId,
    pub snapshot_id: SnapshotId,
    pub binding: AuthorityBinding,
}

/// Closed, typed I7.20 directive carried by a refused P-07 presentation.
///
/// I7.20 requires every non-success answer to carry the applicable Recovery or
/// Conflict Directive beside its disposition and exact reason code. A directive
/// is a closed typed value and never prose: a human-readable message may
/// accompany it, but no message ever selects or alters one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum P07RefusalDirective {
    /// The presented binding or session subject contradicts itself and must be
    /// repaired before the operation is presented again.
    RepairPresentedBinding,
    /// The presented fence is not the current Kernel fence: fail closed and do
    /// not reuse it.
    StaleFenceFailClosed,
    /// The presented operation identity already committed different content;
    /// re-serve fresh state instead of retrying the same operation.
    ResubmitFromCurrentState,
    /// The commit outcome is unproven; reconcile the exact retained snapshot
    /// before any retry.
    ReconcileExactSnapshot,
    /// No admissible next action is derivable from the presentation; the owner
    /// decides.
    OwnerEscalation,
}

impl P07RefusalDirective {
    /// Stable wire value for this directive.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RepairPresentedBinding => "repair-presented-binding",
            Self::StaleFenceFailClosed => "stale-fence-fail-closed",
            Self::ResubmitFromCurrentState => "resubmit-from-current-state",
            Self::ReconcileExactSnapshot => "reconcile-exact-snapshot",
            Self::OwnerEscalation => "owner-escalation",
        }
    }

    /// Parses one directive wire value, failing closed on anything unrecognised
    /// so a new or misspelled value can never be read as a known directive.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "repair-presented-binding" => Some(Self::RepairPresentedBinding),
            "stale-fence-fail-closed" => Some(Self::StaleFenceFailClosed),
            "resubmit-from-current-state" => Some(Self::ResubmitFromCurrentState),
            "reconcile-exact-snapshot" => Some(Self::ReconcileExactSnapshot),
            "owner-escalation" => Some(Self::OwnerEscalation),
            _ => None,
        }
    }
}

/// Closed, typed I7.20 cause of a refused P-07 presentation.
///
/// Every variant is a fact the P-07 presentation path has already proven by a
/// comparison or a failed validation at that exact point. No variant names a
/// condition that was not observed, and none carries prose, a payload, or a
/// provider detail: this is the closed P-07 control vocabulary that the owner
/// of the wire projects onto the open I7.20 reason-code registry, so a refusal
/// that the presentation path *can* explain never has to arrive as a generic
/// code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum P07RefusalCause {
    /// The presented fence failed its own validation.
    StateFenceUnvalidated,
    /// The presented authority epoch disagrees with the presented fence it
    /// carries, so the presentation contradicts itself.
    AuthorityEpochDisagreesWithFence,
    /// The proven session facts could not be bound into the presented
    /// principal/session/scope subject.
    SessionSubjectUnbindable,
    /// The presented fence is not the currently active Kernel fence.
    StaleStateFence,
    /// The answered frame did not carry the receipt kind this operation must
    /// return.
    ResponseRouteMismatch,
    /// The refusal frame is not a shape the receiving side can classify, so no
    /// more specific cause is derivable from it.
    RefusalFrameIncompatible,
    /// Changed content was presented under an operation identity that already
    /// committed different content.
    OperationIdentityAlreadyCommitted,
    /// The commit outcome could not be established at the boundary.
    CommitOutcomeUnproven,
}

impl P07RefusalCause {
    /// Stable wire value for this cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StateFenceUnvalidated => "state-fence-unvalidated",
            Self::AuthorityEpochDisagreesWithFence => "authority-epoch-disagrees-with-fence",
            Self::SessionSubjectUnbindable => "session-subject-unbindable",
            Self::StaleStateFence => "stale-state-fence",
            Self::ResponseRouteMismatch => "response-route-mismatch",
            Self::RefusalFrameIncompatible => "refusal-frame-incompatible",
            Self::OperationIdentityAlreadyCommitted => "operation-identity-already-committed",
            Self::CommitOutcomeUnproven => "commit-outcome-unproven",
        }
    }

    /// Parses one cause wire value, failing closed on anything unrecognised so
    /// an unknown cause is never silently read as a known one.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "state-fence-unvalidated" => Some(Self::StateFenceUnvalidated),
            "authority-epoch-disagrees-with-fence" => Some(Self::AuthorityEpochDisagreesWithFence),
            "session-subject-unbindable" => Some(Self::SessionSubjectUnbindable),
            "stale-state-fence" => Some(Self::StaleStateFence),
            "response-route-mismatch" => Some(Self::ResponseRouteMismatch),
            "refusal-frame-incompatible" => Some(Self::RefusalFrameIncompatible),
            "operation-identity-already-committed" => Some(Self::OperationIdentityAlreadyCommitted),
            "commit-outcome-unproven" => Some(Self::CommitOutcomeUnproven),
            _ => None,
        }
    }
}

/// Errors at the typed P-07 port.
///
/// `Unavailable` stays first for wire compatibility with the pure G-01
/// fragment. `NotAdmitted` reports a Kernel-side admission refusal (fenced or
/// epoch-gated authority, transport admission refusal, or a missing P-07
/// route — never a receipt). `InvalidBinding` reports a caller-side binding
/// that is internally inconsistent (owner/fence/epoch/receipt mismatch).
/// `UnknownOutcome` reports a possible commit with a lost acknowledgement and
/// must never be collapsed to unavailable/non-executed: the exact request is
/// retained under its snapshot until exact reconciliation.
///
/// `Refused` carries the exact cause the presentation path already proved for
/// a refusal that none of the variants above describes precisely. A variant is
/// used only when its own contract names the condition; a `Refused` cause is
/// never inferred from prose and never defaulted to a generic code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum P07PortError {
    Unavailable,
    NotAdmitted,
    InvalidBinding,
    /// Changed content was presented under an operation identity that already
    /// committed different content (issue #2962, step 6 / I5.27). The
    /// committed result is authoritative; the new content is refused, never
    /// merged and never re-applied under the same identity.
    IdentityConflict,
    UnknownOutcome {
        snapshot_id: SnapshotId,
    },
    /// A refusal whose exact I7.20 cause the presentation path has already
    /// proven, so the operator surface receives a typed failure instead of one
    /// generic code standing in for several distinguishable decisions.
    Refused {
        cause: P07RefusalCause,
    },
}

impl fmt::Display for P07PortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter
                .write_str("P-07 authority activation is unavailable in the pure G-01 fragment"),
            Self::NotAdmitted => {
                formatter.write_str("P-07 authority refused the presented activation")
            }
            Self::InvalidBinding => {
                formatter.write_str("P-07 activation binding is internally inconsistent")
            }
            Self::IdentityConflict => formatter.write_str(
                "P-07 activation identity already committed different content for this request",
            ),
            Self::UnknownOutcome { snapshot_id } => write!(
                formatter,
                "P-07 activation outcome is unknown for snapshot {snapshot_id}; \
                 the exact request is retained for reconciliation"
            ),
            Self::Refused { cause } => {
                write!(formatter, "P-07 activation refused ({})", cause.as_str())
            }
        }
    }
}

impl Error for P07PortError {}

/// P-07 owns activation/revocation. Implementations live outside this crate.
pub trait P07AuthorityPort: Send + Sync {
    fn activate_grant(
        &self,
        request: &GrantActivationRequest,
    ) -> Result<AuthorityActivationReceipt, P07PortError>;

    fn revoke_grant(
        &self,
        request: &GrantRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, P07PortError>;

    fn activate_introduction(
        &self,
        request: &IntroductionActivationRequest,
    ) -> Result<AuthorityActivationReceipt, P07PortError>;

    fn revoke_introduction(
        &self,
        request: &IntroductionRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, P07PortError>;

    /// Mechanically activates ONE authenticated root crossing (issue #2962,
    /// step 4).
    ///
    /// This is a distinct operation from ordinary grant activation, not an
    /// overload of it: the request carries the full root-transition operation
    /// binding (operation identity, idempotency key, canonical request digest,
    /// both grant identities AND their immutable commitments, both roots, the
    /// graph snapshot/revisions, the full binding, policy revision, deadline,
    /// effect ceiling, semantic decision reference, and the authenticated
    /// subject), and the reply is a transition-specific receipt that commits
    /// every one of those fields together with the Kernel activation identity
    /// and its durable ORS record.
    ///
    /// Implementations must return the SAME receipt for exact replay of
    /// identical bytes under one operation identity, and must refuse changed
    /// content under that identity with
    /// [`P07PortError::IdentityConflict`]. A possible commit with a lost
    /// acknowledgement is `UnknownOutcome` carrying the exact
    /// `graph_snapshot_id`; it is never re-presented under a fresh identity.
    fn activate_root_transition(
        &self,
        request: &RootTransitionActivationRequest,
    ) -> Result<RootTransitionActivationReceipt, P07PortError>;
}

/// Deterministic no-authority port used by pure tests and pre-P-07 profiles.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableP07AuthorityPort;

impl P07AuthorityPort for UnavailableP07AuthorityPort {
    fn activate_grant(
        &self,
        _request: &GrantActivationRequest,
    ) -> Result<AuthorityActivationReceipt, P07PortError> {
        Err(P07PortError::Unavailable)
    }

    fn revoke_grant(
        &self,
        _request: &GrantRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, P07PortError> {
        Err(P07PortError::Unavailable)
    }

    fn activate_introduction(
        &self,
        _request: &IntroductionActivationRequest,
    ) -> Result<AuthorityActivationReceipt, P07PortError> {
        Err(P07PortError::Unavailable)
    }

    fn revoke_introduction(
        &self,
        _request: &IntroductionRevocationRequest,
    ) -> Result<AuthorityRevocationReceipt, P07PortError> {
        Err(P07PortError::Unavailable)
    }

    fn activate_root_transition(
        &self,
        _request: &RootTransitionActivationRequest,
    ) -> Result<RootTransitionActivationReceipt, P07PortError> {
        Err(P07PortError::Unavailable)
    }
}
