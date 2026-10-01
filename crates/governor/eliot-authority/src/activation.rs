use std::{error::Error, fmt};

use eliot_receipts::{AuthorityBinding, GrantClosureReceipt, GrantClosureState, ReceiptIdentity};
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityError, GrantId, IntroductionId, RevocationOperationIdentity,
    RootTransitionActivationReceipt, RootTransitionActivationRequest, SnapshotId, validate_text,
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
    /// The presented authority epoch does not match the current Kernel epoch;
    /// fail closed and re-present under the current epoch and lineage.
    RefreshAuthorityEpoch,
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
            Self::RefreshAuthorityEpoch => "refresh-authority-epoch",
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
            "refresh-authority-epoch" => Some(Self::RefreshAuthorityEpoch),
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
    /// The presented authority epoch is from the active lineage but does not
    /// match the current Kernel epoch.
    StaleAuthorityEpoch,
    /// The presented authority epoch belongs to a different lineage from the
    /// current Kernel epoch; the tuples are unrelated and must not be ordered.
    CrossLineageAuthorityEpoch,
    /// The presented authority-owner field failed its typed validation.
    InvalidOwnerField,
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
    /// The P-07 owner boundary required for grant or introduction lifecycle
    /// operations is not bound.
    P07OwnerUnavailable,
    /// The presented authority receipt expired before this operation.
    AuthorityReceiptExpired,
    /// The legacy control reserve could not admit the operation.
    ControlReserveExhausted,
    /// Normal-work admission capacity was exhausted.
    NormalCapacityExhausted,
    /// Protected control-reserve capacity was exhausted.
    ProtectedReserveExhausted,
    /// The emergency admission slot was unavailable.
    EmergencySlotUnavailable,
    /// The control guarantee required for this operation was lost.
    ControlGuaranteeLost,
    /// A required dependency was unavailable.
    DependencyUnavailable,
    /// The recovery owner or recovery view was unavailable.
    RecoveryUnavailable,
    /// The durable recovery-state operation failed.
    RecoveryStateFailure,
}

impl P07RefusalCause {
    /// Stable wire value for this cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StateFenceUnvalidated => "state-fence-unvalidated",
            Self::AuthorityEpochDisagreesWithFence => "authority-epoch-disagrees-with-fence",
            Self::StaleAuthorityEpoch => "stale-authority-epoch",
            Self::CrossLineageAuthorityEpoch => "cross-lineage-authority-epoch",
            Self::InvalidOwnerField => "invalid-owner-field",
            Self::SessionSubjectUnbindable => "session-subject-unbindable",
            Self::StaleStateFence => "stale-state-fence",
            Self::ResponseRouteMismatch => "response-route-mismatch",
            Self::RefusalFrameIncompatible => "refusal-frame-incompatible",
            Self::OperationIdentityAlreadyCommitted => "operation-identity-already-committed",
            Self::CommitOutcomeUnproven => "commit-outcome-unproven",
            Self::P07OwnerUnavailable => "p07-owner-unavailable",
            Self::AuthorityReceiptExpired => "authority-receipt-expired",
            Self::ControlReserveExhausted => "control-reserve-exhausted",
            Self::NormalCapacityExhausted => "normal-capacity-exhausted",
            Self::ProtectedReserveExhausted => "protected-reserve-exhausted",
            Self::EmergencySlotUnavailable => "emergency-slot-unavailable",
            Self::ControlGuaranteeLost => "control-guarantee-lost",
            Self::DependencyUnavailable => "dependency-unavailable",
            Self::RecoveryUnavailable => "recovery-unavailable",
            Self::RecoveryStateFailure => "recovery-state-failure",
        }
    }

    /// Parses one cause wire value, failing closed on anything unrecognised so
    /// an unknown cause is never silently read as a known one.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "state-fence-unvalidated" => Some(Self::StateFenceUnvalidated),
            "authority-epoch-disagrees-with-fence" => Some(Self::AuthorityEpochDisagreesWithFence),
            "stale-authority-epoch" => Some(Self::StaleAuthorityEpoch),
            "cross-lineage-authority-epoch" => Some(Self::CrossLineageAuthorityEpoch),
            "invalid-owner-field" => Some(Self::InvalidOwnerField),
            "session-subject-unbindable" => Some(Self::SessionSubjectUnbindable),
            "stale-state-fence" => Some(Self::StaleStateFence),
            "response-route-mismatch" => Some(Self::ResponseRouteMismatch),
            "refusal-frame-incompatible" => Some(Self::RefusalFrameIncompatible),
            "operation-identity-already-committed" => Some(Self::OperationIdentityAlreadyCommitted),
            "commit-outcome-unproven" => Some(Self::CommitOutcomeUnproven),
            "p07-owner-unavailable" => Some(Self::P07OwnerUnavailable),
            "authority-receipt-expired" => Some(Self::AuthorityReceiptExpired),
            "control-reserve-exhausted" => Some(Self::ControlReserveExhausted),
            "normal-capacity-exhausted" => Some(Self::NormalCapacityExhausted),
            "protected-reserve-exhausted" => Some(Self::ProtectedReserveExhausted),
            "emergency-slot-unavailable" => Some(Self::EmergencySlotUnavailable),
            "control-guarantee-lost" => Some(Self::ControlGuaranteeLost),
            "dependency-unavailable" => Some(Self::DependencyUnavailable),
            "recovery-unavailable" => Some(Self::RecoveryUnavailable),
            "recovery-state-failure" => Some(Self::RecoveryStateFailure),
            _ => None,
        }
    }
}

/// Errors at the typed P-07 port.
///
/// `Unavailable` stays first for wire compatibility with the pure G-01
/// fragment. `NotAdmitted` reports a transport admission refusal or missing
/// P-07 route. Known Kernel authority, expiry, capacity, dependency, and
/// recovery failures use `Refused` with their distinct proven cause. It never
/// means a receipt. `InvalidBinding` reports a caller-side binding that is
/// internally inconsistent (owner/fence/epoch/receipt mismatch).
/// `UnknownOutcome` reports a possible commit with a lost acknowledgement and
/// must never be collapsed to unavailable/non-executed: the exact request is
/// retained under its snapshot until exact reconciliation.
///
/// `Refused` carries the exact cause already proved at the P-07 presentation
/// boundary. A cause is never inferred from prose or defaulted to a generic
/// code.
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

/// Authenticated Human/Policy maintenance decision owning one grant revocation
/// (issue #2100, audit 5924750035 item 1).
///
/// The target grant, owner snapshot, `AuthorityBinding` (State Fence, epoch,
/// owner, ceilings) and admitted revocation operation identity arrive from the
/// authenticated maintenance-request ingress (or its canonical admitted
/// equivalent). They are never derived from the restored graph, a diagnostic
/// row, or a pending-scan candidate: a recovered snapshot already carries
/// fenced grants as `Revoked`, so deriving a request from it would either
/// fabricate a decision or re-present a fenced grant as a fresh revocation.
///
/// Every coordinate is validated here: blank identities refuse, a binding
/// whose fence disagrees with its own epoch refuses, and a blank authority
/// owner refuses. The admitted operation identity arrives already refused by
/// [`RevocationOperationIdentity::admit`] when incomplete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedMaintenanceRevocation {
    request: GrantRevocationRequest,
    operation: RevocationOperationIdentity,
}

impl AdmittedMaintenanceRevocation {
    /// Admits one maintenance revocation decision into its exact
    /// [`GrantRevocationRequest`] plus operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for a blank target/snapshot identity, a
    /// binding whose State Fence disagrees with its own authority epoch, or a
    /// blank authority owner.
    pub fn admit(
        target_grant_id: &str,
        snapshot_id: &str,
        binding: AuthorityBinding,
        operation: RevocationOperationIdentity,
    ) -> Result<Self, AuthorityError> {
        let grant_id = GrantId::new(target_grant_id)?;
        let snapshot = SnapshotId::new(snapshot_id)?;
        if !binding
            .state_fence
            .authority_epoch
            .is_same_authority(&binding.authority_epoch)
        {
            return Err(AuthorityError::EpochMismatch);
        }
        validate_text(
            binding.authority_owner.as_str(),
            "maintenance_revocation.authority_owner",
        )?;
        Ok(Self {
            request: GrantRevocationRequest {
                grant_id,
                snapshot_id: snapshot,
                binding,
            },
            operation,
        })
    }

    /// Returns the exact admitted revocation request.
    #[must_use]
    pub const fn request(&self) -> &GrantRevocationRequest {
        &self.request
    }

    /// Returns the exact admitted revocation operation identity.
    #[must_use]
    pub const fn operation(&self) -> &RevocationOperationIdentity {
        &self.operation
    }
}

/// Proves one already committed closure binds the exact re-admitted request
/// (issue #2100, audit 5924750035 items 3 and 6).
///
/// The committed target, snapshot, State Fence and authority epoch must equal
/// the re-admitted decision's own coordinates, and both the closure and its
/// authority receipt must be `Revoked`. A diagnostic tick alone never satisfies
/// this: only the owner's re-admitted decision plus the owner's committed
/// bytes together authorize the second phase.
///
/// # Errors
///
/// Returns [`AuthorityError`] for a target/snapshot/fence/epoch disagreement
/// or a non-revoked closure. The failure is typed so a changed request under
/// one operation identity conflicts instead of reconciling.
pub fn check_resume_closure_binds_request(
    request: &GrantRevocationRequest,
    closure: &GrantClosureReceipt,
) -> Result<(), AuthorityError> {
    if closure.state != GrantClosureState::Revoked
        || closure.authority_receipt.state != GrantClosureState::Revoked
    {
        return Err(AuthorityError::InvalidField(
            "maintenance_resume.closure_state",
        ));
    }
    if closure.declaration.target_grant_id != request.grant_id.as_str() {
        return Err(AuthorityError::InvalidField(
            "maintenance_resume.target_grant_id",
        ));
    }
    if closure.authority_receipt.snapshot_id != request.snapshot_id.as_str() {
        return Err(AuthorityError::InvalidField(
            "maintenance_resume.snapshot_id",
        ));
    }
    if closure.authority.state_fence != request.binding.state_fence {
        return Err(AuthorityError::FenceMismatch);
    }
    if !closure
        .authority_receipt
        .authority_epoch
        .is_same_authority(&request.binding.state_fence.authority_epoch)
    {
        return Err(AuthorityError::EpochMismatch);
    }
    Ok(())
}

/// Proves one linked second phase binds the original first-phase bytes plus
/// the Store-issued receipt identity by content (issue #2100, audit 5924750035
/// item 5).
///
/// The linked closure's operation identity and whole declaration must equal
/// the committed closure's, and the linked receipt must equal the presented
/// `ReceiptIdentity`. Existence or shape agreement is never enough.
///
/// # Errors
///
/// Returns [`AuthorityError::ReceiptMismatch`] for any content disagreement.
pub fn check_second_phase_link_binds_closure(
    closure: &GrantClosureReceipt,
    receipt_identity: &ReceiptIdentity,
    linked_closure: &GrantClosureReceipt,
    linked_receipt: &ReceiptIdentity,
) -> Result<(), AuthorityError> {
    if linked_closure.operation_id != closure.operation_id
        || linked_closure.declaration != closure.declaration
        || linked_receipt != receipt_identity
    {
        return Err(AuthorityError::ReceiptMismatch);
    }
    Ok(())
}
