use std::{error::Error, fmt};

use eliot_receipts::AuthorityBinding;
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};

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
