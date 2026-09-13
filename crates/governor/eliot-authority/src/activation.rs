use std::{error::Error, fmt};

use eliot_receipts::AuthorityBinding;
use eliot_runtime_contracts::{AuthorityActivationReceipt, AuthorityRevocationReceipt};

use crate::{GrantId, IntroductionId, SnapshotId};

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
    UnknownOutcome { snapshot_id: SnapshotId },
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
}
