//! Authenticated Host→Kernel restore-destination delivery consumed by the
//! restore adapter (issue #962).
//!
//! Architecture: A12.2 Principal, Session, and Visibility (identity is
//! established by the installation boundary: the OS-authenticated Host
//! service peer plus digest-bound request/response correlation, never a
//! self-declared string); A13.2 Kernel and Failure Domains; I1.8 Exact
//! Ownership and Call Paths (the Kernel requests, the Host issues, the
//! adapter verifies — no component invents, authorizes, and commits
//! alone); I5.27 canonical operation identity (deterministic digest-bound
//! request identity per target/transaction/source; issuance is effect-free
//! read-only so a fresh request duplicates nothing); I14.21 unknown-commit
//! recovery (post-send uncertainty stays `Unknown` for a fresh retry,
//! never success).
//!
//! What this file owns: the Kernel-side delivery call that replaces the
//! retired plaintext file handoff. It builds the digest-bound typed
//! request, exchanges it through the endpoint client (existing pipe,
//! existing frames, OS peer authentication of the Host server), checks
//! the receipt echoes the requested descriptors, and assembles the
//! canonical authorization bytes the adapter verifies, journals, and pins
//! before any effect. The delivered bytes carry live owner facts —
//! installation, generation, roots, revision — observed by the Host at
//! issuance time for this exact request: freshness comes from per-call
//! issuance plus request/response correlation, and current-root binding
//! from the adapter's containment check against the live work root.
//!
//! Capability cell: restore-destination delivery consumption.
//! Forbidden authority: no pipe/ACL/authentication redesign, no new wire
//! family, no credential handling, no semantic interpretation (the adapter
//! owns verification), no invented installation identity (the Kernel
//! asserts the coordinator-supplied source; the Host verifies it against
//! its live epoch and the OS peer proves which service answered).

use eliot_host_control_endpoint::backup::{
    HostRestoreDestinationClient, RestoreDestinationDeliveryError,
};
use eliot_host_control_endpoint::{
    HostRestoreDestinationReceipt, HostRestoreDestinationRuntimeRequest, HostRuntimeControlRequest,
};
use eliot_platform::PlatformHandle;

/// Failure of one Kernel-side delivery call. Transport/peer/framing
/// failures and Host `Unknown` answers fail closed; validation mismatches
/// refuse without retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostDeliveryError {
    /// Pipe, peer-authentication, or framing failure.
    Transport(String),
    /// The channel refused or the receipt does not bind the request.
    Rejected(String),
    /// The Host answered `Unknown`: issuance outcome undecided. Retry with
    /// a fresh admitted request; never treat as success.
    Unknown {
        /// Opaque owner pending reference binding the undecided request.
        pending_ref: String,
    },
}

impl std::fmt::Display for HostDeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "host delivery failed: {detail}"),
            Self::Rejected(detail) => write!(f, "host delivery refused: {detail}"),
            Self::Unknown { pending_ref } => {
                write!(f, "host delivery outcome unknown: {pending_ref}")
            }
        }
    }
}

impl From<RestoreDestinationDeliveryError> for HostDeliveryError {
    fn from(error: RestoreDestinationDeliveryError) -> Self {
        match error {
            RestoreDestinationDeliveryError::Transport(detail) => Self::Transport(detail),
            RestoreDestinationDeliveryError::Rejected(detail) => Self::Rejected(detail),
            RestoreDestinationDeliveryError::Unknown { pending_ref } => {
                Self::Unknown { pending_ref }
            }
        }
    }
}

fn handle(value: &str, field: &'static str) -> Result<PlatformHandle, HostDeliveryError> {
    PlatformHandle::new(value.to_owned())
        .map_err(|_| HostDeliveryError::Rejected(format!("delivery descriptor {field} is invalid")))
}

/// Builds the deterministic digest-bound delivery request for one
/// target/transaction/source triple. The request identity is a pure
/// function of the descriptors (precedent: `host-owned-scm-store-recovery`
/// requests): same descriptors, same identity — safe because issuance is
/// effect-free read-only — while every call still receives live owner
/// facts correlated to its exact digests.
pub fn delivery_request(
    target_id: &str,
    transaction_id: &str,
    source_installation_id: &str,
) -> Result<HostRuntimeControlRequest, HostDeliveryError> {
    use eliot_contracts::sha256_hex;
    let input = HostRestoreDestinationRuntimeRequest {
        target_id: handle(target_id, "target_id")?,
        transaction_id: handle(transaction_id, "transaction_id")?,
        source_installation_id: handle(source_installation_id, "source_installation_id")?,
    };
    let identity = sha256_hex(
        format!("restore-destination:{target_id}:{transaction_id}:{source_installation_id}")
            .as_bytes(),
    );
    let request_id = handle(
        &format!("restore-destination:{identity}"),
        "request_id",
    )?;
    HostRuntimeControlRequest::new_restore_destination(request_id, input)
        .map_err(HostDeliveryError::Rejected)
}

/// Fetches one Host-issued destination authorization over the
/// authenticated Host pipe for the exact descriptors.
pub async fn fetch_authorization(
    target_id: &str,
    transaction_id: &str,
    source_installation_id: &str,
) -> Result<HostRestoreDestinationReceipt, HostDeliveryError> {
    let request = delivery_request(target_id, transaction_id, source_installation_id)?;
    HostRestoreDestinationClient::exchange(&request)
        .await
        .map_err(HostDeliveryError::from)
}

/// Assembles the canonical authorization bytes from a delivered receipt
/// after echo-checking every requested descriptor. The bytes feed the
/// existing adapter verifier unchanged: field names and value domains are
/// identical to the Host owner binding, so the verifier, journal, pin,
/// and continuity logic all apply to delivered bytes exactly as they did
/// to hint bytes.
pub fn authorization_bytes(
    receipt: &HostRestoreDestinationReceipt,
    target_id: &str,
    transaction_id: &str,
    source_installation_id: &str,
) -> Result<Vec<u8>, HostDeliveryError> {
    if receipt.target_id.as_str() != target_id
        || receipt.transaction_id.as_str() != transaction_id
        || receipt.source_installation_id.as_str() != source_installation_id
    {
        return Err(HostDeliveryError::Rejected(
            "delivered receipt does not echo the requested descriptors".to_owned(),
        ));
    }
    let value = serde_json::json!({
        "wire": receipt.wire.as_str(),
        "issuer": receipt.issuer.as_str(),
        "source_installation_id": receipt.source_installation_id.as_str(),
        "target_id": receipt.target_id.as_str(),
        "transaction_id": receipt.transaction_id.as_str(),
        "manifest_digest": receipt.manifest_digest.as_str(),
        "roots_digest": receipt.roots_digest.as_str(),
        "registry_revision": receipt.registry_revision,
        "kernel_work_root": receipt.kernel_work_root.as_str(),
        "approved_generation": receipt.approved_generation.as_str(),
    });
    serde_json::to_vec(&value).map_err(|_| {
        HostDeliveryError::Rejected("delivered receipt could not be encoded".to_owned())
    })
}
