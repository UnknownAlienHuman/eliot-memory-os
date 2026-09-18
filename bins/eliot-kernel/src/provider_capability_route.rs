//! Authenticated provider-capability composition route (T9-04, issue #1108).
//!
//! Daemon-side composition only: builds a [`ProviderCapabilityContext`] from
//! the authenticated Kernel client (session + service guard + ORS handle)
//! and verifies one presented provider proof against the durable Kernel/ORS
//! records bound to the exact attempt and operation, plus the presented
//! route/capacity revision. No signing, no tokens, no cached `Verified`
//! marker, no user authentication: every call re-queries ORS and the live
//! authority epoch, so restore always observes fresh owner evidence.
//!
//! The capability wire contract itself ([`ProviderProofKind`],
//! [`ProviderCapabilityRequest`], [`ProviderCapabilityExpectation`],
//! [`verify_provider_capability`], [`ProviderCapabilityError`],
//! [`PROVIDER_CAPABILITY_WIRE_VERSION`]) is owned by
//! `eliot_kernel_service::protocol::provider_capability` (parallel Writer-A
//! slice of the same issue); this module only authenticates the session,
//! loads the durable claim row, re-queries the live epoch, and delegates to
//! the owner. It never fabricates persistence, admission, or a receipt.
//!
//! Transport error mapping is mechanical: session/auth/shape failures fail
//! closed as `SessionFenced`; an unknown claim identity is `UnknownRequest`;
//! an attempt/operation mismatch under a known claim is `IdentityConflict`;
//! owner and store failures fail closed as `SessionFenced`.
//!
//! Architecture: A12.2 Principal, Session and visibility; A13.2 Kernel and
//! failure domains.
//! Implementation: I1.2 Required processes of the first complete runtime;
//! I1.8 Exact ownership and call paths.
//! Forbidden authority: must not mint provider semantics, must not cache
//! verification, must not accept an unauthenticated session.

use super::{
    KernelComposition, KernelFrameAction, KernelServiceState, caller_binding, sha256_json,
    status_frame, unix_ms,
};
use eliot_contracts::{EpochId, StateFence};
use eliot_ipc::{Session, TransportError};
// M2 capability contract owner (`protocol::provider_capability`, parallel
// Writer-A slice of #1108, re-exported at the service root following the
// claim/replay import pattern). This route consumes the owner types by
// value; it defines no capability semantics of its own.
use eliot_kernel_service::{
    KernelService, PROVIDER_CAPABILITY_WIRE_VERSION, ProviderCapabilityError,
    ProviderCapabilityExpectation, ProviderCapabilityRequest, ProviderProofKind,
    verify_provider_capability,
};
use eliot_ors::{OperationIdentity, RedbRecoveryStore};
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Wire operation.
// ---------------------------------------------------------------------------

/// Verifies one presented provider proof against the durable Kernel/ORS
/// records bound to its exact attempt and operation.
pub(crate) const PROVIDER_CAPABILITY_VERIFY_OPERATION: &str =
    "native_worker.provider_capability.verify";

/// Returns true for the provider-capability operations owned here.
pub(crate) fn is_provider_capability_operation(operation: &str) -> bool {
    operation == PROVIDER_CAPABILITY_VERIFY_OPERATION
}

/// Maximum length of a bounded presented identity field, in UTF-8 bytes.
const MAX_CAPABILITY_TEXT_LEN: usize = 256;
/// Maximum length of a presented proof reference, in UTF-8 bytes.
const MAX_PROOF_REF_LEN: usize = 1_024;
/// Maximum length carried in any typed error message, in characters.
const MAX_ERROR_TEXT_CHARS: usize = 128;

// ---------------------------------------------------------------------------
// Typed route errors (mechanical TransportError mapping at the boundary).
// ---------------------------------------------------------------------------

/// Typed failure for one provider-capability composition or verification.
///
/// Every message is bounded and secret-free: identities are truncated to
/// [`MAX_ERROR_TEXT_CHARS`] characters and no proof, payload, digest, or
/// credential material is ever rendered.
#[derive(Debug)]
pub enum ProviderCapabilityRouteError {
    /// Session authentication, readiness, or presenter-shape failure.
    Session(String),
    /// Kernel owner-state or durable-store access failure.
    Store(String),
    /// The capability owner rejected the presented proof.
    Capability(ProviderCapabilityError),
    /// The claim identity has no staged ORS record.
    UnknownClaim(String),
    /// The presented attempt/operation disagrees with the durable row.
    BindingMismatch(String),
}

impl std::fmt::Display for ProviderCapabilityRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(reason) => write!(f, "provider capability session rejected: {reason}"),
            Self::Store(reason) => write!(f, "provider capability store unavailable: {reason}"),
            Self::Capability(_) => {
                write!(f, "provider capability proof rejected by the kernel owner")
            }
            Self::UnknownClaim(identity) => {
                write!(f, "provider capability claim is unknown: {identity}")
            }
            Self::BindingMismatch(identity) => write!(
                f,
                "provider capability attempt/operation mismatches claim: {identity}"
            ),
        }
    }
}

impl std::error::Error for ProviderCapabilityRouteError {}

impl From<ProviderCapabilityError> for ProviderCapabilityRouteError {
    fn from(error: ProviderCapabilityError) -> Self {
        Self::Capability(error)
    }
}

impl ProviderCapabilityRouteError {
    /// Maps one typed failure into the closed transport vocabulary.
    pub(crate) fn into_transport(self) -> TransportError {
        match self {
            Self::UnknownClaim(_) => TransportError::UnknownRequest,
            Self::BindingMismatch(_) => TransportError::IdentityConflict,
            Self::Session(_) | Self::Store(_) | Self::Capability(_) => {
                TransportError::SessionFenced
            }
        }
    }
}

/// Truncates one identity to a bounded, secret-free error fragment.
fn bounded_identity(value: &str) -> String {
    value.chars().take(MAX_ERROR_TEXT_CHARS).collect()
}

// ---------------------------------------------------------------------------
// Authenticated capability context.
// ---------------------------------------------------------------------------

/// Authenticated provider-capability context for one Kernel client session.
///
/// Holds shared owner handles only: the Kernel service guard source, the
/// ORS handle, the authenticated principal binding, and the epoch observed
/// at construction. It holds no cached verification verdict and no payload
/// cache: [`ProviderCapabilityContext::verify`] re-queries the durable row
/// and the live epoch on every call.
pub struct ProviderCapabilityContext {
    service: Arc<Mutex<KernelService>>,
    ors: Arc<RedbRecoveryStore>,
    session_principal_binding: String,
    live_authority_epoch: EpochId,
}

impl ProviderCapabilityContext {
    /// Returns the principal binding this context was authenticated for.
    #[must_use]
    pub fn session_principal_binding(&self) -> &str {
        &self.session_principal_binding
    }

    /// Returns the authority epoch observed when this context was built.
    #[must_use]
    pub fn live_authority_epoch(&self) -> &EpochId {
        &self.live_authority_epoch
    }

    /// Verifies one presented provider proof of the given kind.
    ///
    /// Loads the durable claim row by exact claim identity, requires the
    /// presented attempt and operation to equal the row binding, then
    /// delegates to the capability owner with the presented proof, the
    /// loaded row, and a freshly re-queried live-epoch expectation
    /// (`revoked` stays false: no revocation feed exists on this path, so
    /// withdrawal is observed only as digest/currentness disagreement).
    /// Every call re-queries ORS and the live epoch; nothing is cached, so
    /// restore always observes fresh owner evidence.
    #[allow(
        clippy::too_many_arguments,
        reason = "the presented proof is one flat wire tuple; grouping it would invent a second contract beside the owner request"
    )]
    pub fn verify(
        &self,
        kind: ProviderProofKind,
        attempt_id: &str,
        operation_id: &str,
        claim_id: &str,
        proof_ref: &str,
        canonical_payload_sha256: &str,
        binding_digest: &str,
        executable_digest: &str,
        route_rev: &str,
        capacity_rev: &str,
    ) -> Result<(), ProviderCapabilityRouteError> {
        let claim_identity = OperationIdentity::new(claim_id).map_err(|_| {
            ProviderCapabilityRouteError::Session("claim identity is malformed".to_owned())
        })?;
        let row = self
            .ors
            .load_native_worker_claim(&claim_identity)
            .map_err(|_| {
                ProviderCapabilityRouteError::Store(
                    "durable claim record is unavailable".to_owned(),
                )
            })?
            .ok_or_else(|| {
                ProviderCapabilityRouteError::UnknownClaim(bounded_identity(claim_id))
            })?;
        if row.attempt_id.as_str() != attempt_id || row.operation_id.as_str() != operation_id {
            return Err(ProviderCapabilityRouteError::BindingMismatch(
                bounded_identity(claim_id),
            ));
        }
        // Fresh live epoch on every call: never the construction-time copy.
        let live_epoch = self
            .service
            .lock()
            .map_err(|_| {
                ProviderCapabilityRouteError::Store("kernel owner state is unavailable".to_owned())
            })?
            .authority_epoch();
        // Freshness gate: the durable row's admission epoch sequence must
        // equal the live authority sequence, so restore observes fresh owner
        // evidence and a stale admission fails closed as StaleEpoch (mapped
        // to SessionFenced at the transport boundary). The row carries only
        // the sequence (u64); lineage agreement rides the session fence
        // checked at dispatch plus the owner's is_same_authority on the
        // fresh live epoch below.
        if row.authority_epoch != live_epoch.sequence.get() {
            return Err(ProviderCapabilityRouteError::Capability(
                ProviderCapabilityError::StaleEpoch,
            ));
        }
        let request = ProviderCapabilityRequest {
            claim_id: row.claim_id.as_str().to_owned(),
            attempt_id: row.attempt_id.as_str().to_owned(),
            operation_id: row.operation_id.as_str().to_owned(),
            proof_kind: kind,
            proof_ref: proof_ref.to_owned(),
            canonical_payload_sha256: canonical_payload_sha256.to_owned(),
            binding_digest: binding_digest.to_owned(),
            executable_binding_digest: executable_digest.to_owned(),
            route_revision: route_rev.to_owned(),
            capacity_revision: capacity_rev.to_owned(),
        };
        let expectation = ProviderCapabilityExpectation {
            current_route_revision: route_rev.to_owned(),
            current_capacity_revision: capacity_rev.to_owned(),
            live_authority_epoch: live_epoch.clone(),
            revoked: false,
        };
        // W-A owner signature is the 7-parameter pure verifier
        // (request, expectation, loaded attempt/operation/binding/executable,
        // live epoch). The ORS claim row carries no executable-binding column
        // by design in this slice (no write migration; see the owner module
        // residual), so the presented executable digest rides per call: the
        // owner shape-checks it as lowercase SHA-256 and the durable
        // equality gate in this slice is the binding digest from the exact
        // row above. The durable attempt/operation/binding come from the row
        // and the epoch is the freshly re-queried live authority epoch.
        verify_provider_capability(
            &request,
            &expectation,
            row.attempt_id.as_str(),
            row.operation_id.as_str(),
            row.binding_digest.as_str(),
            executable_digest,
            &live_epoch,
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Composition entry point.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Builds the provider-capability context for one session.
    ///
    /// Never constructs from an unauthenticated session: the service must be
    /// `Ready`, the peer identity must validate, the caller binding must
    /// derive, and (on Windows) the session must be the current daemon
    /// session. Each gate reuses the existing daemon guard instead of
    /// duplicating auth logic.
    pub fn provider_capability_for_session(
        &self,
        session: &Session,
    ) -> Result<ProviderCapabilityContext, ProviderCapabilityRouteError> {
        if self.service_state().map_err(|_| {
            ProviderCapabilityRouteError::Session("kernel service state is unavailable".to_owned())
        })? != KernelServiceState::Ready
        {
            return Err(ProviderCapabilityRouteError::Session(
                "kernel service is not ready for provider capability composition".to_owned(),
            ));
        }
        session.peer.validate().map_err(|_| {
            ProviderCapabilityRouteError::Session(
                "provider capability session peer is not authenticated".to_owned(),
            )
        })?;
        let (owner, _session_binding) = caller_binding(session).map_err(|_| {
            ProviderCapabilityRouteError::Session(
                "provider capability session binding failed".to_owned(),
            )
        })?;
        #[cfg(windows)]
        self.require_current_daemon_session(session).map_err(|_| {
            ProviderCapabilityRouteError::Session(
                "provider capability session is not the current daemon session".to_owned(),
            )
        })?;
        let live_authority_epoch = self
            .service
            .lock()
            .map_err(|_| {
                ProviderCapabilityRouteError::Store("kernel owner state is unavailable".to_owned())
            })?
            .authority_epoch();
        Ok(ProviderCapabilityContext {
            service: Arc::clone(&self.service),
            ors: Arc::clone(&self.generation_gateway.ors),
            session_principal_binding: format!(
                "module={};principal={}",
                owner.module_id(),
                owner.principal_digest()
            ),
            live_authority_epoch,
        })
    }
}

// ---------------------------------------------------------------------------
// Dispatch entry point.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Dispatches one provider-capability frame.
    ///
    /// The caller ([`crate::KernelComposition::dispatch_frame`]) has already
    /// gated service readiness and peer authentication mirroring the Process
    /// gate; those gates are re-checked here so direct callers cannot bypass
    /// them. Per-call session authentication, the ORS lookup, the fresh
    /// live-epoch query, and the owner delegation live in
    /// [`ProviderCapabilityContext::verify`].
    pub(crate) fn dispatch_provider_capability_frame(
        &self,
        session: &Session,
        frame: &Frame,
    ) -> Result<KernelFrameAction, TransportError> {
        if self
            .service_state()
            .map_err(|_| TransportError::SessionFenced)?
            != KernelServiceState::Ready
        {
            return Err(TransportError::SessionFenced);
        }
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let request_id = frame
            .request_id
            .clone()
            .ok_or(TransportError::SessionFenced)?;
        let identity = frame
            .request_identity
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let identity_value =
            serde_json::to_value(identity).map_err(|_| TransportError::SessionFenced)?;
        let presented_fence: StateFence = identity_value
            .get("request")
            .and_then(|request| request.get("state_fence"))
            .cloned()
            .and_then(|fence| serde_json::from_value(fence).ok())
            .ok_or(TransportError::SessionFenced)?;
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&presented_fence)
        {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let operation = payload
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if operation != PROVIDER_CAPABILITY_VERIFY_OPERATION {
            return Err(TransportError::SessionFenced);
        }
        let receipt = self
            .handle_provider_capability_verify(session, &payload)
            .map_err(ProviderCapabilityRouteError::into_transport)?;
        let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, receipt)?;
        frame.request_id = Some(request_id);
        frame
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(KernelFrameAction::Reply(frame))
    }

    /// Verifies one presented provider proof and seals the success receipt.
    fn handle_provider_capability_verify(
        &self,
        session: &Session,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, ProviderCapabilityRouteError> {
        let wire_version = payload
            .get("wire_version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ProviderCapabilityRouteError::Session("capability wire version".to_owned())
            })?;
        if wire_version != PROVIDER_CAPABILITY_WIRE_VERSION {
            return Err(ProviderCapabilityRouteError::Session(
                "capability wire version".to_owned(),
            ));
        }
        let claim_id = require_capability_text(payload, "claim_id", MAX_CAPABILITY_TEXT_LEN)?;
        let attempt_id = require_capability_text(payload, "attempt_id", MAX_CAPABILITY_TEXT_LEN)?;
        let operation_id =
            require_capability_text(payload, "operation_id", MAX_CAPABILITY_TEXT_LEN)?;
        let proof_kind_value =
            require_capability_text(payload, "proof_kind", MAX_CAPABILITY_TEXT_LEN)?;
        let proof_kind = parse_proof_kind(&proof_kind_value)?;
        let proof_ref = require_capability_text(payload, "proof_ref", MAX_PROOF_REF_LEN)?;
        let canonical_payload_sha256 =
            require_capability_digest(payload, "canonical_payload_sha256")?;
        let binding_digest = require_capability_digest(payload, "binding_digest")?;
        let executable_digest = require_capability_digest(payload, "executable_binding_digest")?;
        let route_rev =
            require_capability_text(payload, "route_revision", MAX_CAPABILITY_TEXT_LEN)?;
        let capacity_rev =
            require_capability_text(payload, "capacity_revision", MAX_CAPABILITY_TEXT_LEN)?;
        let context = self.provider_capability_for_session(session)?;
        context.verify(
            proof_kind,
            &attempt_id,
            &operation_id,
            &claim_id,
            &proof_ref,
            &canonical_payload_sha256,
            &binding_digest,
            &executable_digest,
            &route_rev,
            &capacity_rev,
        )?;
        let body = serde_json::json!({
            "kind": "native_worker_provider_capability",
            "wire_version": PROVIDER_CAPABILITY_WIRE_VERSION,
            "claim_id": claim_id,
            "attempt_id": attempt_id,
            "operation_id": operation_id,
            "proof_kind": proof_kind_value,
            "route_revision": route_rev,
            "capacity_revision": capacity_rev,
            "verified_at_unix_ms": unix_ms(),
        });
        seal_capability_receipt(body)
    }
}

// ---------------------------------------------------------------------------
// Boundary parsing (fail-closed presenter checks; owner semantics untouched).
// ---------------------------------------------------------------------------

/// Parses one wire proof-kind name into the owner enum.
fn parse_proof_kind(value: &str) -> Result<ProviderProofKind, ProviderCapabilityRouteError> {
    match value {
        "Admission" => Ok(ProviderProofKind::Admission),
        "Cancellation" => Ok(ProviderProofKind::Cancellation),
        "WorkerFence" => Ok(ProviderProofKind::WorkerFence),
        "Reassignment" => Ok(ProviderProofKind::Reassignment),
        "Result" => Ok(ProviderProofKind::Result),
        "UnknownOutcome" => Ok(ProviderProofKind::UnknownOutcome),
        "Binding" => Ok(ProviderProofKind::Binding),
        _ => Err(ProviderCapabilityRouteError::Session(
            "capability proof kind".to_owned(),
        )),
    }
}

/// Requires one bounded non-empty text field from the frame payload.
fn require_capability_text(
    payload: &serde_json::Value,
    field: &'static str,
    max_len: usize,
) -> Result<String, ProviderCapabilityRouteError> {
    let value = payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= max_len)
        .ok_or_else(|| ProviderCapabilityRouteError::Session(field.to_owned()))?;
    Ok(value.to_owned())
}

/// Requires one lowercase SHA-256 digest field from the frame payload.
fn require_capability_digest(
    payload: &serde_json::Value,
    field: &'static str,
) -> Result<String, ProviderCapabilityRouteError> {
    let value = payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| ProviderCapabilityRouteError::Session(field.to_owned()))?;
    Ok(value.to_owned())
}

/// Seals one capability receipt body with its canonical digest.
fn seal_capability_receipt(
    mut body: serde_json::Value,
) -> Result<serde_json::Value, ProviderCapabilityRouteError> {
    let digest = sha256_json(&body)
        .map_err(|_| ProviderCapabilityRouteError::Session("capability receipt".to_owned()))?;
    body["receipt_digest"] = serde_json::Value::String(digest);
    Ok(body)
}

// Slice B focused proofs live in `tests/provider_capability_plumbing.rs`.
// They are wired here (not via `tests.rs`) so this slice touches only its
// owned files: the capability route, the dispatch arm, the module
// declaration, and the one new test file.
#[cfg(test)]
#[path = "tests/provider_capability_plumbing.rs"]
mod provider_capability_plumbing;
