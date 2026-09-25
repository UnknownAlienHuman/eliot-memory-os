//! Authenticated research-provider dispatch route (issue #24).
//!
//! Daemon-side composition only: builds a [`ResearchProviderContext`] from the
//! authenticated Kernel client (session + service guard + Kernel owner
//! handle) and admits one bounded research-provider dispatch against the
//! **live** authority epoch and the authenticated session's module-generation
//! State Fence, then seals the dispatch receipt. It never reads an executable
//! from environment, argv, stdin, or task text; the executable path in the
//! presented dispatch is the Kernel-issued provider generation's exact
//! immutable artifact identity and is re-bound to its content digest before a
//! receipt is issued.
//!
//! The wire contract itself ([`ResearchProviderDispatch`],
//! [`ResearchProviderDispatchReceipt`], [`ResearchProviderDisposition`],
//! [`ResearchProviderError`], [`RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION`]) is
//! owned by `eliot_kernel_service::protocol::research_provider`. This module
//! only authenticates the session, re-queries the live authority epoch, and
//! delegates to the owner. It never fabricates persistence, admission, or a
//! receipt.
//!
//! Every call re-queries the live authority epoch; nothing is cached, so
//! restore always observes fresh owner evidence. A stale epoch or an
//! incompatible State Fence fences fail-closed and is never downgraded to a
//! best-effort parse.
//!
//! Residual (reported, not papered over): `eliot-ors` carries no
//! research-provider row — see
//! `crates/kernel/eliot-ors/src/store.rs`, which has no research provider
//! table and no `load_research_provider_*` reader, and
//! `crates/kernel/eliot-ors/src/versioned_artifact.rs`, whose
//! `VersionedArtifactRegistry` is pure in-memory domain logic with no durable
//! loader. This route therefore cannot bind a durable Governor-owned attempt
//! or source-portfolio row, and does not pretend to: durable Research
//! Job/Attempt and coverage-denominator state are owned by #15/#18. What this
//! route does prove is the live-admission property I21.11 requires: a reachable
//! endpoint alone grants nothing, and the receipt must echo the exact request
//! digest before any caller may treat it as admission.
//!
//! Architecture: A12.2 Principal, Session and visibility; A13.2 Kernel and
//! failure domains.
//! Implementation: I1.2 Required processes of the first complete runtime;
//! I1.8 Exact ownership and call paths; I21.11 Research federation provider.
//! Forbidden authority: must not mint provider semantics, must not cache
//! verification, must not accept an unauthenticated session, must not create
//! durable canonical state.

use super::{
    KernelComposition, KernelFrameAction, KernelServiceState, caller_binding, sha256_json,
    status_frame, unix_ms,
};
use eliot_contracts::{EpochId, StateFence};
use eliot_ipc::{Session, TransportError};
use eliot_kernel_service::{
    RESEARCH_PROVIDER_CANCEL_OPERATION, RESEARCH_PROVIDER_DISPATCH_OPERATION,
    RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION, RESEARCH_PROVIDER_MAX_TEXT,
    RESEARCH_PROVIDER_RECONCILE_OPERATION, RESEARCH_PROVIDER_STATUS_OPERATION,
    RESEARCH_PROVIDER_WIRE_ID, ResearchProviderDispatch, ResearchProviderDispatchReceipt,
    ResearchProviderDisposition, ResearchProviderError,
};
use eliot_protocol::{Frame, FrameKind, MessageType, ProtocolPayload};
use std::sync::{Arc, Mutex};

/// Returns true for the research-provider operations owned here.
pub(crate) fn is_research_provider_operation(operation: &str) -> bool {
    matches!(
        operation,
        RESEARCH_PROVIDER_DISPATCH_OPERATION
            | RESEARCH_PROVIDER_STATUS_OPERATION
            | RESEARCH_PROVIDER_CANCEL_OPERATION
            | RESEARCH_PROVIDER_RECONCILE_OPERATION
    )
}

/// Returns the closed receipt kind discriminator the owner validates against.
const RECEIPT_KIND: &str = ResearchProviderDispatchReceipt::RECEIPT_KIND;

/// Maximum length carried in any typed error message, in characters.
const MAX_ERROR_TEXT_CHARS: usize = 128;

// ---------------------------------------------------------------------------
// Typed route errors (mechanical TransportError mapping at the boundary).
// ---------------------------------------------------------------------------

/// Typed failure for one research-provider composition or dispatch admission.
///
/// Every message is bounded and secret-free: identities are truncated to
/// [`MAX_ERROR_TEXT_CHARS`] characters and no payload, digest, or credential
/// material is ever rendered.
#[derive(Debug)]
pub enum ResearchProviderRouteError {
    /// Session authentication, readiness, or presenter-shape failure.
    Session(String),
    /// Kernel owner-state access failure.
    Store(String),
    /// The dispatch wire owner rejected the presentation.
    Dispatch(ResearchProviderError),
    /// The request names a control operation this route does not own.
    UnknownOperation(String),
}

impl std::fmt::Display for ResearchProviderRouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(reason) => write!(f, "research provider session rejected: {reason}"),
            Self::Store(reason) => write!(f, "research provider owner state unavailable: {reason}"),
            Self::Dispatch(_) => {
                write!(f, "research provider dispatch rejected by the kernel owner")
            }
            Self::UnknownOperation(identity) => {
                write!(f, "research provider operation is unknown: {identity}")
            }
        }
    }
}

impl std::error::Error for ResearchProviderRouteError {}

impl From<ResearchProviderError> for ResearchProviderRouteError {
    fn from(error: ResearchProviderError) -> Self {
        Self::Dispatch(error)
    }
}

impl ResearchProviderRouteError {
    /// Maps one typed failure into the closed transport vocabulary.
    ///
    /// A stale epoch or fence fences the session; an unknown control
    /// operation is `UnknownRequest`; everything else fails closed. No I7.20
    /// `reason_code` is projected here because this variant never reaches a
    /// caller as a response: it fences the session, exactly as the provider-
    /// capability and native-worker routes do. The reason code belongs to the
    /// responses that do reach a caller, which are the sealed receipts below
    /// (they carry `disposition` plus the exact `reason_code`) and the
    /// `eliot-mod-research` client that re-verifies them.
    pub(crate) fn into_transport(self) -> TransportError {
        match self {
            Self::UnknownOperation(_) => TransportError::UnknownRequest,
            Self::Session(_) | Self::Store(_) | Self::Dispatch(_) => TransportError::SessionFenced,
        }
    }
}

/// Truncates one identity to a bounded, secret-free error fragment.
fn bounded_identity(value: &str) -> String {
    value.chars().take(MAX_ERROR_TEXT_CHARS).collect()
}

// ---------------------------------------------------------------------------
// Authenticated research-provider context.
// ---------------------------------------------------------------------------

/// Authenticated research-provider context for one Kernel client session.
///
/// Holds shared owner handles only: the Kernel service guard source, the
/// authenticated principal binding, and the epoch observed at construction. It
/// holds no cached verdict and no payload cache:
/// [`ResearchProviderContext::admit`] re-queries the live epoch on every call.
pub struct ResearchProviderContext {
    service: Arc<Mutex<eliot_kernel_service::KernelService>>,
    session_principal_binding: String,
    live_authority_epoch: EpochId,
}

impl ResearchProviderContext {
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

    /// Admits one presented research dispatch against live Kernel authority.
    ///
    /// Validates the closed presentation through the wire owner, requires the
    /// presented Authority Epoch to be the same authority as the freshly
    /// re-queried live epoch, and requires the presented State Fence to be
    /// compatible with the authenticated session's module-generation fence.
    /// On success it seals one receipt whose `request_sha256` is the canonical
    /// digest of the exact admitted bytes, so the caller can prove the receipt
    /// answers its own request. Nothing is cached between calls.
    ///
    /// # Errors
    ///
    /// Returns [`ResearchProviderRouteError::Dispatch`] when the wire owner
    /// refuses the presentation, and
    /// [`ResearchProviderRouteError::Store`] when Kernel owner state cannot be
    /// read.
    pub fn admit(
        &self,
        dispatch: &ResearchProviderDispatch,
        session_fence: &StateFence,
    ) -> Result<ResearchProviderDispatchReceipt, ResearchProviderRouteError> {
        dispatch.validate()?;
        // Fresh live epoch on every call: never the construction-time copy.
        let live_epoch = self
            .service
            .lock()
            .map_err(|_| {
                ResearchProviderRouteError::Store("kernel owner state is unavailable".to_owned())
            })?
            .authority_epoch();
        if !live_epoch.is_same_authority(&dispatch.authority_epoch) {
            return Err(ResearchProviderRouteError::Dispatch(
                ResearchProviderError::StaleEpoch,
            ));
        }
        if !session_fence.is_compatible_with(&dispatch.state_fence) {
            return Err(ResearchProviderRouteError::Dispatch(
                ResearchProviderError::StaleFence,
            ));
        }
        seal_dispatch_receipt(dispatch, &live_epoch, ResearchProviderDisposition::Admitted)
    }

    /// Seals one honest non-success receipt for a control operation this
    /// Kernel cannot answer.
    ///
    /// `status`, `cancel` and `reconcile` address an *already-admitted*
    /// research operation, which requires a durable research Job/Attempt row
    /// in ORS. `eliot-ors` has no such table and no reader (see the module
    /// residual), so this route cannot look the operation up and must not
    /// pretend it did. It therefore returns a sealed, non-admitted receipt
    /// carrying `disposition: Unavailable` and the exact I7.20
    /// `CAPABILITY_UNAVAILABLE` reason code, still echoing the presented
    /// request digest so the caller can prove which request went unanswered.
    ///
    /// A caller's `verify_echo` refuses this receipt because its disposition is
    /// not `Admitted`, so a degraded control path can never be mistaken for an
    /// admission.
    pub fn refuse_control_operation(
        &self,
        dispatch: &ResearchProviderDispatch,
        session_fence: &StateFence,
    ) -> Result<ResearchProviderDispatchReceipt, ResearchProviderRouteError> {
        dispatch.validate()?;
        if !session_fence.is_compatible_with(&dispatch.state_fence) {
            return Err(ResearchProviderRouteError::Dispatch(
                ResearchProviderError::StaleFence,
            ));
        }
        let live_epoch = self
            .service
            .lock()
            .map_err(|_| {
                ResearchProviderRouteError::Store("kernel owner state is unavailable".to_owned())
            })?
            .authority_epoch();
        seal_dispatch_receipt(
            dispatch,
            &live_epoch,
            ResearchProviderDisposition::Unavailable,
        )
    }
}

// ---------------------------------------------------------------------------
// Composition entry point.
// ---------------------------------------------------------------------------

impl KernelComposition {
    /// Builds the research-provider context for one session.
    ///
    /// Never constructs from an unauthenticated session: the service must be
    /// `Ready`, the peer identity must validate, the caller binding must
    /// derive, and (on Windows) the session must be the current daemon
    /// session. Each gate reuses the existing daemon guard instead of
    /// duplicating auth logic.
    pub fn research_provider_for_session(
        &self,
        session: &Session,
    ) -> Result<ResearchProviderContext, ResearchProviderRouteError> {
        if self.service_state().map_err(|_| {
            ResearchProviderRouteError::Session("kernel service state is unavailable".to_owned())
        })? != KernelServiceState::Ready
        {
            return Err(ResearchProviderRouteError::Session(
                "kernel service is not ready for research provider composition".to_owned(),
            ));
        }
        session.peer.validate().map_err(|_| {
            ResearchProviderRouteError::Session(
                "research provider session peer is not authenticated".to_owned(),
            )
        })?;
        let (owner, _session_binding) = caller_binding(session).map_err(|_| {
            ResearchProviderRouteError::Session(
                "research provider session binding failed".to_owned(),
            )
        })?;
        #[cfg(windows)]
        self.require_current_daemon_session(session).map_err(|_| {
            ResearchProviderRouteError::Session(
                "research provider session is not the current daemon session".to_owned(),
            )
        })?;
        let live_authority_epoch = self
            .service
            .lock()
            .map_err(|_| {
                ResearchProviderRouteError::Store("kernel owner state is unavailable".to_owned())
            })?
            .authority_epoch();
        Ok(ResearchProviderContext {
            service: Arc::clone(&self.service),
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
    /// Dispatches one research-provider frame.
    ///
    /// The caller ([`crate::KernelComposition::dispatch_frame`]) has already
    /// gated service readiness and peer authentication mirroring the Process
    /// gate; those gates are re-checked here so direct callers cannot bypass
    /// them. Per-call session authentication, the fresh live-epoch query, and
    /// the owner delegation live in [`ResearchProviderContext::admit`].
    ///
    /// Admission is returned as a distinct [`KernelFrameAction::Research`]
    /// action rather than a plain reply so the front-door driver can serve it
    /// on a control connection and fence it on a bridge connection, exactly as
    /// it does for Doctor/testd/Dreamer authority.
    pub(crate) fn dispatch_research_provider_frame(
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
        if frame.request_identity.is_none() {
            return Err(TransportError::SessionFenced);
        }
        let payload = match &frame.payload {
            ProtocolPayload::Json(payload) => payload.clone(),
            _ => return Err(TransportError::SessionFenced),
        };
        let operation = payload
            .get("operation")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !is_research_provider_operation(operation) {
            return Err(
                ResearchProviderRouteError::UnknownOperation(bounded_identity(operation))
                    .into_transport(),
            );
        }
        self.handle_research_provider(session, &request_id, operation, &payload)
            .map_err(ResearchProviderRouteError::into_transport)?;
        Ok(KernelFrameAction::Research {
            request_id,
            operation: operation.to_owned(),
            payload,
        })
    }

    /// Admits one research-provider request and returns its sealed reply
    /// frame, already mapped into the closed transport vocabulary.
    ///
    /// This is the control-connection entry point used by the front-door
    /// driver, so the binary never needs the private route module: the typed
    /// route error is translated here exactly once, at the transport
    /// boundary, and no typed failure is collapsed into prose.
    pub fn research_provider_reply_frame(
        &self,
        session: &Session,
        request_id: &eliot_contracts::RequestId,
        operation: &str,
        payload: &serde_json::Value,
    ) -> Result<Frame, TransportError> {
        if !is_research_provider_operation(operation) {
            return Err(
                ResearchProviderRouteError::UnknownOperation(bounded_identity(operation))
                    .into_transport(),
            );
        }
        self.handle_research_provider(session, request_id, operation, payload)
            .map_err(ResearchProviderRouteError::into_transport)
    }

    /// Admits one research-provider request and seals its reply frame.
    ///
    /// Shared by the front-door control connection and by direct callers, so
    /// the session gates and the owner delegation are never bypassed by taking
    /// the frame path alone.
    pub(crate) fn handle_research_provider(
        &self,
        session: &Session,
        request_id: &eliot_contracts::RequestId,
        operation: &str,
        payload: &serde_json::Value,
    ) -> Result<Frame, ResearchProviderRouteError> {
        let wire_version = require_wire_text(payload, "wire_version", MAX_ERROR_TEXT_CHARS)?;
        if wire_version != RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION {
            return Err(ResearchProviderRouteError::Session(wire_version));
        }
        let dispatch = decode_dispatch(payload)?;
        let context = self.research_provider_for_session(session)?;
        // Session fence join: the presented dispatch must be compatible with
        // the authenticated session's module-generation State Fence, checked
        // here and again inside the context against the live epoch.
        if !session
            .module_generation
            .state_fence
            .is_compatible_with(&dispatch.state_fence)
        {
            return Err(ResearchProviderRouteError::Dispatch(
                ResearchProviderError::StaleFence,
            ));
        }
        let receipt = if operation == RESEARCH_PROVIDER_DISPATCH_OPERATION {
            context.admit(&dispatch, &session.module_generation.state_fence)?
        } else {
            // `status` / `cancel` / `reconcile` address an already-admitted
            // operation; without a durable research row the honest answer is
            // a sealed typed non-success receipt, never a fabricated status.
            context.refuse_control_operation(&dispatch, &session.module_generation.state_fence)?
        };
        let body = seal_receipt_body(operation, &dispatch, &receipt)?;
        let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, body)
            .map_err(|_| ResearchProviderRouteError::Session("research reply frame".to_owned()))?;
        frame.request_id = Some(request_id.clone());
        frame
            .validate()
            .map_err(|_| ResearchProviderRouteError::Session("research reply frame".to_owned()))?;
        Ok(frame)
    }
}

// ---------------------------------------------------------------------------
// Boundary parsing and receipt sealing.
// ---------------------------------------------------------------------------

/// Requires one bounded non-empty text field from the frame payload.
fn require_wire_text(
    payload: &serde_json::Value,
    field: &'static str,
    max_len: usize,
) -> Result<String, ResearchProviderRouteError> {
    payload
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= max_len)
        .map(str::to_owned)
        .ok_or(ResearchProviderRouteError::Session(field.to_owned()))
}

/// Decodes the nested owner-typed dispatch envelope from the frame payload.
///
/// The wire owner owns the schema; this route only extracts the `dispatch`
/// member and lets the owner's `validate` decide. A payload without exactly
/// one `dispatch` object is refused before any owner call.
fn decode_dispatch(
    payload: &serde_json::Value,
) -> Result<ResearchProviderDispatch, ResearchProviderRouteError> {
    let wire_id = require_wire_text(payload, "wire_id", RESEARCH_PROVIDER_MAX_TEXT)?;
    if wire_id != RESEARCH_PROVIDER_WIRE_ID {
        return Err(ResearchProviderRouteError::Session(wire_id));
    }
    let body = payload
        .get("dispatch")
        .ok_or_else(|| ResearchProviderRouteError::Session("research dispatch".to_owned()))?;
    serde_json::from_value(body.clone())
        .map_err(|_| ResearchProviderRouteError::Session("research dispatch".to_owned()))
}

/// Seals one receipt with its canonical digest.
fn seal_dispatch_receipt(
    dispatch: &ResearchProviderDispatch,
    live_epoch: &EpochId,
    disposition: ResearchProviderDisposition,
) -> Result<ResearchProviderDispatchReceipt, ResearchProviderRouteError> {
    let mut receipt = ResearchProviderDispatchReceipt {
        wire_id: dispatch.wire_id.clone(),
        wire_version: dispatch.wire_version.clone(),
        kind: RECEIPT_KIND.to_owned(),
        disposition,
        // I7.20: a non-success response carries its exact reason code; an
        // admitted response carries none.
        reason_code: if disposition.admits() {
            String::new()
        } else {
            disposition.reason_code().to_owned()
        },
        operation_id: dispatch.operation_id.clone(),
        cancellation_id: dispatch.cancellation_id.clone(),
        request_sha256: dispatch.canonical_sha256()?,
        admitted_authority_epoch: live_epoch.clone(),
        admitted_generation: dispatch.process_generation,
        admitted_fence: dispatch.state_fence.clone(),
        admitted_at_unix_ms: unix_ms(),
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = receipt
        .compute_digest()
        .map_err(|_| ResearchProviderRouteError::Session("research receipt".to_owned()))?;
    // Fail-closed self-check: the Kernel never emits a receipt it would itself
    // refuse, so a caller can trust `validate` on the wire bytes alone.
    receipt
        .validate()
        .map_err(ResearchProviderRouteError::Dispatch)?;
    Ok(receipt)
}

/// Projects the admitted receipt into the bounded reply body.
fn seal_receipt_body(
    operation: &str,
    dispatch: &ResearchProviderDispatch,
    receipt: &ResearchProviderDispatchReceipt,
) -> Result<serde_json::Value, ResearchProviderRouteError> {
    let body = serde_json::json!({
        "kind": RECEIPT_KIND,
        "wire_id": RESEARCH_PROVIDER_WIRE_ID,
        "wire_version": RESEARCH_PROVIDER_DISPATCH_WIRE_VERSION,
        "operation": operation,
        "receipt": receipt,
        "module_id": dispatch.module_id,
        "module_generation_id": dispatch.module_generation_id,
        "principal_binding_scope": "kernel-live-authority",
    });
    let digest = sha256_json(&body)
        .map_err(|_| ResearchProviderRouteError::Session("research receipt body".to_owned()))?;
    let mut body = body;
    body["body_sha256"] = serde_json::Value::String(digest);
    Ok(body)
}
