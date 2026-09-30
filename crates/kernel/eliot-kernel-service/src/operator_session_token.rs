//! Kernel-owned Operator session token for one authenticated local UI
//! binding (issue #1777, I11.8).
//!
//! I11.8 requires the `WinUI` operational binding to carry "a short-lived
//! Kernel challenge/session token". This module is the Kernel owner of that
//! value and has the same shape, and the same preconditions, as the normal
//! Notify launch grant in `notify_grant.rs`: it reads live Kernel admission
//! (Ready state, unfenced generation, current authority epoch and fence),
//! requires the retained session evidence to match that exact epoch and
//! fence, and returns a Kernel-side authorization that carries *observed*
//! authority rather than caller-asserted authority.
//!
//! What is different, and why the token is not merely a renamed copy of the
//! broker registration digest:
//!
//! * the token is derived here, over the exact bound evidence plus the live
//!   authority triple, so the broker cannot produce or recompute it - it
//!   names a Kernel authority epoch, State Fence and generation the broker
//!   does not hold;
//! * it is issued per binding: the bound evidence carries the one-shot
//!   handoff nonce, the OS-observed Windows SID/session/client-process tuple
//!   and the exact requested role and capability set, so two UI bindings
//!   never share a token and a token minted for one binding cannot be
//!   presented for another;
//! * it is short-lived: the Kernel derives `expires_at` from its own observed
//!   clock and the bounded TTL below. There is no refresh path here, so an
//!   expired token is stale, never continuous.
//!
//! The grant binds caller-declared evidence and echoes it back unchanged. It
//! is not, and does not claim to be, proof that a presented process id owns a
//! channel: the OS-observed connected peer is the broker's proof
//! (`bins/eliot-user-broker/src/main.rs::serve_operator_pipe_connection`),
//! and the broker compares this echoed evidence against that observed peer
//! before it accepts any redemption. This module never observes a client
//! process, never constructs broker wire types, and never spawns anything.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eliot_contracts::{EpochId, ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use eliot_receipts::SessionBinding;

use crate::{KernelService, KernelServiceError, KernelServiceState};

/// Operation-id prefix for Operator session tokens. The id is deterministic in
/// the exact one-shot handoff nonce, mirroring the `notify:` convention for
/// Notify launch grants: re-challenging one still-unredeemed binding under the
/// same Kernel authority is idempotent, and any other binding is a distinct
/// operation.
pub const OPERATOR_SESSION_TOKEN_OPERATION_PREFIX: &str = "operatorsession:";

/// Domain separator for the token digest. The token is a Kernel-issued binding
/// identity, not a credential for any other surface, so its preimage is
/// domain-separated from every other digest in the system.
const OPERATOR_SESSION_TOKEN_DOMAIN: &str = "eliot.operator-session-token.v1";

/// Lifetime of one issued Operator session token. The token exists only to
/// carry one authenticated binding across one challenge/redemption exchange;
/// a longer-lived binding is re-challenged against live Kernel admission.
pub const OPERATOR_SESSION_TOKEN_TTL_MS: u64 = 60_000;

/// Bounded length of every caller-declared identity string in this grant.
const OPERATOR_SESSION_FIELD_LIMIT: usize = 512;

/// Explicit evidence for one Operator session token.
///
/// Every field is caller-supplied and re-validated here. The Kernel adds only
/// live admission (epoch, fence, generation), its own clock, and the token
/// itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorSessionTokenInputs {
    /// Live Kernel-issued registration identity of the broker asking for the
    /// token (lowercase SHA-256).
    pub registration_digest: String,
    /// One-shot handoff nonce the broker issued for this exact binding.
    pub handoff_nonce: String,
    /// Windows SID observed for the connecting UI process.
    pub windows_sid: String,
    /// Interactive logon Session observed for the connecting UI process.
    pub interactive_session_id: String,
    /// OS process id observed for the connecting UI process.
    pub client_process_id: String,
    /// Image path observed for the connecting UI process.
    pub client_image_path: String,
    /// Requested Human role for this binding.
    pub role: String,
    /// Exact capability set requested for this binding.
    pub capabilities: Vec<String>,
    /// Retained Kernel-issued session evidence, checked for currency against
    /// live admission below.
    pub session: SessionBinding,
}

/// Kernel-bound Operator session authorization.
///
/// Carries the live authority epoch, State Fence and generation observed at
/// bind time, the bounded lease, and the exact evidence the token is bound to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorSessionAuthorization {
    operation_id: String,
    session: SessionBinding,
    authority_epoch: EpochId,
    state_fence: StateFence,
    generation: ResourceGeneration,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    token: String,
    inputs: OperatorSessionTokenInputs,
}

impl OperatorSessionAuthorization {
    /// Deterministic operation identity (`operatorsession:<handoff-nonce>`).
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Retained session evidence bound at grant time.
    #[must_use]
    pub const fn session(&self) -> &SessionBinding {
        &self.session
    }

    /// Live authority epoch observed at grant time.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Live State Fence observed at grant time.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Live generation observed at grant time.
    #[must_use]
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Kernel-observed issuance instant, in Unix milliseconds.
    #[must_use]
    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    /// Absolute expiry of this token, in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }

    /// The Kernel-issued session token the client presents at redemption.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The exact evidence this token is bound to, exactly as admitted.
    #[must_use]
    pub const fn inputs(&self) -> &OperatorSessionTokenInputs {
        &self.inputs
    }
}

fn bounded_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= OPERATOR_SESSION_FIELD_LIMIT
        && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// The canonical token preimage. It carries the live authority triple, so the
/// broker cannot reproduce the digest from the registration it already holds.
#[derive(serde::Serialize)]
struct TokenPreimage<'a> {
    domain: &'a str,
    operation_id: &'a str,
    registration_digest: &'a str,
    handoff_nonce: &'a str,
    windows_sid: &'a str,
    interactive_session_id: &'a str,
    client_process_id: &'a str,
    client_image_path: &'a str,
    role: &'a str,
    capabilities: &'a [String],
    session_id: &'a str,
    authority_epoch: &'a EpochId,
    state_fence: &'a StateFence,
    generation: u64,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

fn operator_session_token(
    operation_id: &str,
    authority_epoch: &EpochId,
    state_fence: &StateFence,
    generation: ResourceGeneration,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    inputs: &OperatorSessionTokenInputs,
) -> Result<String, KernelServiceError> {
    let preimage = TokenPreimage {
        domain: OPERATOR_SESSION_TOKEN_DOMAIN,
        operation_id,
        registration_digest: &inputs.registration_digest,
        handoff_nonce: &inputs.handoff_nonce,
        windows_sid: &inputs.windows_sid,
        interactive_session_id: &inputs.interactive_session_id,
        client_process_id: &inputs.client_process_id,
        client_image_path: &inputs.client_image_path,
        role: &inputs.role,
        capabilities: &inputs.capabilities,
        session_id: inputs.session.session_id.as_str(),
        authority_epoch,
        state_fence,
        generation: generation.value(),
        issued_at_unix_ms,
        expires_at_unix_ms,
    };
    let bytes = canonical_json_bytes(&preimage).map_err(|_| KernelServiceError::InvalidField {
        field: "operator_session.preimage",
        reason: "canonical token preimage could not be encoded",
    })?;
    Ok(sha256_hex(&bytes))
}

fn validate_operator_session_inputs(
    inputs: &OperatorSessionTokenInputs,
) -> Result<(), KernelServiceError> {
    if !valid_sha256(&inputs.registration_digest) {
        return Err(KernelServiceError::InvalidField {
            field: "operator_session.registration_digest",
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    if !bounded_text(&inputs.handoff_nonce)
        || !bounded_text(&inputs.windows_sid)
        || !bounded_text(&inputs.interactive_session_id)
        || !bounded_text(&inputs.role)
    {
        return Err(KernelServiceError::InvalidField {
            field: "operator_session.binding",
            reason: "must be a non-empty bounded identity value",
        });
    }
    if !inputs.client_process_id.is_empty()
        && !inputs
            .client_process_id
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(KernelServiceError::InvalidField {
            field: "operator_session.client_process_id",
            reason: "must be a decimal OS process id",
        });
    }
    if inputs.client_process_id == "0" {
        return Err(KernelServiceError::InvalidField {
            field: "operator_session.client_process_id",
            reason: "must be a live OS process id",
        });
    }
    let image = std::path::Path::new(inputs.client_image_path.as_str());
    if !bounded_text(&inputs.client_image_path)
        || !image.is_absolute()
        || image.file_name().is_none()
    {
        return Err(KernelServiceError::InvalidField {
            field: "operator_session.client_image_path",
            reason: "must be an absolute observed image path",
        });
    }
    if inputs.capabilities.is_empty() {
        return Err(KernelServiceError::InvalidField {
            field: "operator_session.capabilities",
            reason: "must carry the exact requested capability set",
        });
    }
    let mut seen: Vec<&str> = Vec::with_capacity(inputs.capabilities.len());
    for capability in &inputs.capabilities {
        if !bounded_text(capability) {
            return Err(KernelServiceError::InvalidField {
                field: "operator_session.capabilities",
                reason: "must be bounded capability names",
            });
        }
        if seen.contains(&capability.as_str()) {
            return Err(KernelServiceError::InvalidField {
                field: "operator_session.capabilities",
                reason: "must be an exact set without duplicates",
            });
        }
        seen.push(capability.as_str());
    }
    Ok(())
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Binds one fresh, short-lived Operator session token against live Kernel
/// admission.
///
/// Reads Ready state, unfenced generation, and the current authority
/// epoch/fence from the live service; requires the retained session evidence
/// to match that exact epoch and fence; validates the presented binding
/// evidence. The issued token is derived from that evidence plus the observed
/// authority triple, and its expiry is derived from the Kernel's own clock.
/// There is no refresh, renewal, or continuity path: a superseded epoch, a
/// fenced generation, a non-`Ready` service, a malformed binding, or an
/// unprovable activation lineage all fail closed.
///
/// # Errors
///
/// Returns [`KernelServiceError::GenerationFenced`] when the generation is
/// fenced, [`KernelServiceError::AdmissionClosed`] when the service is not
/// `Ready`, [`KernelServiceError::ReadinessNotProven`] when no activation
/// lineage is retained, or [`KernelServiceError::InvalidField`] for stale
/// session authority, malformed evidence, or a clock that cannot express the
/// bounded lease.
pub fn bind_operator_session_token(
    service: &KernelService,
    inputs: &OperatorSessionTokenInputs,
) -> Result<OperatorSessionAuthorization, KernelServiceError> {
    if service.generation_fenced() {
        return Err(KernelServiceError::GenerationFenced);
    }
    if service.state() != KernelServiceState::Ready {
        return Err(KernelServiceError::AdmissionClosed(service.state()));
    }
    let activation = service
        .activation_receipt()
        .ok_or(KernelServiceError::ReadinessNotProven)?;
    let authority_epoch = service.authority_epoch();
    let expected_fence = StateFence::new(authority_epoch.clone(), activation.generation);
    if !inputs
        .session
        .authority_epoch
        .is_same_authority(&authority_epoch)
        || inputs.session.state_fence != expected_fence
    {
        return Err(KernelServiceError::InvalidField {
            field: "operator_session.session-authority",
            reason: "stale-authority-epoch-or-fence",
        });
    }
    validate_operator_session_inputs(inputs)?;
    let issued_at_unix_ms = unix_ms();
    if issued_at_unix_ms == 0 {
        return Err(KernelServiceError::InvalidField {
            field: "operator_session.clock",
            reason: "Kernel clock observation is zero",
        });
    }
    let expires_at_unix_ms = issued_at_unix_ms
        .checked_add(OPERATOR_SESSION_TOKEN_TTL_MS)
        .filter(|expires| *expires > issued_at_unix_ms)
        .ok_or(KernelServiceError::InvalidField {
            field: "operator_session.clock",
            reason: "cannot express the bounded session-token lease",
        })?;
    let operation_id = format!(
        "{OPERATOR_SESSION_TOKEN_OPERATION_PREFIX}{}",
        inputs.handoff_nonce
    );
    let token = operator_session_token(
        &operation_id,
        &authority_epoch,
        &expected_fence,
        activation.generation,
        issued_at_unix_ms,
        expires_at_unix_ms,
        inputs,
    )?;
    Ok(OperatorSessionAuthorization {
        operation_id,
        session: inputs.session.clone(),
        authority_epoch,
        state_fence: expected_fence,
        generation: activation.generation,
        issued_at_unix_ms,
        expires_at_unix_ms,
        token,
        inputs: inputs.clone(),
    })
}
