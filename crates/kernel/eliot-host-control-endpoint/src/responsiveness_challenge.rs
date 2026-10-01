//! Authenticated Host control-owner responsiveness challenge (issue #1757).
//!
//! Architecture: I8.3 (`docs/architecture/I08-03-deterministic-supervision-loop.md`),
//! I1.4 (independent SCM branches), I13.5 (stale generation/revision is a conflict).
//!
//! This cell distinguishes a live Host process from a responsive current Host
//! control owner. A challenge is issued to the exact owner-path request
//! carried by [`OwnerChallengeEnvelope`]; only the Host control-owner contour
//! that drains the bounded owner queue can answer it with an exactly
//! correlated response. A listener-thread echo cannot prove the Host control
//! loop is making progress, and a response proves only the declared control
//! property, not whole-product readiness.
//!
//! Ownership: the wire contract stays owned by `eliot-host-service`; every
//! validation below reuses its original validators
//! ([`HostRuntimeControlRequest::validate`],
//! [`HostRuntimeControlResponse::validate`], [`response_matches_request`]).
//! This cell adds only the challenge binding (exact correlation, freshness
//! bound, protocol revision). The owner-contour handler that pops the queue
//! and answers lives in the Host composition and is out of scope for this
//! lane; until it is wired, [`validate_owner_challenge_response`] has no
//! production caller (STITCH).
//!
//! Redaction: only digests and coordination identities enter an envelope.
//! Credentials, nonces, and raw path/user data are never fields here.

use eliot_host_service::runtime_control::{
    HostControlChallenge, HostControlChallengeResponse, HostRuntimeControlRequest,
    HostRuntimeControlResponse, response_matches_request,
};

/// Protocol revision of the owner-challenge binding. Responses carrying any
/// other revision are rejected so a stale or foreign challenge can never
/// establish responsiveness.
pub const OWNER_CHALLENGE_PROTOCOL_REVISION: u16 = 1;

/// Upper bound, in seconds, for one challenge wait. The envelope travels the
/// existing bounded owner queue (30s response bound); a longer wait would
/// outlive the queue guarantee and is rejected at issue time.
pub const OWNER_CHALLENGE_MAX_WAIT_SECS: u64 = 30;

/// One Watchdog-issued responsiveness challenge bound to the exact owner-path
/// request that carries it.
///
/// The challenge identity is the request identity itself
/// (`request.request_id`): exact correlation is a content comparison, never a
/// second lookup. `expected_owner_digest` is the canonical owner-epoch digest
/// (see `eliot-host-state::host_owner_epoch_digest`) the answering owner must
/// report; the Host control owner echoes it alongside its current
/// owner/epoch and control-progress observation.
pub struct OwnerChallengeEnvelope {
    request: HostRuntimeControlRequest,
    expected_owner_digest: String,
    wait_secs: u64,
    protocol_revision: u16,
}

impl OwnerChallengeEnvelope {
    /// Issues a challenge on an already-constructed owner-path request.
    ///
    /// Runs the original wire-owner validator on the request, then binds the
    /// expected owner digest, the bounded wait, and the protocol revision.
    ///
    /// # Errors
    ///
    /// Returns a refusal when the request fails its own validation, when the
    /// expected owner digest is blank or carries control characters, or when
    /// the wait is zero or exceeds [`OWNER_CHALLENGE_MAX_WAIT_SECS`].
    pub fn issue(
        request: HostRuntimeControlRequest,
        expected_owner_digest: &str,
        wait_secs: u64,
    ) -> Result<Self, String> {
        request.validate()?;
        if expected_owner_digest.trim().is_empty()
            || expected_owner_digest.chars().any(char::is_control)
        {
            return Err("expected owner digest is not a coordination identity".to_owned());
        }
        if wait_secs == 0 || wait_secs > OWNER_CHALLENGE_MAX_WAIT_SECS {
            return Err("challenge wait is outside the bounded owner-queue guarantee".to_owned());
        }
        Ok(Self {
            request,
            expected_owner_digest: expected_owner_digest.to_owned(),
            wait_secs,
            protocol_revision: OWNER_CHALLENGE_PROTOCOL_REVISION,
        })
    }

    /// The exact owner-path request carrying this challenge.
    #[must_use]
    pub const fn request(&self) -> &HostRuntimeControlRequest {
        &self.request
    }

    /// The challenge identity: exactly the carrier request identity.
    #[must_use]
    pub fn challenge_id(&self) -> &str {
        self.request.request_id.as_str()
    }

    /// The owner-epoch digest the answering owner must report.
    #[must_use]
    pub fn expected_owner_digest(&self) -> &str {
        &self.expected_owner_digest
    }

    /// The bounded wait, in seconds, granted to the owner contour.
    #[must_use]
    pub const fn wait_secs(&self) -> u64 {
        self.wait_secs
    }

    /// The protocol revision this challenge was issued under.
    #[must_use]
    pub const fn protocol_revision(&self) -> u16 {
        self.protocol_revision
    }
}

/// Validates one owner answer against the challenge that issued it.
///
/// Runs the original wire-owner response validator, then requires exact
/// correlation with the challenge carrier via the original
/// [`response_matches_request`] predicate. A forged, replayed, or
/// wrong-epoch response cannot satisfy both validators at once.
///
/// A successful validation proves only that the current Host control owner
/// answered this exact challenge within its bound — the declared control
/// property — not whole-product readiness. Freshness of the
/// `expected_owner_digest` against the live target, and replay resistance
/// across challenge identities, are the challenger's duty at issue time: one
/// envelope answers exactly one challenge identity.
///
/// # Errors
///
/// Returns a refusal when the envelope or response fails validation, or when
/// the response does not exactly correlate with the challenge carrier.
pub fn validate_owner_challenge_response(
    envelope: &OwnerChallengeEnvelope,
    response: &HostRuntimeControlResponse,
) -> Result<(), String> {
    if envelope.protocol_revision != OWNER_CHALLENGE_PROTOCOL_REVISION {
        return Err("challenge protocol revision mismatch".to_owned());
    }
    envelope.request.validate()?;
    response.validate()?;
    if !response_matches_request(&envelope.request, response) {
        return Err("response does not exactly correlate with the challenge".to_owned());
    }
    Ok(())
}

/// One Watchdog-issued responsiveness challenge bound to the wire-owner
/// challenge contract (`eliot-host-service::runtime_control`).
///
/// This is the typed form of [`OwnerChallengeEnvelope`]: the challenge
/// identity is the carrier request's `request_id` (exactly the wire-owner
/// challenge's `challenge_id`), and the expected owner digest is the
/// wire-owner challenge's `expected_owner_epoch_digest`. Every validation
/// below reuses the wire-owner validators; this cell adds only the
/// carrier-to-challenge identity binding.
///
/// The answering side is the Host control-owner contour that drains the
/// bounded owner queue (see [`owner_answer_correlates`]). STITCH: the
/// production caller lives in the Host composition lane
/// (`bins/eliot-host/src/main.rs`, `process_runtime_control_requests`), which
/// must call the wire-owner [`HostControlChallengeResponse::answer`]
/// constructor at the queue drain and pass the result through the correlation
/// gate here; until it is wired, neither call has a production caller.
pub struct TypedOwnerChallenge {
    request: HostRuntimeControlRequest,
    challenge: HostControlChallenge,
}

impl TypedOwnerChallenge {
    /// Binds an issued wire-owner challenge to the exact owner-path request
    /// that carries it.
    ///
    /// Runs both wire-owner validators, then requires the challenge identity
    /// to equal the carrier request identity: a challenge bound to another
    /// carrier cannot be issued here. Agreement on the expected owner digest
    /// is enforced at answer time by exact correlation.
    ///
    /// # Errors
    ///
    /// Returns a refusal when either peer fails its own validation or when
    /// the challenge identity is not the carrier request identity.
    pub fn bind(
        request: HostRuntimeControlRequest,
        challenge: HostControlChallenge,
    ) -> Result<Self, String> {
        request.validate()?;
        challenge.validate()?;
        if challenge.challenge_id.as_str() != request.request_id.as_str() {
            return Err("challenge identity is not the carrier request identity".to_owned());
        }
        Ok(Self { request, challenge })
    }

    /// The exact owner-path request carrying this challenge.
    #[must_use]
    pub const fn request(&self) -> &HostRuntimeControlRequest {
        &self.request
    }

    /// The bound wire-owner challenge.
    #[must_use]
    pub const fn challenge(&self) -> &HostControlChallenge {
        &self.challenge
    }

    /// The challenge identity: exactly the carrier request identity.
    #[must_use]
    pub fn challenge_id(&self) -> &str {
        self.challenge.challenge_id.as_str()
    }
}

/// Checks one contour-produced answer for exact correlation before the
/// endpoint serializes it onto the owner queue reply.
///
/// The answer itself is constructed with the wire-owner constructor
/// ([`HostControlChallengeResponse::answer`]) at the owner-queue drain, from
/// the contour's current owner/epoch digests plus the defined control-progress
/// observation. This gate then requires both wire-owner validators to hold
/// and the answer to correlate exactly (same challenge identity, same
/// revision, answering owner/epoch equal to the expected owner-epoch digest).
/// A listener-thread echo, a healthy-helper answer, or a Kernel/daemon reply
/// carries a different owner digest and cannot correlate.
///
/// STITCH (Host composition lane): call the wire-owner `answer` constructor
/// inside the owner-queue drain in `bins/eliot-host/src/main.rs`
/// (`process_runtime_control_requests`) so the answer carries the contour's
/// live owner/epoch plus its loop-advance observation, then pass the result
/// through this gate before replying. Until then neither call has a
/// production caller.
#[must_use]
pub fn owner_answer_correlates(
    bound: &TypedOwnerChallenge,
    response: &HostControlChallengeResponse,
) -> bool {
    bound.request.validate().is_ok()
        && response.validate().is_ok()
        && response.correlates(bound.challenge())
}

/// Validates one typed owner answer against the bound challenge.
///
/// Runs both wire-owner validators, then requires exact correlation (same
/// challenge identity, same revision, answering owner/epoch equal to the
/// expected owner-epoch digest), freshness within the absolute deadline, and
/// replay refusal when the challenger already consumed this identity. A
/// forged, replayed, wrong-epoch, or stale answer cannot satisfy all gates at
/// once.
///
/// A successful validation proves only that the current Host control owner
/// answered this exact challenge within its bound — the declared control
/// property — not whole-product readiness.
///
/// # Errors
///
/// Returns a refusal when any gate above fails.
pub fn validate_typed_owner_challenge_response(
    bound: &TypedOwnerChallenge,
    response: &HostControlChallengeResponse,
    already_answered: bool,
    now_unix_ms: u64,
) -> Result<(), String> {
    bound.request.validate()?;
    response.validate_against(bound.challenge(), already_answered, now_unix_ms)
}
