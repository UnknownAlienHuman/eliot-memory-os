//! Replay-stable owner state for one published WASM join.
//!
//! Issue #2786 requires one-shot delivery consumption to survive an exact
//! publication replay. The existing join table owns admission, but its
//! registration operation replaces the retained record with `consumed=false`.
//! That makes a byte-identical replay capable of re-arming an already-spent
//! delivery before the table is moved into long-lived Kernel state.
//!
//! This module owns the missing pure state transition. It performs no file I/O,
//! starts no process, retains no guest bytes and grants no execution. A later
//! wiring change can make `WasmJoinTable::register_delivery` delegate to this
//! transition and then hoist the table into the composition root without
//! changing the replay semantics again.

use crate::wasm_dispatch::{
    JoinDeny, WASM_DELIVERY_IDENTITY_VERSION, WasmDeliveryIdentity, WasmJoinGate,
};

/// Complete identity retained for one registered WASM join.
///
/// The binding contains every value the one-shot admission gate compares plus
/// the publication identity that distinguishes a genuine replacement from an
/// exact replay. It contains no artifact or input bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmJoinRegistrationBinding {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Child-identical authority identity.
    pub authority_id: String,
    /// Owner-issued grant digest.
    pub grant_digest: String,
    /// Forward-issued invocation digest.
    pub invocation_digest: String,
    /// Bound delivery-envelope digest.
    pub envelope_digest: String,
    /// Grant expiry in Unix milliseconds.
    pub expires_at: u64,
    /// Delivery identity contract version.
    pub delivery_version: u16,
    /// Stable publication incarnation for this admission.
    pub publication_incarnation: u64,
    /// Exact publication revision retained for diagnostics and conflict proof.
    pub publication_revision: u64,
}

impl WasmJoinRegistrationBinding {
    /// Builds the registration binding from the already-published join and its
    /// exact delivery identity.
    ///
    /// The function re-joins all overlapping fields. A caller cannot pair a
    /// join with another claim, operation, grant, expiry or delivery envelope
    /// and still obtain a registration state.
    ///
    /// # Errors
    ///
    /// Returns [`WasmJoinRegistrationError`] when either input is malformed or
    /// the join and delivery do not describe the same publication.
    pub fn from_published(
        join: &WasmJoinGate,
        delivery: &WasmDeliveryIdentity,
    ) -> Result<Self, WasmJoinRegistrationError> {
        require_text(&join.claim_id, "join.claim_id")?;
        require_text(&join.operation_id, "join.operation_id")?;
        require_text(&join.authority_id, "join.authority_id")?;
        require_digest(&join.grant_digest, "join.grant_digest")?;
        require_digest(&join.invocation_digest, "join.invocation_digest")?;
        require_digest(&delivery.envelope_digest, "delivery.envelope_digest")?;
        if join.expires_at == 0 {
            return Err(WasmJoinRegistrationError::InvalidField(
                "join.expires_at",
            ));
        }
        if delivery.delivery_version != WASM_DELIVERY_IDENTITY_VERSION {
            return Err(WasmJoinRegistrationError::InvalidField(
                "delivery.delivery_version",
            ));
        }
        if delivery.publication_incarnation == 0 || delivery.publication_revision == 0 {
            return Err(WasmJoinRegistrationError::InvalidField(
                "delivery.publication_identity",
            ));
        }
        if join.claim_id != delivery.claim_id {
            return Err(WasmJoinRegistrationError::BindingMismatch(
                "claim_id",
            ));
        }
        if join.operation_id != delivery.operation_id {
            return Err(WasmJoinRegistrationError::BindingMismatch(
                "operation_id",
            ));
        }
        if join.grant_digest != delivery.grant_digest {
            return Err(WasmJoinRegistrationError::BindingMismatch(
                "grant_digest",
            ));
        }
        if join.expires_at != delivery.expires_at {
            return Err(WasmJoinRegistrationError::BindingMismatch(
                "expires_at",
            ));
        }
        Ok(Self {
            claim_id: join.claim_id.clone(),
            operation_id: join.operation_id.clone(),
            authority_id: join.authority_id.clone(),
            grant_digest: join.grant_digest.clone(),
            invocation_digest: join.invocation_digest.clone(),
            envelope_digest: delivery.envelope_digest.clone(),
            expires_at: join.expires_at,
            delivery_version: delivery.delivery_version,
            publication_incarnation: delivery.publication_incarnation,
            publication_revision: delivery.publication_revision,
        })
    }
}

/// Retained replay state for one registered delivery-bound join.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmJoinRegistrationState {
    binding: WasmJoinRegistrationBinding,
    consumed: bool,
}

impl WasmJoinRegistrationState {
    /// Creates a fresh, unconsumed registration.
    #[must_use]
    pub const fn fresh(binding: WasmJoinRegistrationBinding) -> Self {
        Self {
            binding,
            consumed: false,
        }
    }

    /// Borrows the exact retained registration binding.
    #[must_use]
    pub const fn binding(&self) -> &WasmJoinRegistrationBinding {
        &self.binding
    }

    /// Reports whether the one-shot admission has already been consumed.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Admits one delivery-bound invocation and consumes the one-shot state.
    ///
    /// This is the record-level twin of `WasmJoinTable::admit_claim`: the
    /// retained binding must be fresh, both presented digests must match, and
    /// a successful admission flips the retained state exactly once. It does
    /// not remove stale state; the table owner retains that bounded cleanup
    /// responsibility.
    ///
    /// # Errors
    ///
    /// Returns the existing stable [`JoinDeny`] taxonomy for stale, replayed or
    /// mismatched presentations.
    pub fn admit_claim(
        &mut self,
        presented_invocation_digest: &str,
        presented_envelope_digest: &str,
        now_ms: u64,
    ) -> Result<(), JoinDeny> {
        if self.binding.expires_at <= now_ms {
            return Err(JoinDeny::Stale);
        }
        if self.consumed {
            return Err(JoinDeny::Replayed);
        }
        if self.binding.invocation_digest != presented_invocation_digest
            || self.binding.envelope_digest != presented_envelope_digest
        {
            return Err(JoinDeny::Mismatched);
        }
        self.consumed = true;
        Ok(())
    }
}

/// Outcome of reconciling one publication with retained registration state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WasmJoinRegistrationDisposition {
    /// No prior state existed; a fresh one-shot registration was created.
    Registered,
    /// The same publication replayed before consumption; the pending state was
    /// retained unchanged.
    ExactReplayPending,
    /// The same publication replayed after consumption; the spent state was
    /// retained unchanged and was not re-armed.
    ExactReplayConsumed,
}

/// Fail-closed registration transition errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WasmJoinRegistrationError {
    /// A required registration field is blank, malformed or uninitialized.
    #[error("WASM_JOIN_REGISTRATION_INVALID:{0}")]
    InvalidField(&'static str),
    /// The published join and delivery identity do not bind the same value.
    #[error("WASM_JOIN_REGISTRATION_BINDING_MISMATCH:{0}")]
    BindingMismatch(&'static str),
    /// A different publication was presented under a still-retained
    /// `(claim_id, operation_id)` owner key.
    #[error("WASM_JOIN_REGISTRATION_IDENTITY_CONFLICT")]
    IdentityConflict,
}

/// Reconciles a published join with the registration retained under its owner
/// key.
///
/// Exact replay is observational: it returns the byte-identical retained state
/// and preserves the one-shot consumption bit. A different binding under the
/// same key is an identity conflict, not a replacement or a fresh permit. The
/// caller must retire the previous owner record explicitly before registering a
/// genuinely new publication.
///
/// # Errors
///
/// Returns [`WasmJoinRegistrationError`] when the incoming publication is
/// malformed, does not bind internally, or conflicts with retained state.
pub fn reconcile_wasm_join_registration(
    retained: Option<&WasmJoinRegistrationState>,
    join: &WasmJoinGate,
    delivery: &WasmDeliveryIdentity,
) -> Result<
    (
        WasmJoinRegistrationState,
        WasmJoinRegistrationDisposition,
    ),
    WasmJoinRegistrationError,
> {
    let incoming = WasmJoinRegistrationBinding::from_published(join, delivery)?;
    let Some(retained) = retained else {
        return Ok((
            WasmJoinRegistrationState::fresh(incoming),
            WasmJoinRegistrationDisposition::Registered,
        ));
    };
    if retained.binding != incoming {
        return Err(WasmJoinRegistrationError::IdentityConflict);
    }
    let disposition = if retained.consumed {
        WasmJoinRegistrationDisposition::ExactReplayConsumed
    } else {
        WasmJoinRegistrationDisposition::ExactReplayPending
    };
    Ok((retained.clone(), disposition))
}

fn require_text(
    value: &str,
    field: &'static str,
) -> Result<(), WasmJoinRegistrationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(WasmJoinRegistrationError::InvalidField(field));
    }
    Ok(())
}

fn require_digest(
    value: &str,
    field: &'static str,
) -> Result<(), WasmJoinRegistrationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WasmJoinRegistrationError::InvalidField(field));
    }
    Ok(())
}
