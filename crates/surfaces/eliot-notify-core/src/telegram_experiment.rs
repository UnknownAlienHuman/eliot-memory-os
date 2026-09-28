//! Experiment-scoped Telegram messaging adapter with proof-gated promotion.
//!
//! Telegram is the first `MessagingBridge` implementation experiment
//! (I10.23), not a core dependency. Local UI/CLI operation never requires
//! this module: the composition root holds it as `Option<TelegramExperiment>`
//! and every canonical delivery path runs unchanged when it is absent or
//! detached.
//!
//! Promotion to [`AdapterLifecycle::Default`] requires durable Product Proof
//! for all six I10.23 conditions named by the issue contract:
//! principal/session binding, text plus file delivery, restart between
//! result commit and send, visible unknown/duplicate handling, access
//! revocation, and non-reexecution of task effects. Each condition is
//! represented by the lowercase hexadecimal SHA-256 digest of its durable
//! receipt. Configuration alone (attached/enabled) can never promote: an
//! attached adapter with incomplete or malformed evidence stays
//! [`AdapterLifecycle::Experimental`].
//!
//! The same gate serves every subsequent messaging adapter through
//! [`adapter_promotion_status`] and [`promote_adapter_to_default`], so
//! adapter count can never substitute for the common-contract proof.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical identifier of the first messaging-adapter experiment.
pub const TELEGRAM_ADAPTER_ID: &str = "telegram";

/// Exact length of a lowercase hexadecimal SHA-256 receipt digest.
const RECEIPT_HEX_LENGTH: usize = 64;

/// Lifecycle of one messaging adapter.
///
/// The default state is [`AdapterLifecycle::Experimental`]; only a complete
/// and well-formed [`PromotionEvidence`] record advances an adapter to
/// [`AdapterLifecycle::Default`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterLifecycle {
    /// Experiment: usable only behind explicit opt-in, never a default.
    Experimental,
    /// Default: the six Product Proof receipts are present and well-formed.
    Default,
}

impl AdapterLifecycle {
    /// Returns true only for the promoted default state.
    #[must_use]
    pub const fn is_default(self) -> bool {
        matches!(self, Self::Default)
    }

    /// Returns true while the adapter remains an experiment.
    #[must_use]
    pub const fn is_experimental(self) -> bool {
        matches!(self, Self::Experimental)
    }
}

/// Typed, fail-closed promotion failure.
///
/// Every variant keeps the adapter [`AdapterLifecycle::Experimental`]; a
/// malformed handle, a revoked binding without its receipt, or a missing
/// condition is rejected rather than emulated with weaker guarantees.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PromotionError {
    /// The adapter identifier is empty, so no gate decision applies.
    #[error("messaging adapter id is empty")]
    EmptyAdapterId,
    /// One named Product Proof condition has no durable receipt.
    #[error("promotion evidence is missing: {0}")]
    MissingEvidence(&'static str),
    /// One named Product Proof receipt handle is malformed.
    #[error("promotion evidence is malformed: {0}")]
    InvalidEvidence(&'static str),
}

/// Durable Product Proof record gating adapter promotion.
///
/// Each field holds the lowercase hexadecimal SHA-256 digest of the durable
/// receipt evidencing one I10.23 promotion condition. `None` means the
/// condition has no receipt yet; the adapter remains experimental until
/// every field is present and well-formed.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PromotionEvidence {
    /// Receipt for principal/session binding of the enrolled platform identity.
    pub principal_session_binding: Option<String>,
    /// Receipt for text plus immutable-artifact file delivery.
    pub text_and_file_delivery: Option<String>,
    /// Receipt for restart between result commit and send (crash recovery).
    pub restart_between_commit_and_send: Option<String>,
    /// Receipt for visible unknown/duplicate delivery state.
    pub unknown_duplicate_visibility: Option<String>,
    /// Receipt for access revocation blocking future delivery.
    pub access_revocation: Option<String>,
    /// Receipt for non-reexecution of task effects during delivery recovery.
    pub non_reexecution: Option<String>,
}

impl PromotionEvidence {
    /// Empty record: no Product Proof condition is evidenced yet.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Returns true only when every condition carries a receipt handle.
    ///
    /// Presence alone does not promote; [`Self::validate`] additionally
    /// rejects malformed handles.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing_field().is_none()
    }

    /// Names the first condition without a receipt, if any.
    #[must_use]
    pub fn missing_field(&self) -> Option<&'static str> {
        if self.principal_session_binding.is_none() {
            return Some("principal_session_binding");
        }
        if self.text_and_file_delivery.is_none() {
            return Some("text_and_file_delivery");
        }
        if self.restart_between_commit_and_send.is_none() {
            return Some("restart_between_commit_and_send");
        }
        if self.unknown_duplicate_visibility.is_none() {
            return Some("unknown_duplicate_visibility");
        }
        if self.access_revocation.is_none() {
            return Some("access_revocation");
        }
        if self.non_reexecution.is_none() {
            return Some("non_reexecution");
        }
        None
    }

    /// Rejects a missing or malformed receipt handle.
    ///
    /// # Errors
    ///
    /// Returns [`PromotionError::MissingEvidence`] when a condition has no
    /// receipt and [`PromotionError::InvalidEvidence`] when a present handle
    /// is not a lowercase hexadecimal SHA-256 digest.
    pub fn validate(&self) -> Result<(), PromotionError> {
        if let Some(field) = self.missing_field() {
            return Err(PromotionError::MissingEvidence(field));
        }
        validate_receipt(
            self.principal_session_binding
                .as_deref()
                .unwrap_or_default(),
            "principal_session_binding",
        )?;
        validate_receipt(
            self.text_and_file_delivery.as_deref().unwrap_or_default(),
            "text_and_file_delivery",
        )?;
        validate_receipt(
            self.restart_between_commit_and_send
                .as_deref()
                .unwrap_or_default(),
            "restart_between_commit_and_send",
        )?;
        validate_receipt(
            self.unknown_duplicate_visibility
                .as_deref()
                .unwrap_or_default(),
            "unknown_duplicate_visibility",
        )?;
        validate_receipt(
            self.access_revocation.as_deref().unwrap_or_default(),
            "access_revocation",
        )?;
        validate_receipt(
            self.non_reexecution.as_deref().unwrap_or_default(),
            "non_reexecution",
        )?;
        Ok(())
    }
}

/// Rejects any receipt handle that is not a lowercase SHA-256 digest.
fn validate_receipt(value: &str, field: &'static str) -> Result<(), PromotionError> {
    let malformed = value.len() != RECEIPT_HEX_LENGTH
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase());
    if malformed {
        Err(PromotionError::InvalidEvidence(field))
    } else {
        Ok(())
    }
}

/// Reports the lifecycle for any messaging adapter under the common gate.
///
/// An empty adapter id, a missing receipt, or a malformed handle all resolve
/// to [`AdapterLifecycle::Experimental`]. This is the promotion query used by
/// every adapter generation, including the second adapter admitted only
/// after the same common-contract proof.
#[must_use]
pub fn adapter_promotion_status(
    adapter_id: &str,
    evidence: &PromotionEvidence,
) -> AdapterLifecycle {
    if adapter_id.is_empty() {
        return AdapterLifecycle::Experimental;
    }
    if evidence.validate().is_ok() {
        AdapterLifecycle::Default
    } else {
        AdapterLifecycle::Experimental
    }
}

/// Promotes an adapter to default only with complete, well-formed proof.
///
/// # Errors
///
/// Returns [`PromotionError::EmptyAdapterId`] for an empty adapter id,
/// [`PromotionError::MissingEvidence`] when a condition has no receipt, and
/// [`PromotionError::InvalidEvidence`] when a present handle is malformed.
/// The adapter remains experimental on every error; promotion is never
/// inferred from configuration alone.
pub fn promote_adapter_to_default(
    adapter_id: &str,
    evidence: &PromotionEvidence,
) -> Result<AdapterLifecycle, PromotionError> {
    if adapter_id.is_empty() {
        return Err(PromotionError::EmptyAdapterId);
    }
    evidence.validate()?;
    Ok(AdapterLifecycle::Default)
}

/// Experiment-scoped Telegram adapter handle.
///
/// `attached` is explicit opt-in configuration and is never promotion: the
/// lifecycle stays [`AdapterLifecycle::Experimental`] until the attached
/// evidence record validates. A detached handle and an absent (`None`)
/// composition slot are equivalent for canonical delivery, which never
/// requires this experiment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TelegramExperiment {
    attached: bool,
    evidence: PromotionEvidence,
}

impl TelegramExperiment {
    /// Detached handle: canonical delivery is unaffected.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            attached: false,
            evidence: PromotionEvidence::empty(),
        }
    }

    /// Explicitly attached handle with its durable Product Proof record.
    ///
    /// Attachment alone does not promote; [`Self::lifecycle`] still reports
    /// experimental until every receipt validates.
    #[must_use]
    pub fn attached(evidence: PromotionEvidence) -> Self {
        Self {
            attached: true,
            evidence,
        }
    }

    /// Returns true only after explicit opt-in attachment.
    #[must_use]
    pub const fn is_attached(&self) -> bool {
        self.attached
    }

    /// Borrows the durable Product Proof record.
    #[must_use]
    pub fn evidence(&self) -> &PromotionEvidence {
        &self.evidence
    }

    /// Reports the Telegram lifecycle under the common promotion gate.
    ///
    /// A detached experiment is always experimental; an attached experiment
    /// reaches default only through [`adapter_promotion_status`] with
    /// complete, well-formed proof.
    #[must_use]
    pub fn lifecycle(&self) -> AdapterLifecycle {
        if !self.attached {
            return AdapterLifecycle::Experimental;
        }
        adapter_promotion_status(TELEGRAM_ADAPTER_ID, &self.evidence)
    }
}
