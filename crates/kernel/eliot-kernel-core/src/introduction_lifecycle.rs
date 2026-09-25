//! Durable capability-introduction lifecycle compiler for P-07.
//!
//! The Governor service owns introduction compilation (I6.15): it resolves
//! the supporting grants, resource handle, facet manifest, holder, epochs,
//! and revisions into one complete [`IntroductionHydration`] whose opaque ORS
//! record carries the exact activation bytes. This module owns the Kernel
//! side of that contract: hydration shape and field completeness, the
//! mechanical fence-input derivation from owner-presented bytes, and the
//! digest the port binds into its idempotency gate.
//!
//! The Kernel fences presented authority and never invents introduction rows:
//!
//! - activation commits the owner-presented record verbatim after validation;
//! - revocation derives the fence record from the previously committed
//!   activation bytes with only the revocation record identity swapped in,
//!   mirroring the grant-closure member derivation;
//! - a `Fenced` row is fence evidence, never activatable authority: restore
//!   never reactivates a path or epoch.

use eliot_ors::{
    CapabilityIntroductionActivation, CapabilityIntroductionFence, OperationIdentity,
    OperationalRecordInput,
};

use crate::error::{KernelError, validate_id};
use crate::grant_activation_port::IntroductionActivationIntent;

/// Complete Governor-owned material needed to activate one capability
/// introduction durably.
///
/// The hydration source must provide every field; the Kernel supplies no
/// semantic default, resolves no supporting grant, and invents no facet,
/// holder, or revision. Without this material the thin introduction path
/// stays fail-closed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntroductionHydration {
    /// Complete semantic activation intent from the canonical Governor owner.
    pub intent: IntroductionActivationIntent,
    /// Opaque ORS input bound to the same introduction identity and fence.
    pub durable_record: CapabilityIntroductionActivation,
    /// Caller-supplied observation time for the activation gate.
    pub observed_at_ms: i64,
}

/// The complete field set a Governor hydration source must return for one
/// introduction.
///
/// This is deliberately kept beside [`IntroductionHydration`] so an auditor
/// can compare the accepted issue brief with the port boundary without
/// inferring completeness from a constructor or from later live-state
/// validation.
pub const INTRODUCTION_HYDRATION_FIELDS: &[&str] = &[
    "intent.operation_id",
    "intent.introduction_id",
    "intent.authority_root_ref",
    "intent.snapshot_id",
    "intent.grant_graph_revision",
    "intent.supporting_grant_ids",
    "intent.resource_handle",
    "intent.facet_manifest_ref",
    "intent.holder_principal",
    "intent.session_id",
    "intent.scope_id",
    "intent.binding",
    "intent.allowed_effect",
    "intent.proof_ceiling",
    "intent.issued_at_ms",
    "intent.expires_at_ms",
    "intent.receipt_obligations",
    "durable_record",
    "observed_at_ms",
];

impl IntroductionHydration {
    /// Checks every canonical field before the hydration enters the gate.
    ///
    /// The source owns semantic resolution, but the port owns this boundary
    /// check: no omitted/defaulted identity, lineage, binding, ceiling,
    /// time, or obligation field can reach ORS or live state. The opaque
    /// record must carry the intent identity so a row can never be bound to
    /// a different introduction.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] for any blank, defaulted, or
    /// disagreeing field. Binding, ceiling, and expiry gates run inside the
    /// port call against the active epoch and observation time.
    pub fn validate_complete(&self) -> Result<(), KernelError> {
        validate_id(&self.intent.operation_id, "hydration.intent.operation_id")?;
        validate_id(
            &self.intent.introduction_id,
            "hydration.intent.introduction_id",
        )?;
        validate_id(
            &self.intent.authority_root_ref,
            "hydration.intent.authority_root_ref",
        )?;
        validate_id(&self.intent.snapshot_id, "hydration.intent.snapshot_id")?;
        if self.intent.supporting_grant_ids.is_empty() {
            return Err(KernelError::InvalidField {
                field: "hydration.intent.supporting_grant_ids",
                reason: "at least one supporting grant is required",
            });
        }
        for supporting in &self.intent.supporting_grant_ids {
            validate_id(supporting, "hydration.intent.supporting_grant_id")?;
        }
        validate_id(
            &self.intent.resource_handle,
            "hydration.intent.resource_handle",
        )?;
        validate_id(
            &self.intent.facet_manifest_ref,
            "hydration.intent.facet_manifest_ref",
        )?;
        validate_id(
            &self.intent.holder_principal,
            "hydration.intent.holder_principal",
        )?;
        validate_id(&self.intent.session_id, "hydration.intent.session_id")?;
        validate_id(&self.intent.scope_id, "hydration.intent.scope_id")?;
        for obligation in &self.intent.receipt_obligations {
            validate_id(obligation, "hydration.intent.receipt_obligation")?;
        }
        if self.intent.grant_graph_revision == 0 {
            return Err(KernelError::InvalidField {
                field: "hydration.intent.grant_graph_revision",
                reason: "grant graph revision must be nonzero",
            });
        }
        if self.durable_record.record().record_id.as_str() != self.intent.operation_id
            || self.durable_record.record().subject_id.as_str() != self.intent.introduction_id
        {
            return Err(KernelError::InvalidField {
                field: "hydration.durable_record",
                reason: "hydrated opaque introduction record has a different identity",
            });
        }
        Ok(())
    }
}

/// Derives the fence record identity for one introduction revocation.
///
/// The identity binds the revocation operation to the fenced introduction so
/// a fence can never be mistaken for another operation's record.
#[must_use]
pub fn introduction_fence_record_id(operation_id: &str, introduction_id: &str) -> String {
    format!("{operation_id}/fence/{introduction_id}")
}

/// Builds one introduction fence record from its committed activation input:
/// the exact opaque bytes with only the revocation record identity swapped
/// in, mirroring the grant-closure member derivation.
///
/// The activation bytes are owner-presented (committed from
/// [`IntroductionHydration`] or read back from the durable row); only the
/// record identity changes, so the fence covers exactly the fenced authority
/// and nothing else.
///
/// # Errors
///
/// Returns [`KernelError::RecoveryState`] when the derived record identity
/// or the fenced input fails ORS validation.
pub fn introduction_fence_input(
    activation_input: &OperationalRecordInput,
    operation_id: &str,
) -> Result<CapabilityIntroductionFence, KernelError> {
    let introduction_id = activation_input.subject_id.as_str().to_owned();
    let mut input = activation_input.clone();
    input.record_id =
        OperationIdentity::new(introduction_fence_record_id(operation_id, &introduction_id))
            .map_err(KernelError::RecoveryState)?;
    CapabilityIntroductionFence::new(input).map_err(KernelError::RecoveryState)
}
