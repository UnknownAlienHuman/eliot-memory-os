//! Owner-issued `WorkScopeResolutionReceipt`s (issue #1787, issuance slice).
//!
//! A receipt field claiming authentication — or a self-computed hash — does
//! not prove owner issuance. [`issue_resolution_receipt`] proves it the only
//! honest way: it reads the live [`WorkScopeBindingOwner`] at the admission
//! fence and refuses to issue unless that read succeeds, the retained binding
//! matches the retained [`WorkScopeDescriptor`] on every identity field, and
//! the retained guard receipt is `MATCHED` for the binding's current
//! generation. The selected identity and fingerprint then come from those
//! authenticated records, never from proposal claims.
//!
//! `Authenticated` issuance additionally requires a real source closure: the
//! retained binding is re-checked with [`ScopeBindingGuard`] against the
//! supplied [`GoverningSourceSet`] and [`PrivacyProfile`], and issuance fails
//! unless the fresh receipt is `MATCHED`. `Provisional` issuance records the
//! same evidence without source closure and can never admit Material effects;
//! admission withholds it (see `caller::verify_receipt_for_admission`).

use super::{
    GoverningSourceSet, IdentityEvidence, PrivacyProfile, ResolutionAuthentication,
    ScopeBindingDisposition, ScopeBindingGuard, ScopeFingerprint, WorkScopeBindingOwner,
    WorkScopeDescriptor, WorkScopeError, WorkScopeResolutionReceipt, text,
};
use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// How an issuance attempt failed without producing a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IssuanceRefusal {
    StaleOwnerFence,
    BindingDescriptorMismatch,
    GuardNotMatched,
    SourceClosureFailed,
}

/// Issues a durable resolution receipt from the live owner binding.
///
/// Consumes the actual authenticated binding (`owner` read at `fence`) and
/// the current resource description (`descriptor`). Every identity field of
/// the retained binding must equal the descriptor; the retained guard receipt
/// must be `MATCHED`. For `Authenticated` receipts the binding is additionally
/// re-checked against the supplied source closure and issuance fails unless
/// that fresh check is `MATCHED` too.
///
/// # Errors
///
/// Returns [`WorkScopeError`] when the owner read, descriptor, receipt shape,
/// or source closure is malformed, and [`IssuanceRefusal`] (as
/// `BindingReceiptMismatch` / `BindingReceiptNotMatched` /
/// `StateFenceMismatch`) when live records disagree.
#[allow(
    clippy::too_many_arguments,
    reason = "issuance joins every durable receipt field in one owner-checked constructor"
)]
pub fn issue_resolution_receipt(
    receipt_ref: impl Into<String>,
    proposal_ref: impl Into<String>,
    descriptor: &WorkScopeDescriptor,
    owner: &WorkScopeBindingOwner,
    fence: &StateFence,
    authentication: ResolutionAuthentication,
    supporting_evidence: Vec<IdentityEvidence>,
    rejected_candidate_refs: Vec<String>,
    unresolved_candidate_refs: Vec<String>,
    authority_ref: impl Into<String>,
    source_closure: Option<(&GoverningSourceSet, &PrivacyProfile)>,
) -> Result<WorkScopeResolutionReceipt, WorkScopeError> {
    let receipt_ref = receipt_ref.into();
    let proposal_ref = proposal_ref.into();
    let authority_ref = authority_ref.into();
    text(&receipt_ref, "receipt_ref")?;
    text(&proposal_ref, "proposal_ref")?;
    text(&authority_ref, "authority_ref")?;
    descriptor.validate()?;
    let snapshot = owner
        .read_current(fence)
        .map_err(|_| WorkScopeError::StateFenceMismatch)?;
    let bound = &snapshot.binding.scope;
    if bound.scope_ref != descriptor.scope_ref
        || bound.kind != descriptor.kind
        || bound.lineage_ref
            != descriptor
                .lineage
                .as_ref()
                .map(|lineage| lineage.lineage_ref.clone())
        || bound.generation != descriptor.generation.resource_generation.value()
        || !descriptor.instances.iter().any(|instance| {
            instance.instance_ref == bound.instance_ref
                && instance.root_identity == bound.root_identity
        })
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    if snapshot.guard_receipt.disposition != ScopeBindingDisposition::Matched {
        return Err(WorkScopeError::BindingReceiptNotMatched);
    }
    if authentication == ResolutionAuthentication::Authenticated {
        let Some((sources, privacy)) = source_closure else {
            return Err(WorkScopeError::PrivacyDenied);
        };
        let fresh = ScopeBindingGuard.check(&snapshot.binding, &snapshot.binding, sources, privacy);
        if fresh.disposition != ScopeBindingDisposition::Matched {
            return Err(WorkScopeError::BindingReceiptNotMatched);
        }
    }
    let receipt = WorkScopeResolutionReceipt {
        receipt_ref,
        proposal_ref,
        selected: snapshot.binding.clone().scope,
        fingerprint: ScopeFingerprint::derive_for(descriptor),
        authentication,
        supporting_evidence,
        rejected_candidate_refs,
        unresolved_candidate_refs,
        authority_ref,
        state_fence: fence.clone(),
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Names the [`IssuanceRefusal`] behind a refusal error for callers that map
/// it to trigger verdicts without string matching.
#[must_use]
pub fn issuance_refusal(error: &WorkScopeError) -> Option<IssuanceRefusal> {
    match error {
        WorkScopeError::StateFenceMismatch => Some(IssuanceRefusal::StaleOwnerFence),
        WorkScopeError::BindingReceiptMismatch => {
            Some(IssuanceRefusal::BindingDescriptorMismatch)
        }
        WorkScopeError::BindingReceiptNotMatched => Some(IssuanceRefusal::GuardNotMatched),
        WorkScopeError::PrivacyDenied => Some(IssuanceRefusal::SourceClosureFailed),
        _ => None,
    }
}
