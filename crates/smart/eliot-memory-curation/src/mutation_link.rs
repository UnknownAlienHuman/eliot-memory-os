//! Mutation-path linkage for lifecycle receipts (#1905).
//!
//! This module is linkage only: it binds one explicit semantic-state
//! transition to the canonical mutation that persists it. The canonical
//! store owner persists [`CurationMutationLink`] rows through exactly one
//! of the four named operations; this crate never captures, revises,
//! polices, or audits by itself. Corrections stay forward revisions, and a
//! model paraphrase never inherits elevated standing without an
//! independent qualifying basis.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical mutation operations that may persist a lifecycle transition.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MutationOperation {
    /// Persists a raw capture as an observation candidate.
    CaptureObservation,
    /// Persists a forward epistemic revision or supersession.
    ApplyEpistemicRevision,
    /// Persists a governed lifecycle policy decision.
    ApplyLifecyclePolicy,
    /// Links a stable receipt id to its audit event.
    AppendAuditEvent,
}

impl MutationOperation {
    /// Exact store wire name of the operation.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CaptureObservation => "CaptureObservation",
            Self::ApplyEpistemicRevision => "ApplyEpistemicRevision",
            Self::ApplyLifecyclePolicy => "ApplyLifecyclePolicy",
            Self::AppendAuditEvent => "AppendAuditEvent",
        }
    }
}

/// Failures for mutation linkage construction and chain inspection.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MutationLinkError {
    /// A required text field is blank or carries control characters.
    #[error("{field} is blank or contains a control character")]
    InvalidText { field: &'static str },
    /// No immutable input handles were named.
    #[error("mutation link names no input handles")]
    EmptyInputs,
    /// The same handle was named twice.
    #[error("mutation link names a duplicate handle")]
    Duplicate,
    /// A digest is not lowercase hex of the expected width.
    #[error("{field} must be lowercase hex")]
    InvalidDigest { field: &'static str },
    /// A model paraphrase claims elevated standing without basis.
    #[error("model paraphrase lacks an independent qualifying basis for {role}")]
    ForbiddenElevation { role: String },
    /// A correction names no superseded handle.
    #[error("correction requires a forward supersession link")]
    NotForwardRevision,
    /// A superseded handle is outside the transition inputs.
    #[error("superseded handle is outside the transition inputs")]
    SupersededOutsideInputs,
    /// A new revision reuses a superseded handle as its output.
    #[error("new revision must not reuse a superseded handle")]
    OutputReusesSuperseded,
    /// Evidence and counterevidence name the same handle.
    #[error("evidence and counterevidence must be disjoint")]
    EvidenceOverlap,
    /// Capture genesis rules were violated.
    #[error("capture genesis must persist one observation candidate")]
    BadGenesis,
    /// Audit linkage is missing where the chain requires it.
    #[error("mutation link is not linked through AppendAuditEvent")]
    AuditUnlinked,
    /// Chain linkage is broken; the reason names the failing hop.
    #[error("mutation chain is broken: {reason}")]
    BrokenChain { reason: String },
    /// A chain holds no links.
    #[error("mutation chain is empty")]
    EmptyChain,
    /// A value could not be canonicalized for its digest.
    #[error("cannot canonicalize mutation link shape")]
    Canonicalization,
}

fn text(value: &str, field: &'static str) -> Result<(), MutationLinkError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(MutationLinkError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn opt_text(value: Option<&String>, field: &'static str) -> Result<(), MutationLinkError> {
    if let Some(item) = value {
        text(item, field)?;
    }
    Ok(())
}

fn hex_digest(value: &str, field: &'static str) -> Result<(), MutationLinkError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(MutationLinkError::InvalidDigest { field });
    }
    Ok(())
}

fn sorted_unique(
    mut items: Vec<String>,
    field: &'static str,
) -> Result<Vec<String>, MutationLinkError> {
    for item in &items {
        text(item, field)?;
    }
    items.sort();
    if items.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(MutationLinkError::Duplicate);
    }
    Ok(items)
}

/// Normalizes a role name for the paraphrase guard.
fn norm_role(value: &str) -> String {
    value.trim().to_lowercase().replace(['_', ' '], "-")
}

/// Elevated roles a bare paraphrase must never inherit.
fn is_elevated_role(value: &str) -> bool {
    matches!(
        norm_role(value).as_str(),
        "verifier-backed" | "policy" | "procedure" | "proof" | "instruction"
    )
}

fn is_model_actor(value: &str) -> bool {
    value.to_lowercase().contains("model")
}

fn is_verified_status(value: &str) -> bool {
    norm_role(value) == "verified"
}

/// Named constructor arguments for [`CurationMutationLink::new`].
#[derive(Clone, Debug)]
pub struct CurationMutationLinkParams {
    /// Canonical mutation persisting the transition.
    pub operation: MutationOperation,
    /// Stable receipt id, linked through `AppendAuditEvent`.
    pub receipt_id: String,
    /// Immutable input record handles the transition reads.
    pub input_handles: Vec<String>,
    /// Exact source anchor and revision behind the inputs.
    pub source_anchor: String,
    /// Prior semantic role.
    pub prior_role: String,
    /// Proposed semantic role.
    pub proposed_role: String,
    /// Prior epistemic status.
    pub prior_status: String,
    /// Proposed epistemic status.
    pub proposed_status: String,
    /// Actor or deterministic/model transformer identity.
    pub actor: String,
    /// Authority basis for the transition.
    pub authority_basis: String,
    /// Work scope of the transition.
    pub scope: String,
    /// Opaque fence binding digest for the transition.
    pub fence_digest: String,
    /// Evidence references behind the decision.
    pub evidence_refs: Vec<String>,
    /// Counterevidence references preserved by the decision.
    pub counterevidence_refs: Vec<String>,
    /// Explicit admission outcome.
    pub outcome: String,
    /// Independent qualifying basis, when elevated standing is claimed.
    pub qualifying_basis: Option<String>,
    /// Forward supersession links; empty for a genesis capture.
    pub supersedes: Vec<String>,
    /// Output record handle produced by the transition.
    pub output_handle: String,
    /// `AppendAuditEvent` linkage, when already recorded.
    pub audit_event_id: Option<String>,
    /// Digest of the bounded proof payload behind the transition.
    pub proof_digest: String,
}

/// One explicit transition bound to its persisting canonical mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationMutationLink {
    /// Canonical mutation persisting the transition.
    pub operation: MutationOperation,
    /// Stable receipt id, linked through `AppendAuditEvent`.
    pub receipt_id: String,
    /// Immutable input record handles, in sorted order.
    pub input_handles: Vec<String>,
    /// Exact source anchor and revision behind the inputs.
    pub source_anchor: String,
    /// Prior semantic role.
    pub prior_role: String,
    /// Proposed semantic role.
    pub proposed_role: String,
    /// Prior epistemic status.
    pub prior_status: String,
    /// Proposed epistemic status.
    pub proposed_status: String,
    /// Actor or deterministic/model transformer identity.
    pub actor: String,
    /// Authority basis for the transition.
    pub authority_basis: String,
    /// Work scope of the transition.
    pub scope: String,
    /// Opaque fence binding digest for the transition.
    pub fence_digest: String,
    /// Evidence references, in sorted order.
    pub evidence_refs: Vec<String>,
    /// Counterevidence references, in sorted order.
    pub counterevidence_refs: Vec<String>,
    /// Explicit admission outcome.
    pub outcome: String,
    /// Independent qualifying basis, when elevated standing is claimed.
    pub qualifying_basis: Option<String>,
    /// Forward supersession links, in sorted order.
    pub supersedes: Vec<String>,
    /// Output record handle produced by the transition.
    pub output_handle: String,
    /// `AppendAuditEvent` linkage, when already recorded.
    pub audit_event_id: Option<String>,
    /// Digest of the bounded proof payload.
    pub proof_digest: String,
    /// Canonical digest of this link shape, excluding this field.
    pub digest: String,
}

/// Canonical digest shape of a link, excluding the frozen digest field.
#[derive(Serialize)]
struct LinkDigestShape<'a> {
    operation: &'a MutationOperation,
    receipt_id: &'a str,
    input_handles: &'a [String],
    source_anchor: &'a str,
    prior_role: &'a str,
    proposed_role: &'a str,
    prior_status: &'a str,
    proposed_status: &'a str,
    actor: &'a str,
    authority_basis: &'a str,
    scope: &'a str,
    fence_digest: &'a str,
    evidence_refs: &'a [String],
    counterevidence_refs: &'a [String],
    outcome: &'a str,
    qualifying_basis: &'a Option<String>,
    supersedes: &'a [String],
    output_handle: &'a str,
    audit_event_id: &'a Option<String>,
    proof_digest: &'a str,
}

fn canonical(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonical).collect())
        }
        serde_json::Value::Object(object) => {
            let mut entries: Vec<_> = object.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = serde_json::Map::new();
            for (key, item) in entries {
                sorted.insert(key, canonical(item));
            }
            serde_json::Value::Object(sorted)
        }
        scalar => scalar,
    }
}

fn shape_digest<T: Serialize>(shape: &T) -> Result<String, MutationLinkError> {
    let value = serde_json::to_value(shape).map_err(|_| MutationLinkError::Canonicalization)?;
    let bytes =
        serde_json::to_vec(&canonical(value)).map_err(|_| MutationLinkError::Canonicalization)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

impl CurationMutationLink {
    /// Constructs a mutation link after validating every linkage field.
    pub fn new(mut params: CurationMutationLinkParams) -> Result<Self, MutationLinkError> {
        params.input_handles = sorted_unique(params.input_handles, "link.input_handles")?;
        params.evidence_refs = sorted_unique(params.evidence_refs, "link.evidence_refs")?;
        params.counterevidence_refs =
            sorted_unique(params.counterevidence_refs, "link.counterevidence_refs")?;
        params.supersedes = sorted_unique(params.supersedes, "link.supersedes")?;
        let mut link = Self {
            operation: params.operation,
            receipt_id: params.receipt_id,
            input_handles: params.input_handles,
            source_anchor: params.source_anchor,
            prior_role: params.prior_role,
            proposed_role: params.proposed_role,
            prior_status: params.prior_status,
            proposed_status: params.proposed_status,
            actor: params.actor,
            authority_basis: params.authority_basis,
            scope: params.scope,
            fence_digest: params.fence_digest,
            evidence_refs: params.evidence_refs,
            counterevidence_refs: params.counterevidence_refs,
            outcome: params.outcome,
            qualifying_basis: params.qualifying_basis,
            supersedes: params.supersedes,
            output_handle: params.output_handle,
            audit_event_id: params.audit_event_id,
            proof_digest: params.proof_digest,
            digest: String::new(),
        };
        link.validate_shape()?;
        link.digest = link.compute_digest()?;
        Ok(link)
    }

    /// Computes the frozen digest over the canonical link shape.
    pub fn compute_digest(&self) -> Result<String, MutationLinkError> {
        shape_digest(&LinkDigestShape {
            operation: &self.operation,
            receipt_id: self.receipt_id.as_str(),
            input_handles: &self.input_handles,
            source_anchor: self.source_anchor.as_str(),
            prior_role: self.prior_role.as_str(),
            proposed_role: self.proposed_role.as_str(),
            prior_status: self.prior_status.as_str(),
            proposed_status: self.proposed_status.as_str(),
            actor: self.actor.as_str(),
            authority_basis: self.authority_basis.as_str(),
            scope: self.scope.as_str(),
            fence_digest: self.fence_digest.as_str(),
            evidence_refs: &self.evidence_refs,
            counterevidence_refs: &self.counterevidence_refs,
            outcome: self.outcome.as_str(),
            qualifying_basis: &self.qualifying_basis,
            supersedes: &self.supersedes,
            output_handle: self.output_handle.as_str(),
            audit_event_id: &self.audit_event_id,
            proof_digest: self.proof_digest.as_str(),
        })
    }

    /// Whether the link carries its `AppendAuditEvent` linkage.
    pub const fn is_audit_linked(&self) -> bool {
        self.audit_event_id.is_some()
    }

    /// Returns a copy of this link bound to one audit event.
    pub fn link_audit(&self, event: String) -> Result<Self, MutationLinkError> {
        text(&event, "link.audit_event_id")?;
        let mut linked = self.clone();
        linked.audit_event_id = Some(event);
        linked.validate_shape()?;
        linked.digest = linked.compute_digest()?;
        Ok(linked)
    }

    /// Validates shape plus the frozen digest.
    pub fn validate(&self) -> Result<(), MutationLinkError> {
        self.validate_shape()?;
        let expected = self.compute_digest()?;
        if self.digest != expected {
            return Err(MutationLinkError::InvalidDigest {
                field: "link.digest",
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), MutationLinkError> {
        text(&self.receipt_id, "link.receipt_id")?;
        if self.input_handles.is_empty() {
            return Err(MutationLinkError::EmptyInputs);
        }
        text(&self.source_anchor, "link.source_anchor")?;
        text(&self.prior_role, "link.prior_role")?;
        text(&self.proposed_role, "link.proposed_role")?;
        text(&self.prior_status, "link.prior_status")?;
        text(&self.proposed_status, "link.proposed_status")?;
        text(&self.actor, "link.actor")?;
        text(&self.authority_basis, "link.authority_basis")?;
        text(&self.scope, "link.scope")?;
        hex_digest(&self.fence_digest, "link.fence_digest")?;
        text(&self.outcome, "link.outcome")?;
        opt_text(self.qualifying_basis.as_ref(), "link.qualifying_basis")?;
        text(&self.output_handle, "link.output_handle")?;
        opt_text(self.audit_event_id.as_ref(), "link.audit_event_id")?;
        hex_digest(&self.proof_digest, "link.proof_digest")?;
        let evidence: BTreeSet<_> = self.evidence_refs.iter().collect();
        for handle in &self.counterevidence_refs {
            if evidence.contains(handle) {
                return Err(MutationLinkError::EvidenceOverlap);
            }
        }
        for superseded in &self.supersedes {
            if !self.input_handles.contains(superseded) {
                return Err(MutationLinkError::SupersededOutsideInputs);
            }
            if superseded == &self.output_handle {
                return Err(MutationLinkError::OutputReusesSuperseded);
            }
        }
        if norm_role(&self.outcome) == "corrected-forward" && self.supersedes.is_empty() {
            return Err(MutationLinkError::NotForwardRevision);
        }
        self.check_operation_shape()?;
        self.check_paraphrase_guard()?;
        Ok(())
    }

    fn check_operation_shape(&self) -> Result<(), MutationLinkError> {
        match self.operation {
            MutationOperation::CaptureObservation => {
                if self.input_handles.len() != 1
                    || self.output_handle != self.input_handles[0]
                    || !self.supersedes.is_empty()
                    || norm_role(&self.proposed_role) != "observation-candidate"
                {
                    return Err(MutationLinkError::BadGenesis);
                }
                Ok(())
            }
            MutationOperation::AppendAuditEvent => {
                if self.audit_event_id.is_none() {
                    return Err(MutationLinkError::AuditUnlinked);
                }
                Ok(())
            }
            MutationOperation::ApplyEpistemicRevision | MutationOperation::ApplyLifecyclePolicy => {
                Ok(())
            }
        }
    }

    /// Rejects model paraphrases that claim elevated or verified standing
    /// without an independent qualifying basis.
    fn check_paraphrase_guard(&self) -> Result<(), MutationLinkError> {
        let needs_basis =
            is_elevated_role(&self.proposed_role) || is_verified_status(&self.proposed_status);
        if needs_basis
            && is_model_actor(&self.actor)
            && self
                .qualifying_basis
                .as_ref()
                .is_none_or(|basis| basis.trim().is_empty())
        {
            return Err(MutationLinkError::ForbiddenElevation {
                role: self.proposed_role.clone(),
            });
        }
        Ok(())
    }
}

/// Inspectable view of one complete mutation chain from a raw observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationChainView {
    /// Ordered links from the genesis capture to the current head.
    pub ordered: Vec<CurationMutationLink>,
    /// Raw observation handle the chain starts from.
    pub original_input: String,
    /// Current output handle at the head of the chain.
    pub current_output: String,
}

/// Verifies that mutation links form one inspectable chain.
///
/// The first link must be a `CaptureObservation` genesis, every hop must
/// consume the prior output, every superseded handle must resolve to
/// earlier history, and every link must carry its `AppendAuditEvent`
/// linkage.
pub fn verify_mutation_chain(
    links: &[CurationMutationLink],
) -> Result<MutationChainView, MutationLinkError> {
    let first = links.first().ok_or(MutationLinkError::EmptyChain)?;
    for link in links {
        link.validate()?;
        if !link.is_audit_linked() {
            return Err(MutationLinkError::AuditUnlinked);
        }
    }
    if first.operation != MutationOperation::CaptureObservation {
        return Err(MutationLinkError::BrokenChain {
            reason: "chain must start from a CaptureObservation genesis".to_owned(),
        });
    }
    let scope = first.scope.clone();
    let mut known: BTreeSet<&String> = BTreeSet::new();
    for handle in &first.input_handles {
        known.insert(handle);
    }
    known.insert(&first.output_handle);
    for pair in links.windows(2) {
        let (prior, next) = (&pair[0], &pair[1]);
        if next.scope != scope {
            return Err(MutationLinkError::BrokenChain {
                reason: "chain scope must not change silently".to_owned(),
            });
        }
        if !next.input_handles.contains(&prior.output_handle) {
            return Err(MutationLinkError::BrokenChain {
                reason: "hop does not consume the prior output".to_owned(),
            });
        }
        for superseded in &next.supersedes {
            if !known.contains(superseded) {
                return Err(MutationLinkError::BrokenChain {
                    reason: "superseded handle is not reconstructible".to_owned(),
                });
            }
        }
        for handle in &next.input_handles {
            known.insert(handle);
        }
        known.insert(&next.output_handle);
    }
    let Some(last) = links.last() else {
        return Err(MutationLinkError::EmptyChain);
    };
    let Some(original) = first.input_handles.first() else {
        return Err(MutationLinkError::EmptyChain);
    };
    Ok(MutationChainView {
        ordered: links.to_vec(),
        original_input: original.clone(),
        current_output: last.output_handle.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn fence_digest() -> String {
        blake3::hash(b"fixture-fence").to_hex().to_string()
    }

    fn proof(label: &str) -> String {
        blake3::hash(label.as_bytes()).to_hex().to_string()
    }

    fn capture() -> CurationMutationLink {
        CurationMutationLink::new(CurationMutationLinkParams {
            operation: MutationOperation::CaptureObservation,
            receipt_id: "receipt:capture".to_owned(),
            input_handles: vec!["obs:raw-1".to_owned()],
            source_anchor: "fixture-source@r1".to_owned(),
            prior_role: "observation-candidate".to_owned(),
            proposed_role: "observation-candidate".to_owned(),
            prior_status: "observed".to_owned(),
            proposed_status: "observed".to_owned(),
            actor: "deterministic-transformer:fixture".to_owned(),
            authority_basis: "fixture-grant".to_owned(),
            scope: "scope".to_owned(),
            fence_digest: fence_digest(),
            evidence_refs: vec!["obs:raw-1".to_owned()],
            counterevidence_refs: Vec::new(),
            outcome: "admitted".to_owned(),
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_handle: "obs:raw-1".to_owned(),
            audit_event_id: None,
            proof_digest: proof("capture-proof"),
        })
        .expect("valid capture link")
    }

    #[test]
    fn capture_to_claim_chain_is_inspectable() {
        let genesis = capture()
            .link_audit("audit:capture".to_owned())
            .expect("audit linkage");
        let revision = CurationMutationLink::new(CurationMutationLinkParams {
            operation: MutationOperation::ApplyEpistemicRevision,
            receipt_id: "receipt:claim".to_owned(),
            input_handles: vec!["obs:raw-1".to_owned()],
            source_anchor: "fixture-source@r1".to_owned(),
            prior_role: "observation-candidate".to_owned(),
            proposed_role: "claim".to_owned(),
            prior_status: "observed".to_owned(),
            proposed_status: "supported".to_owned(),
            actor: "human-operator:fixture".to_owned(),
            authority_basis: "fixture-grant".to_owned(),
            scope: "scope".to_owned(),
            fence_digest: fence_digest(),
            evidence_refs: vec!["obs:raw-1".to_owned()],
            counterevidence_refs: Vec::new(),
            outcome: "admitted".to_owned(),
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_handle: "claim:1".to_owned(),
            audit_event_id: None,
            proof_digest: proof("claim-proof"),
        })
        .expect("valid revision link")
        .link_audit("audit:claim".to_owned())
        .expect("audit linkage");
        let policy = CurationMutationLink::new(CurationMutationLinkParams {
            operation: MutationOperation::ApplyLifecyclePolicy,
            receipt_id: "receipt:active".to_owned(),
            input_handles: vec!["claim:1".to_owned()],
            source_anchor: "fixture-source@r1".to_owned(),
            prior_role: "claim".to_owned(),
            proposed_role: "claim".to_owned(),
            prior_status: "supported".to_owned(),
            proposed_status: "supported".to_owned(),
            actor: "governance-policy:fixture".to_owned(),
            authority_basis: "fixture-policy-v1".to_owned(),
            scope: "scope".to_owned(),
            fence_digest: fence_digest(),
            evidence_refs: vec!["claim:1".to_owned()],
            counterevidence_refs: Vec::new(),
            outcome: "admitted".to_owned(),
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_handle: "claim:1".to_owned(),
            audit_event_id: None,
            proof_digest: proof("policy-proof"),
        })
        .expect("valid policy link")
        .link_audit("audit:active".to_owned())
        .expect("audit linkage");
        let view = verify_mutation_chain(&[genesis, revision, policy]).expect("chain");
        assert_eq!(view.original_input, "obs:raw-1");
        assert_eq!(view.current_output, "claim:1");
        assert_eq!(view.ordered.len(), 3);
        assert!(
            view.ordered
                .iter()
                .all(CurationMutationLink::is_audit_linked)
        );
    }

    #[test]
    fn correction_is_forward_supersession() {
        let genesis = capture()
            .link_audit("audit:capture".to_owned())
            .expect("audit linkage");
        let correction = CurationMutationLink::new(CurationMutationLinkParams {
            operation: MutationOperation::ApplyEpistemicRevision,
            receipt_id: "receipt:correction".to_owned(),
            input_handles: vec!["obs:raw-1".to_owned()],
            source_anchor: "fixture-source@r1".to_owned(),
            prior_role: "observation-candidate".to_owned(),
            proposed_role: "observation-candidate".to_owned(),
            prior_status: "observed".to_owned(),
            proposed_status: "observed".to_owned(),
            actor: "human-operator:fixture".to_owned(),
            authority_basis: "fixture-grant".to_owned(),
            scope: "scope".to_owned(),
            fence_digest: fence_digest(),
            evidence_refs: vec!["obs:raw-1".to_owned()],
            counterevidence_refs: Vec::new(),
            outcome: "corrected-forward".to_owned(),
            qualifying_basis: None,
            supersedes: vec!["obs:raw-1".to_owned()],
            output_handle: "obs:raw-2".to_owned(),
            audit_event_id: None,
            proof_digest: proof("correction-proof"),
        })
        .expect("valid correction link")
        .link_audit("audit:correction".to_owned())
        .expect("audit linkage");
        let view = verify_mutation_chain(&[genesis, correction]).expect("chain");
        assert_eq!(view.original_input, "obs:raw-1");
        assert_eq!(view.current_output, "obs:raw-2");
    }

    #[test]
    fn model_paraphrase_refused_elevated_standing() {
        let refused = CurationMutationLink::new(CurationMutationLinkParams {
            operation: MutationOperation::ApplyEpistemicRevision,
            receipt_id: "receipt:paraphrase".to_owned(),
            input_handles: vec!["obs:raw-1".to_owned()],
            source_anchor: "fixture-source@r1".to_owned(),
            prior_role: "observation-candidate".to_owned(),
            proposed_role: "proof".to_owned(),
            prior_status: "observed".to_owned(),
            proposed_status: "supported".to_owned(),
            actor: "model-transformer:fixture".to_owned(),
            authority_basis: "fixture-grant".to_owned(),
            scope: "scope".to_owned(),
            fence_digest: fence_digest(),
            evidence_refs: vec!["obs:raw-1".to_owned()],
            counterevidence_refs: Vec::new(),
            outcome: "admitted".to_owned(),
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_handle: "proof:1".to_owned(),
            audit_event_id: None,
            proof_digest: proof("paraphrase-proof"),
        });
        assert!(matches!(
            refused,
            Err(MutationLinkError::ForbiddenElevation { .. })
        ));
        let qualified = CurationMutationLink::new(CurationMutationLinkParams {
            operation: MutationOperation::ApplyEpistemicRevision,
            receipt_id: "receipt:paraphrase-q".to_owned(),
            input_handles: vec!["obs:raw-1".to_owned()],
            source_anchor: "fixture-source@r1".to_owned(),
            prior_role: "observation-candidate".to_owned(),
            proposed_role: "proof".to_owned(),
            prior_status: "observed".to_owned(),
            proposed_status: "supported".to_owned(),
            actor: "model-transformer:fixture".to_owned(),
            authority_basis: "fixture-grant".to_owned(),
            scope: "scope".to_owned(),
            fence_digest: fence_digest(),
            evidence_refs: vec!["obs:raw-1".to_owned()],
            counterevidence_refs: Vec::new(),
            outcome: "admitted".to_owned(),
            qualifying_basis: Some("run:verifier-1".to_owned()),
            supersedes: Vec::new(),
            output_handle: "proof:1".to_owned(),
            audit_event_id: None,
            proof_digest: proof("paraphrase-proof"),
        })
        .expect("independently qualified paraphrase is admitted");
        assert_eq!(qualified.proposed_role, "proof");
    }
}
