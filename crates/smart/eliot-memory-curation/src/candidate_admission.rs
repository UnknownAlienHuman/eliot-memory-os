//! First production caller of the typed lifecycle admission path (#1905).
//!
//! [`CurationAdmission`] and [`verify_admission_chain`] validate explicit
//! semantic-state transitions, but until now nothing outside tests drove
//! them. This module connects the path to real curation inputs in both
//! directions the issue acceptance names:
//!
//! - raw observation → retained [`LifecycleRole::ObservationCandidate`]
//!   genesis admission ([`CurationMutationOperation::CaptureObservation`]);
//! - explicit admitted forward revision → stable transition receipt
//!   ([`CurationMutationOperation::ApplyEpistemicRevision`]), chained and
//!   verified so the original stays reconstructible, every hop linked
//!   through [`CurationMutationOperation::AppendAuditEvent`].
//!
//! Time, fence, and audit-event identity are caller-supplied: curation
//! never mints clocks, fences, or Store envelopes. Persistence stays with
//! the Store owner; [`StoreAdmissionProjection`] documents the exact 1:1
//! mapping of an admission onto a Store `NamedMutationRequest`
//! (`operation` + string `parameters`), so the Store caller persists
//! without any new shapes. No Store, Kernel, or Host file is touched here.

use std::collections::BTreeMap;

use eliot_contracts::{ArtifactId, ClockReading, StateFence};
use eliot_epistemic::lifecycle::{
    ActorIdentity, AdmissionOutcome, LifecycleReceipt, LifecycleReceiptParams, LifecycleRole,
    QualifyingBasis, SourceAnchor,
};
use eliot_evidence::EpistemicStatus;

use crate::admission::{
    AdmissionChainView, CurationAdmission, CurationMutationOperation, verify_admission_chain,
};

/// Caller-supplied inputs for one raw-observation genesis admission.
#[derive(Clone, Debug)]
pub struct ObservationGenesisParams {
    /// Stable receipt id the Store persists and links.
    pub receipt_id: ArtifactId,
    /// Raw observation handle; retained as the candidate output.
    pub raw_handle: ArtifactId,
    /// Exact source anchor and revision behind the raw handle.
    pub source_anchor: SourceAnchor,
    /// Actor performing the capture and its authority basis.
    pub actor: ActorIdentity,
    /// Work scope of the transition.
    pub scope: String,
    /// Caller-owned clock reading (curation mints no time).
    pub clock: ClockReading,
    /// Caller-owned state fence (curation mints no fence).
    pub state_fence: StateFence,
    /// Digest of the bounded proof payload behind the capture.
    pub proof_digest: String,
    /// Store-minted audit event, when the `AppendAuditEvent` linkage for
    /// this receipt is already recorded.
    pub audit_event_id: Option<ArtifactId>,
}

/// Caller-supplied inputs for one explicit forward revision admission.
#[derive(Clone, Debug)]
pub struct ForwardRevisionParams {
    /// Stable receipt id the Store persists and links.
    pub receipt_id: ArtifactId,
    /// Immutable input record handles the transition reads.
    pub input_record_ids: Vec<ArtifactId>,
    /// Exact source anchor and revision behind the inputs.
    pub source_anchor: SourceAnchor,
    /// Explicit prior semantic role.
    pub prior_role: LifecycleRole,
    /// Explicit proposed semantic role.
    pub proposed_role: LifecycleRole,
    /// Explicit prior epistemic status.
    pub prior_status: EpistemicStatus,
    /// Explicit proposed epistemic status.
    pub proposed_status: EpistemicStatus,
    /// Actor performing the revision and its authority basis. A model
    /// actor claiming elevated standing without an independent
    /// qualifying basis is refused by the receipt itself.
    pub actor: ActorIdentity,
    /// Work scope of the transition.
    pub scope: String,
    /// Caller-owned clock reading.
    pub clock: ClockReading,
    /// Caller-owned state fence.
    pub state_fence: StateFence,
    /// Evidence references behind the decision.
    pub evidence_refs: Vec<ArtifactId>,
    /// Counterevidence references preserved by the decision.
    pub counterevidence_refs: Vec<ArtifactId>,
    /// Explicit admission outcome.
    pub outcome: AdmissionOutcome,
    /// Independent qualifying basis, required for elevated standing.
    pub qualifying_basis: Option<QualifyingBasis>,
    /// Forward supersession links; non-empty for corrections.
    pub supersedes: Vec<ArtifactId>,
    /// Output record handle produced by the transition.
    pub output_record_id: ArtifactId,
    /// Digest of the bounded proof payload behind the transition.
    pub proof_digest: String,
    /// Store-minted audit event, when the `AppendAuditEvent` linkage for
    /// this receipt is already recorded.
    pub audit_event_id: Option<ArtifactId>,
}

/// Admits one raw observation as a retained observation candidate.
///
/// This is the first production hop of the #1905 acceptance chain: the
/// raw handle is captured, held as a candidate (no claim, instruction, or
/// proof standing), and bound to its persisting `CaptureObservation`
/// mutation through the returned admission.
pub fn admit_observation_genesis(
    params: ObservationGenesisParams,
) -> Result<CurationAdmission, crate::admission::AdmissionError> {
    let receipt = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: params.receipt_id,
        input_record_ids: vec![params.raw_handle.clone()],
        source_anchor: params.source_anchor,
        prior_role: LifecycleRole::ObservationCandidate,
        proposed_role: LifecycleRole::ObservationCandidate,
        prior_status: EpistemicStatus::Observed,
        proposed_status: EpistemicStatus::Observed,
        actor: params.actor,
        scope: params.scope,
        clock: params.clock,
        state_fence: params.state_fence,
        evidence_refs: vec![params.raw_handle.clone()],
        counterevidence_refs: Vec::new(),
        outcome: AdmissionOutcome::Admitted,
        qualifying_basis: None,
        supersedes: Vec::new(),
        output_record_id: params.raw_handle,
        audit_event_id: params.audit_event_id,
        proof_digest: params.proof_digest,
    })?;
    CurationAdmission::new(CurationMutationOperation::CaptureObservation, receipt)
}

/// Admits one explicit forward revision and verifies the chain back to
/// the raw observation.
///
/// Every hop must consume the prior output and the whole chain must stay
/// audit-linked, so the returned view keeps the original reconstructible.
/// A model-actor paraphrase claiming elevated or verified standing without
/// an independent qualifying basis fails here with the receipt's
/// `ForbiddenElevation` refusal, never as a silent promotion.
pub fn admit_forward_revision(
    prior: &[CurationAdmission],
    params: ForwardRevisionParams,
) -> Result<AdmissionChainView, crate::admission::AdmissionError> {
    let receipt = LifecycleReceipt::new(LifecycleReceiptParams {
        receipt_id: params.receipt_id,
        input_record_ids: params.input_record_ids,
        source_anchor: params.source_anchor,
        prior_role: params.prior_role,
        proposed_role: params.proposed_role,
        prior_status: params.prior_status,
        proposed_status: params.proposed_status,
        actor: params.actor,
        scope: params.scope,
        clock: params.clock,
        state_fence: params.state_fence,
        evidence_refs: params.evidence_refs,
        counterevidence_refs: params.counterevidence_refs,
        outcome: params.outcome,
        qualifying_basis: params.qualifying_basis,
        supersedes: params.supersedes,
        output_record_id: params.output_record_id,
        audit_event_id: params.audit_event_id,
        proof_digest: params.proof_digest,
    })?;
    let revision =
        CurationAdmission::new(CurationMutationOperation::ApplyEpistemicRevision, receipt)?;
    let mut chain = prior.to_vec();
    chain.push(revision);
    verify_admission_chain(&chain)
}

/// Exact Store-persist projection of one admission.
///
/// The Store owner persists this through its existing mutation path with
/// no new shapes: `operation` names the canonical `NamedMutationOperation`
/// wire value (`PascalCase`, matching the closed catalogue) and `fields`
/// carry the receipt identity the Store binds into its
/// `NamedMutationRequest` parameters and `AppendAuditEvent` linkage. The
/// Store mints `operation_id`, envelope, and audit event ids; curation
/// never does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreAdmissionProjection {
    /// Canonical mutation wire name from the closed catalogue.
    pub operation: &'static str,
    /// Stable receipt id, linked through `AppendAuditEvent`.
    pub receipt_id: String,
    /// Frozen receipt digest.
    pub receipt_digest: String,
    /// Output record handle produced by the transition.
    pub output_record_id: String,
    /// Store-minted audit event, when already recorded.
    pub audit_event_id: Option<String>,
    /// String `parameters` entries for the Store `NamedMutationRequest`.
    pub fields: BTreeMap<String, String>,
}

/// Projects one admission onto the Store persist contract.
pub fn project_for_store(admission: &CurationAdmission) -> StoreAdmissionProjection {
    let operation = match admission.operation {
        CurationMutationOperation::CaptureObservation => "CaptureObservation",
        CurationMutationOperation::ApplyEpistemicRevision => "ApplyEpistemicRevision",
        CurationMutationOperation::ApplyLifecyclePolicy => "ApplyLifecyclePolicy",
        CurationMutationOperation::AppendAuditEvent => "AppendAuditEvent",
    };
    let receipt = &admission.receipt;
    let mut fields = BTreeMap::new();
    fields.insert(
        "receipt_id".to_owned(),
        receipt.receipt_id.as_str().to_owned(),
    );
    fields.insert("receipt_digest".to_owned(), receipt.digest.clone());
    fields.insert(
        "output_record_id".to_owned(),
        receipt.output_record_id.as_str().to_owned(),
    );
    if let Some(event) = &receipt.audit_event_id {
        fields.insert("audit_event_id".to_owned(), event.as_str().to_owned());
    }
    StoreAdmissionProjection {
        operation,
        receipt_id: receipt.receipt_id.as_str().to_owned(),
        receipt_digest: receipt.digest.clone(),
        output_record_id: receipt.output_record_id.as_str().to_owned(),
        audit_event_id: receipt
            .audit_event_id
            .as_ref()
            .map(|id| id.as_str().to_owned()),
        fields,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, SourceId, sha256_hex};
    use eliot_epistemic::lifecycle::ActorKind;
    use std::num::NonZeroU64;

    fn test_epoch(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-B");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(test_epoch(1), ResourceGeneration::genesis())
    }

    fn id(value: &str) -> ArtifactId {
        ArtifactId::new(value).expect("valid fixture artifact id")
    }

    fn source(value: &str) -> SourceId {
        SourceId::new(value).expect("valid fixture source id")
    }

    fn anchor() -> SourceAnchor {
        SourceAnchor {
            source_id: source("fixture-source"),
            revision: Some("r1".to_owned()),
            raw_handle: Some("raw:fixture:r1".to_owned()),
        }
    }

    fn clock() -> ClockReading {
        ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(2),
            transaction_sequence: None,
            monotonic_ns: None,
        }
    }

    fn actor(kind: ActorKind) -> ActorIdentity {
        ActorIdentity {
            kind,
            identity: "fixture-actor".to_owned(),
            authority_basis: "fixture-grant".to_owned(),
        }
    }

    /// #1905 acceptance, smallest proof: one captured raw observation
    /// stays inspectable from candidate retention through an admitted
    /// forward revision to a stable audit-linked receipt, the original
    /// reconstructible — while a model paraphrase claiming proof standing
    /// without an independent basis is refused, never promoted.
    #[test]
    fn raw_observation_to_stable_receipt_with_paraphrase_refusal() {
        let genesis = admit_observation_genesis(ObservationGenesisParams {
            receipt_id: id("receipt:capture"),
            raw_handle: id("obs:raw-1"),
            source_anchor: anchor(),
            actor: actor(ActorKind::DeterministicTransformer),
            scope: "scope".to_owned(),
            clock: clock(),
            state_fence: fence(),
            proof_digest: sha256_hex(b"capture-proof"),
            audit_event_id: Some(id("audit:capture")),
        })
        .expect("genesis admission");
        assert_eq!(
            genesis.receipt.proposed_role,
            LifecycleRole::ObservationCandidate
        );

        let view = admit_forward_revision(
            &[genesis],
            ForwardRevisionParams {
                receipt_id: id("receipt:claim"),
                input_record_ids: vec![id("obs:raw-1")],
                source_anchor: anchor(),
                prior_role: LifecycleRole::ObservationCandidate,
                proposed_role: LifecycleRole::Claim,
                prior_status: EpistemicStatus::Observed,
                proposed_status: EpistemicStatus::Supported,
                actor: actor(ActorKind::HumanOperator),
                scope: "scope".to_owned(),
                clock: clock(),
                state_fence: fence(),
                evidence_refs: vec![id("obs:raw-1")],
                counterevidence_refs: Vec::new(),
                outcome: AdmissionOutcome::Admitted,
                qualifying_basis: None,
                supersedes: Vec::new(),
                output_record_id: id("claim:1"),
                proof_digest: sha256_hex(b"claim-proof"),
                audit_event_id: Some(id("audit:claim")),
            },
        )
        .expect("revision admission");
        assert_eq!(view.original_input, id("obs:raw-1"));
        assert_eq!(view.current_output, id("claim:1"));
        assert_eq!(view.ordered.len(), 2);
        assert!(view.ordered.iter().all(CurationAdmission::is_audit_linked));
        let projected = project_for_store(&view.ordered[1]);
        assert_eq!(projected.operation, "ApplyEpistemicRevision");
        assert_eq!(projected.audit_event_id.as_deref(), Some("audit:claim"));

        let refused = admit_forward_revision(
            &view.ordered[..1],
            ForwardRevisionParams {
                receipt_id: id("receipt:paraphrase"),
                input_record_ids: vec![id("obs:raw-1")],
                source_anchor: anchor(),
                prior_role: LifecycleRole::ObservationCandidate,
                proposed_role: LifecycleRole::Proof,
                prior_status: EpistemicStatus::Observed,
                proposed_status: EpistemicStatus::Supported,
                actor: actor(ActorKind::ModelTransformer),
                scope: "scope".to_owned(),
                clock: clock(),
                state_fence: fence(),
                evidence_refs: vec![id("obs:raw-1")],
                counterevidence_refs: Vec::new(),
                outcome: AdmissionOutcome::Admitted,
                qualifying_basis: None,
                supersedes: Vec::new(),
                output_record_id: id("proof:1"),
                proof_digest: sha256_hex(b"paraphrase-proof"),
                audit_event_id: Some(id("audit:paraphrase")),
            },
        );
        assert!(
            matches!(
                refused,
                Err(crate::admission::AdmissionError::Lifecycle(
                    eliot_epistemic::lifecycle::LifecycleError::ForbiddenElevation { .. }
                ))
            ),
            "model paraphrase must be refused elevated standing"
        );
    }
}
