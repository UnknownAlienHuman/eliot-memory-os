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
//! the Store owner; [`project_for_store`] maps an admission onto the exact
//! declared catalogue shape — submittable `CaptureObservation{subject}`
//! parameters, or linkage evidence where the operation is Store-minted —
//! with no invented fields. No Store, Kernel, or Host file is touched here.

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

/// Binds Store-emitted audit event ids back onto an admission chain.
///
/// The Store consumer persists each admission through its named mutation,
/// then returns the real emitted audit event per stable receipt id. This
/// re-links every receipt via `link_audit` (digest recompute) and
/// re-verifies the full chain, so only a completely audit-linked,
/// original-preserving chain returns. A receipt with no emitted event
/// fails with `AuditUnlinked`, and a receipt whose preset disagrees with
/// the emitted event fails with `AuditEventMismatch`: curation never
/// invents audit identity and never silently re-points a preset linkage.
/// Re-linking the already-preset event is digest-stable by construction.
pub fn bind_emitted_audit_events(
    chain: &[CurationAdmission],
    emitted: &[(ArtifactId, ArtifactId)],
) -> Result<AdmissionChainView, crate::admission::AdmissionError> {
    use crate::admission::AdmissionError;
    let mut linked = Vec::with_capacity(chain.len());
    for admission in chain {
        let event = emitted
            .iter()
            .find(|(receipt_id, _)| *receipt_id == admission.receipt.receipt_id)
            .map(|(_, event)| event.clone())
            .ok_or(AdmissionError::AuditUnlinked)?;
        if let Some(preset) = &admission.receipt.audit_event_id
            && *preset != event
        {
            return Err(AdmissionError::AuditEventMismatch {
                receipt: admission.receipt.receipt_id.as_str().to_owned(),
            });
        }
        linked.push(CurationAdmission {
            operation: admission.operation,
            receipt: admission.receipt.link_audit(event)?,
        });
    }
    verify_admission_chain(&linked)
}

/// Exact Store-persist projection of one admission.
///
/// Only `CaptureObservation` has a curation-fillable declared shape
/// (`CAPTURE_OBSERVATION_PARAMETERS{subject}`): the persisted subject is
/// the retained raw output handle. Every other admission-path operation
/// is Store-minted by contract:
/// - `ApplyEpistemicRevision` requires `EPISTEMIC_REVISION_PARAMETERS
///   {revision: EpistemicRevision}` — the Governor-owned epistemic
///   position payload, not a lifecycle receipt;
/// - `ApplyLifecyclePolicy` requires the skill-lifecycle six-field
///   package (`action`, `base_view_digest`, `candidate_digest`,
///   `candidate_package_digest`, `skill_id`, `verifier_ref`);
/// - `AppendAuditEvent` requires the six Store envelope fields
///   (`operation_id`, `idempotency_key`, `session_id`, `access_digest`,
///   `action_digest`, `expected_revision`).
///
/// Projecting receipt fields into those tables would be a fake-field
/// assumption, so those admissions project as linkage evidence only: the
/// Store consumer binds the stable receipt id/digest/output and the real
/// emitted audit event id at its own persist call-site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreProjection {
    /// Submittable `CaptureObservation{subject}` parameters.
    SubmittableCapture {
        /// Canonical mutation wire name from the closed catalogue.
        operation: &'static str,
        /// Exact declared parameters: `subject` only.
        fields: BTreeMap<String, String>,
    },
    /// Store-minted operation: linkage evidence for the Store consumer.
    StoreMinted {
        /// Canonical mutation wire name from the closed catalogue.
        operation: &'static str,
        /// Stable receipt id, linked through `AppendAuditEvent`.
        receipt_id: String,
        /// Frozen receipt digest.
        receipt_digest: String,
        /// Output record handle produced by the transition.
        output_record_id: String,
        /// Real emitted audit event, when already recorded by the Store.
        audit_event_id: Option<String>,
    },
}

/// Projects one admission onto the Store persist contract.
pub fn project_for_store(admission: &CurationAdmission) -> StoreProjection {
    let receipt = &admission.receipt;
    let operation = match admission.operation {
        CurationMutationOperation::CaptureObservation => "CaptureObservation",
        CurationMutationOperation::ApplyEpistemicRevision => "ApplyEpistemicRevision",
        CurationMutationOperation::ApplyLifecyclePolicy => "ApplyLifecyclePolicy",
        CurationMutationOperation::AppendAuditEvent => "AppendAuditEvent",
    };
    if admission.operation == CurationMutationOperation::CaptureObservation {
        let mut fields = BTreeMap::new();
        fields.insert(
            "subject".to_owned(),
            receipt.output_record_id.as_str().to_owned(),
        );
        return StoreProjection::SubmittableCapture { operation, fields };
    }
    StoreProjection::StoreMinted {
        operation,
        receipt_id: receipt.receipt_id.as_str().to_owned(),
        receipt_digest: receipt.digest.clone(),
        output_record_id: receipt.output_record_id.as_str().to_owned(),
        audit_event_id: receipt
            .audit_event_id
            .as_ref()
            .map(|id| id.as_str().to_owned()),
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
    /// stays inspectable from candidate retention through a forward
    /// correction and an admitted revision to a stable audit-linked
    /// receipt, the original reconstructible — while a model paraphrase
    /// claiming proof standing without an independent basis is refused,
    /// never promoted.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn raw_observation_to_stable_receipt_with_paraphrase_refusal() {
        use crate::admission::AdmissionError;
        use eliot_epistemic::lifecycle::LifecycleError;

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
        let genesis_projected = project_for_store(&genesis);

        // Link-back round-trip: an unlinked genesis constructs but never
        // verifies; only the Store-emitted event completes the chain, and
        // a missing event fails instead of inventing audit identity.
        let bare = admit_observation_genesis(ObservationGenesisParams {
            receipt_id: id("receipt:bare"),
            raw_handle: id("obs:raw-1"),
            source_anchor: anchor(),
            actor: actor(ActorKind::DeterministicTransformer),
            scope: "scope".to_owned(),
            clock: clock(),
            state_fence: fence(),
            proof_digest: sha256_hex(b"bare-proof"),
            audit_event_id: None,
        })
        .expect("unlinked genesis constructs");
        assert!(matches!(
            verify_admission_chain(std::slice::from_ref(&bare)),
            Err(AdmissionError::Lifecycle(LifecycleError::AuditUnlinked))
        ));
        assert!(matches!(
            bind_emitted_audit_events(std::slice::from_ref(&bare), &[]),
            Err(AdmissionError::AuditUnlinked)
        ));
        let bound = bind_emitted_audit_events(&[bare], &[(id("receipt:bare"), id("audit:bare"))])
            .expect("emitted link-back verifies");
        assert_eq!(bound.original_input, id("obs:raw-1"));
        assert_eq!(bound.current_output, id("obs:raw-1"));
        assert!(bound.ordered.iter().all(CurationAdmission::is_audit_linked));
        assert!(
            matches!(
                &genesis_projected,
                StoreProjection::SubmittableCapture { fields, .. }
                if fields.get("subject").map(String::as_str) == Some("obs:raw-1")
            ),
            "genesis projects exactly CaptureObservation{{subject}}"
        );

        let corrected = admit_forward_revision(
            &[genesis],
            ForwardRevisionParams {
                receipt_id: id("receipt:correction"),
                input_record_ids: vec![id("obs:raw-1")],
                source_anchor: anchor(),
                prior_role: LifecycleRole::ObservationCandidate,
                proposed_role: LifecycleRole::ObservationCandidate,
                prior_status: EpistemicStatus::Observed,
                proposed_status: EpistemicStatus::Observed,
                actor: actor(ActorKind::HumanOperator),
                scope: "scope".to_owned(),
                clock: clock(),
                state_fence: fence(),
                evidence_refs: vec![id("obs:raw-1")],
                counterevidence_refs: Vec::new(),
                outcome: AdmissionOutcome::CorrectedForward,
                qualifying_basis: None,
                supersedes: vec![id("obs:raw-1")],
                output_record_id: id("obs:raw-2"),
                proof_digest: sha256_hex(b"correction-proof"),
                audit_event_id: Some(id("audit:correction")),
            },
        )
        .expect("correction admission");
        assert_eq!(corrected.original_input, id("obs:raw-1"));
        assert_eq!(corrected.current_output, id("obs:raw-2"));

        let view = admit_forward_revision(
            &corrected.ordered,
            ForwardRevisionParams {
                receipt_id: id("receipt:claim"),
                input_record_ids: vec![id("obs:raw-2")],
                source_anchor: anchor(),
                prior_role: LifecycleRole::ObservationCandidate,
                proposed_role: LifecycleRole::Claim,
                prior_status: EpistemicStatus::Observed,
                proposed_status: EpistemicStatus::Supported,
                actor: actor(ActorKind::HumanOperator),
                scope: "scope".to_owned(),
                clock: clock(),
                state_fence: fence(),
                evidence_refs: vec![id("obs:raw-2")],
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
        assert_eq!(view.ordered.len(), 3);
        assert!(view.ordered.iter().all(CurationAdmission::is_audit_linked));
        let revision_projected = project_for_store(&view.ordered[2]);
        assert!(
            matches!(
                &revision_projected,
                StoreProjection::StoreMinted {
                    operation: "ApplyEpistemicRevision",
                    audit_event_id: Some(event),
                    ..
                } if event.as_str() == "audit:claim"
            ),
            "revision projects as Store-minted linkage evidence, never fake fields"
        );

        // Preset guard: re-linking the preset event is digest-stable, while
        // a divergent emitted event is refused instead of silently
        // re-pointing the linkage.
        let digest_before = view.ordered[2].receipt.digest.clone();
        let rebound = bind_emitted_audit_events(
            &view.ordered,
            &[
                (id("receipt:capture"), id("audit:capture")),
                (id("receipt:correction"), id("audit:correction")),
                (id("receipt:claim"), id("audit:claim")),
            ],
        )
        .expect("preset re-link verifies");
        assert_eq!(rebound.ordered[2].receipt.digest, digest_before);
        assert_eq!(rebound.original_input, id("obs:raw-1"));
        assert!(matches!(
            bind_emitted_audit_events(
                &view.ordered,
                &[
                    (id("receipt:capture"), id("audit:capture")),
                    (id("receipt:correction"), id("audit:WRONG")),
                    (id("receipt:claim"), id("audit:claim")),
                ],
            ),
            Err(AdmissionError::AuditEventMismatch { .. })
        ));

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
