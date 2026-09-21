//! Typed admission of lifecycle receipts through canonical mutations (#1905).
//!
//! This module is linkage only: it binds one explicit semantic-state
//! transition, owned as a typed [`LifecycleReceipt`] by `eliot-epistemic`, to
//! the canonical mutation that persists it. All semantic validation (closed
//! role/status vocabulary, paraphrase guard, verifier basis, digests) lives
//! in the receipt itself; this module enforces only the per-operation shape
//! of the four admission-path mutations and the genesis-first order of an
//! admission chain. Operation wire names match the closed canonical catalogue
//! (`NamedMutationOperation`); this enum carries no duplicate validation.

use eliot_contracts::ArtifactId;
use eliot_epistemic::lifecycle::{
    ActorKind, AdmissionOutcome, LifecycleError, LifecycleReceipt, LifecycleRole, verify_chain,
};
use eliot_evidence::EpistemicStatus;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical mutation operations that may persist a lifecycle transition.
///
/// Only the four admission-path operations are admitted here; the remaining
/// catalogue operations (`UpdateTaskState`, `ReconcileRecovery`, erasure and
/// revocation rows) never persist a lifecycle receipt.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "PascalCase")]
pub enum CurationMutationOperation {
    /// Persists a raw capture as an observation candidate.
    CaptureObservation,
    /// Persists a forward epistemic revision or supersession.
    ApplyEpistemicRevision,
    /// Persists a governed lifecycle policy decision.
    ApplyLifecyclePolicy,
    /// Links a stable receipt id to its audit event.
    AppendAuditEvent,
}

/// Failures for typed mutation admission and chain inspection.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum AdmissionError {
    /// The bound receipt itself is invalid.
    #[error(transparent)]
    Lifecycle(#[from] LifecycleError),
    /// Capture genesis rules were violated.
    #[error("capture genesis must persist one admitted observation candidate")]
    BadGenesis,
    /// A revision changes nothing and supersedes nothing.
    #[error("epistemic revision must transition role/status or record a forward supersession")]
    RevisionWithoutChange,
    /// A lifecycle policy decision names a non-governing authority.
    #[error("lifecycle policy requires a human, governance, or deterministic authority")]
    PolicyAuthority,
    /// Audit linkage is missing where the operation requires it.
    #[error("admission is not linked through AppendAuditEvent")]
    AuditUnlinked,
    /// A chain holds no admissions.
    #[error("admission chain is empty")]
    EmptyChain,
    /// Chain linkage is broken; the reason names the failing hop.
    #[error("admission chain is broken: {reason}")]
    BrokenChain { reason: String },
}

/// One explicit transition bound to its persisting canonical mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurationAdmission {
    /// Canonical mutation persisting the transition.
    pub operation: CurationMutationOperation,
    /// Typed lifecycle receipt; carries its own digest and audit linkage.
    pub receipt: LifecycleReceipt,
}

impl CurationAdmission {
    /// Admits one typed receipt under one canonical mutation.
    pub fn new(
        operation: CurationMutationOperation,
        receipt: LifecycleReceipt,
    ) -> Result<Self, AdmissionError> {
        receipt.validate()?;
        let admission = Self { operation, receipt };
        admission.check_operation_shape()?;
        Ok(admission)
    }

    /// Whether the admission carries its `AppendAuditEvent` linkage.
    pub const fn is_audit_linked(&self) -> bool {
        self.receipt.is_audit_linked()
    }

    fn check_operation_shape(&self) -> Result<(), AdmissionError> {
        match self.operation {
            CurationMutationOperation::CaptureObservation => {
                let receipt = &self.receipt;
                let single_input = receipt.input_record_ids.len() == 1
                    && receipt
                        .input_record_ids
                        .first()
                        .is_some_and(|input| *input == receipt.output_record_id);
                if !single_input
                    || !receipt.supersedes.is_empty()
                    || receipt.prior_role != LifecycleRole::ObservationCandidate
                    || receipt.proposed_role != LifecycleRole::ObservationCandidate
                    || receipt.prior_status != EpistemicStatus::Observed
                    || receipt.proposed_status != EpistemicStatus::Observed
                    || receipt.outcome != AdmissionOutcome::Admitted
                {
                    return Err(AdmissionError::BadGenesis);
                }
                Ok(())
            }
            CurationMutationOperation::ApplyEpistemicRevision => {
                let receipt = &self.receipt;
                if receipt.proposed_role == receipt.prior_role
                    && receipt.proposed_status == receipt.prior_status
                    && receipt.supersedes.is_empty()
                {
                    return Err(AdmissionError::RevisionWithoutChange);
                }
                Ok(())
            }
            CurationMutationOperation::ApplyLifecyclePolicy => {
                if !matches!(
                    self.receipt.actor.kind,
                    ActorKind::HumanOperator
                        | ActorKind::GovernancePolicy
                        | ActorKind::DeterministicTransformer
                ) {
                    return Err(AdmissionError::PolicyAuthority);
                }
                Ok(())
            }
            CurationMutationOperation::AppendAuditEvent => {
                if !self.receipt.is_audit_linked() {
                    return Err(AdmissionError::AuditUnlinked);
                }
                Ok(())
            }
        }
    }
}

/// Inspectable view of one complete admission chain from a raw observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionChainView {
    /// Ordered admissions from the genesis capture to the current head.
    pub ordered: Vec<CurationAdmission>,
    /// Raw observation handle the chain starts from.
    pub original_input: ArtifactId,
    /// Current output handle at the head of the chain.
    pub current_output: ArtifactId,
}

/// Verifies that admissions form one inspectable chain from a raw observation.
///
/// Receipt continuity (scope, state handoff, handle plumbing, supersession
/// reconstructibility, audit linkage) is enforced by the receipt chain
/// verifier; this layer additionally pins the operation order to exactly one
/// opening `CaptureObservation` genesis followed by revisions, policy
/// decisions, or audit linkages.
pub fn verify_admission_chain(
    chain: &[CurationAdmission],
) -> Result<AdmissionChainView, AdmissionError> {
    let [first, ..] = chain else {
        return Err(AdmissionError::EmptyChain);
    };
    if first.operation != CurationMutationOperation::CaptureObservation {
        return Err(AdmissionError::BrokenChain {
            reason: "chain must start from a CaptureObservation genesis".to_owned(),
        });
    }
    for (index, admission) in chain.iter().enumerate() {
        admission.check_operation_shape()?;
        if index > 0 && admission.operation == CurationMutationOperation::CaptureObservation {
            return Err(AdmissionError::BrokenChain {
                reason: "CaptureObservation genesis must open the chain exactly once".to_owned(),
            });
        }
    }
    let receipts: Vec<LifecycleReceipt> = chain
        .iter()
        .map(|admission| admission.receipt.clone())
        .collect();
    let view = verify_chain(&receipts)?;
    Ok(AdmissionChainView {
        ordered: chain.to_vec(),
        original_input: view.original_input,
        current_output: view.current_output,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, ClockReading, EpochId, EpochLineageId, ResourceGeneration, SourceId,
        StateFence, sha256_hex,
    };
    use eliot_epistemic::lifecycle::{ActorIdentity, LifecycleReceiptParams, SourceAnchor};
    use std::num::NonZeroU64;

    fn test_epoch(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
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

    fn digest_of(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn actor(kind: ActorKind) -> ActorIdentity {
        ActorIdentity {
            kind,
            identity: "fixture-actor".to_owned(),
            authority_basis: "fixture-grant".to_owned(),
        }
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

    fn receipt(
        receipt_id: &str,
        prior_role: LifecycleRole,
        proposed_role: LifecycleRole,
        outcome: AdmissionOutcome,
        supersedes: Vec<ArtifactId>,
        output: &str,
        actor_kind: ActorKind,
    ) -> LifecycleReceipt {
        LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id(receipt_id),
            input_record_ids: vec![id("obs:raw-1")],
            source_anchor: anchor(),
            prior_role,
            proposed_role,
            prior_status: EpistemicStatus::Observed,
            proposed_status: EpistemicStatus::Observed,
            actor: actor(actor_kind),
            scope: "scope".to_owned(),
            clock: clock(),
            state_fence: fence(),
            evidence_refs: vec![id("obs:raw-1")],
            counterevidence_refs: Vec::new(),
            outcome,
            qualifying_basis: None,
            supersedes,
            output_record_id: id(output),
            audit_event_id: None,
            proof_digest: digest_of(receipt_id),
        })
        .expect("valid fixture receipt")
    }

    fn capture() -> CurationAdmission {
        let linked = receipt(
            "receipt:capture",
            LifecycleRole::ObservationCandidate,
            LifecycleRole::ObservationCandidate,
            AdmissionOutcome::Admitted,
            Vec::new(),
            "obs:raw-1",
            ActorKind::DeterministicTransformer,
        )
        .link_audit(id("audit:capture"))
        .expect("audit linkage");
        CurationAdmission::new(CurationMutationOperation::CaptureObservation, linked)
            .expect("valid capture admission")
    }

    #[test]
    fn capture_to_policy_chain_is_inspectable() {
        let genesis = capture();
        let revision = CurationAdmission::new(
            CurationMutationOperation::ApplyEpistemicRevision,
            receipt(
                "receipt:claim",
                LifecycleRole::ObservationCandidate,
                LifecycleRole::Claim,
                AdmissionOutcome::Admitted,
                Vec::new(),
                "claim:1",
                ActorKind::HumanOperator,
            )
            .link_audit(id("audit:claim"))
            .expect("audit linkage"),
        )
        .expect("valid revision admission");
        let policy = CurationAdmission::new(
            CurationMutationOperation::ApplyLifecyclePolicy,
            LifecycleReceipt::new(LifecycleReceiptParams {
                receipt_id: id("receipt:active"),
                input_record_ids: vec![id("claim:1")],
                source_anchor: anchor(),
                prior_role: LifecycleRole::Claim,
                proposed_role: LifecycleRole::Claim,
                prior_status: EpistemicStatus::Observed,
                proposed_status: EpistemicStatus::Supported,
                actor: actor(ActorKind::GovernancePolicy),
                scope: "scope".to_owned(),
                clock: clock(),
                state_fence: fence(),
                evidence_refs: vec![id("claim:1")],
                counterevidence_refs: Vec::new(),
                outcome: AdmissionOutcome::Admitted,
                qualifying_basis: None,
                supersedes: Vec::new(),
                output_record_id: id("claim:1"),
                audit_event_id: None,
                proof_digest: digest_of("policy-proof"),
            })
            .expect("valid policy receipt")
            .link_audit(id("audit:active"))
            .expect("audit linkage"),
        )
        .expect("valid policy admission");
        let view = verify_admission_chain(&[genesis, revision, policy]).expect("chain");
        assert_eq!(view.original_input, id("obs:raw-1"));
        assert_eq!(view.current_output, id("claim:1"));
        assert_eq!(view.ordered.len(), 3);
        assert!(view.ordered.iter().all(CurationAdmission::is_audit_linked));
    }

    #[test]
    fn genesis_must_persist_one_candidate() {
        let elevated = receipt(
            "receipt:elevated",
            LifecycleRole::ObservationCandidate,
            LifecycleRole::Claim,
            AdmissionOutcome::Admitted,
            Vec::new(),
            "claim:1",
            ActorKind::HumanOperator,
        );
        assert!(matches!(
            CurationAdmission::new(CurationMutationOperation::CaptureObservation, elevated),
            Err(AdmissionError::BadGenesis)
        ));
    }

    #[test]
    fn revision_without_change_is_rejected() {
        let noop = receipt(
            "receipt:noop",
            LifecycleRole::Claim,
            LifecycleRole::Claim,
            AdmissionOutcome::Admitted,
            Vec::new(),
            "claim:1",
            ActorKind::HumanOperator,
        );
        assert!(matches!(
            CurationAdmission::new(CurationMutationOperation::ApplyEpistemicRevision, noop),
            Err(AdmissionError::RevisionWithoutChange)
        ));
    }

    #[test]
    fn policy_requires_governing_authority() {
        // A verifier run is not a model paraphrase, so the receipt itself is
        // valid; the policy operation still refuses its authority.
        let run_policy = receipt(
            "receipt:run-policy",
            LifecycleRole::ObservationCandidate,
            LifecycleRole::Claim,
            AdmissionOutcome::Admitted,
            Vec::new(),
            "claim:1",
            ActorKind::VerifierRun,
        );
        assert!(matches!(
            CurationAdmission::new(CurationMutationOperation::ApplyLifecyclePolicy, run_policy),
            Err(AdmissionError::PolicyAuthority)
        ));
    }

    #[test]
    fn append_audit_requires_linkage() {
        let unlinked = receipt(
            "receipt:unlinked",
            LifecycleRole::ObservationCandidate,
            LifecycleRole::ObservationCandidate,
            AdmissionOutcome::Admitted,
            Vec::new(),
            "obs:raw-1",
            ActorKind::DeterministicTransformer,
        );
        assert!(matches!(
            CurationAdmission::new(CurationMutationOperation::AppendAuditEvent, unlinked),
            Err(AdmissionError::AuditUnlinked)
        ));
    }
}
