//! Typed admission of lifecycle receipts through canonical mutations (#1905,
//! #40 W5).
//!
//! The lifecycle/action admission vocabulary and its admissibility rules
//! belong to the Kernel authority boundary, not to a cognitive donor. This
//! module is that owner: it binds one explicit semantic-state transition,
//! owned as a typed [`LifecycleReceipt`] by `eliot-epistemic`, to the
//! canonical mutation that persists it. All semantic validation (closed
//! role/status vocabulary, paraphrase guard, verifier basis, digests) lives
//! in the receipt itself; this module enforces only the per-operation shape
//! of the four admission-path mutations and the genesis-first order of an
//! admission chain. Operation wire names match the closed canonical
//! catalogue (`NamedMutationOperation`); this enum carries no duplicate
//! validation.
//!
//! Migration (#40 W5): the rules moved here from the `eliot-memory-curation`
//! donor's `admission` module, whose migration target is "neutral screen
//! contracts plus read-only screening/protection; no lifecycle/action
//! ownership". The donor retains only the read-only screening surface, and
//! the Kernel persist seam is now its only caller of these rules.

use eliot_contracts::{ArtifactId, ClockReading, StateFence};
use eliot_epistemic::lifecycle::{
    ActorIdentity, ActorKind, AdmissionOutcome, LifecycleError, LifecycleReceipt,
    LifecycleReceiptParams, LifecycleRole, QualifyingBasis, SourceAnchor, verify_chain,
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
pub enum LifecycleMutationOperation {
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
pub enum LifecycleAdmissionError {
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
    /// A Store-emitted audit event does not match the receipt preset.
    #[error("emitted audit event does not match the receipt preset for {receipt}")]
    AuditEventMismatch {
        /// Stable receipt identity whose preset disagrees.
        receipt: String,
    },
    /// A chain holds no admissions.
    #[error("admission chain is empty")]
    EmptyChain,
    /// Chain linkage is broken; the reason names the failing hop.
    #[error("admission chain is broken: {reason}")]
    BrokenChain {
        /// Stable reason code naming the failing hop.
        reason: String,
    },
}

/// One explicit transition bound to its persisting canonical mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LifecycleAdmission {
    /// Canonical mutation persisting the transition.
    pub operation: LifecycleMutationOperation,
    /// Typed lifecycle receipt; carries its own digest and audit linkage.
    pub receipt: LifecycleReceipt,
}

impl LifecycleAdmission {
    /// Admits one typed receipt under one canonical mutation.
    pub fn new(
        operation: LifecycleMutationOperation,
        receipt: LifecycleReceipt,
    ) -> Result<Self, LifecycleAdmissionError> {
        receipt.validate()?;
        let admission = Self { operation, receipt };
        admission.check_operation_shape()?;
        Ok(admission)
    }

    /// Whether the admission carries its `AppendAuditEvent` linkage.
    pub const fn is_audit_linked(&self) -> bool {
        self.receipt.is_audit_linked()
    }

    fn check_operation_shape(&self) -> Result<(), LifecycleAdmissionError> {
        match self.operation {
            LifecycleMutationOperation::CaptureObservation => {
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
                    return Err(LifecycleAdmissionError::BadGenesis);
                }
                Ok(())
            }
            LifecycleMutationOperation::ApplyEpistemicRevision => {
                let receipt = &self.receipt;
                if receipt.proposed_role == receipt.prior_role
                    && receipt.proposed_status == receipt.prior_status
                    && receipt.supersedes.is_empty()
                {
                    return Err(LifecycleAdmissionError::RevisionWithoutChange);
                }
                Ok(())
            }
            LifecycleMutationOperation::ApplyLifecyclePolicy => {
                if !matches!(
                    self.receipt.actor.kind,
                    ActorKind::HumanOperator
                        | ActorKind::GovernancePolicy
                        | ActorKind::DeterministicTransformer
                ) {
                    return Err(LifecycleAdmissionError::PolicyAuthority);
                }
                Ok(())
            }
            LifecycleMutationOperation::AppendAuditEvent => {
                if !self.receipt.is_audit_linked() {
                    return Err(LifecycleAdmissionError::AuditUnlinked);
                }
                Ok(())
            }
        }
    }
}

/// Inspectable view of one complete admission chain from a raw observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAdmissionChainView {
    /// Ordered admissions from the genesis capture to the current head.
    pub ordered: Vec<LifecycleAdmission>,
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
pub fn verify_lifecycle_admission_chain(
    chain: &[LifecycleAdmission],
) -> Result<LifecycleAdmissionChainView, LifecycleAdmissionError> {
    let [first, ..] = chain else {
        return Err(LifecycleAdmissionError::EmptyChain);
    };
    if first.operation != LifecycleMutationOperation::CaptureObservation {
        return Err(LifecycleAdmissionError::BrokenChain {
            reason: "chain must start from a CaptureObservation genesis".to_owned(),
        });
    }
    for (index, admission) in chain.iter().enumerate() {
        admission.check_operation_shape()?;
        if index > 0 && admission.operation == LifecycleMutationOperation::CaptureObservation {
            return Err(LifecycleAdmissionError::BrokenChain {
                reason: "CaptureObservation genesis must open the chain exactly once".to_owned(),
            });
        }
    }
    let receipts: Vec<LifecycleReceipt> = chain
        .iter()
        .map(|admission| admission.receipt.clone())
        .collect();
    let view = verify_chain(&receipts)?;
    Ok(LifecycleAdmissionChainView {
        ordered: chain.to_vec(),
        original_input: view.original_input,
        current_output: view.current_output,
    })
}

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
    /// Caller-owned clock reading (no clock is minted here).
    pub clock: ClockReading,
    /// Caller-owned state fence (no fence is minted here).
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
/// The raw handle is captured, held as a candidate (no claim, instruction, or
/// proof standing), and bound to its persisting `CaptureObservation` mutation
/// through the returned admission.
pub fn admit_observation_genesis(
    params: ObservationGenesisParams,
) -> Result<LifecycleAdmission, LifecycleAdmissionError> {
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
    LifecycleAdmission::new(LifecycleMutationOperation::CaptureObservation, receipt)
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
    prior: &[LifecycleAdmission],
    params: ForwardRevisionParams,
) -> Result<LifecycleAdmissionChainView, LifecycleAdmissionError> {
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
        LifecycleAdmission::new(LifecycleMutationOperation::ApplyEpistemicRevision, receipt)?;
    let mut chain = prior.to_vec();
    chain.push(revision);
    verify_lifecycle_admission_chain(&chain)
}

/// Store-emitted audit linkage for one admission, mirroring the
/// persistence seam's `LinkAuditBinding` field-for-field
/// (`curation_receipt_id`, `audit_operation_id`, `emitted_event_ids`).
/// `emitted_event_ids` carries the real `WriteReceipt.emitted_event_ids`
/// of the committed leg; the appointed `audit_operation_id` is the
/// operation identity the receipt preset must equal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmittedAuditLink {
    /// Stable receipt identity linked by this entry.
    pub curation_receipt_id: String,
    /// Appointed audit operation identity the preset must equal.
    pub audit_operation_id: String,
    /// Real emitted event ids of the committed leg; non-empty.
    pub emitted_event_ids: Vec<String>,
}

/// Binds Store-emitted audit linkage back onto an admission chain.
///
/// Input mirrors the persistence seam's `LinkAuditBinding` exactly. The seam
/// persists each admission through its named mutation, then returns these
/// bindings. This re-links every receipt via `link_audit` (digest recompute)
/// and re-verifies the full chain, so only a completely audit-linked,
/// original-preserving chain returns.
///
/// Exact rules, no invented identity:
/// - a receipt with no binding entry fails with `AuditUnlinked`;
/// - a receipt with no preset fails with `AuditUnlinked` (nothing to
///   check the appointed identity against);
/// - a preset disagreeing with the appointed `audit_operation_id` fails
///   with `AuditEventMismatch` (mirrors the seam's exact
///   preset==appointed check on the returned bindings);
/// - an entry with no emitted events fails with `AuditUnlinked` (a leg
///   that emitted nothing recorded no linkable emission);
/// - re-linking the preset event is digest-stable by construction.
pub fn bind_emitted_audit_events(
    chain: &[LifecycleAdmission],
    links: &[EmittedAuditLink],
) -> Result<LifecycleAdmissionChainView, LifecycleAdmissionError> {
    let mut linked = Vec::with_capacity(chain.len());
    for admission in chain {
        let link = links
            .iter()
            .find(|entry| entry.curation_receipt_id == admission.receipt.receipt_id.as_str())
            .ok_or(LifecycleAdmissionError::AuditUnlinked)?;
        let preset = admission
            .receipt
            .audit_event_id
            .clone()
            .ok_or(LifecycleAdmissionError::AuditUnlinked)?;
        if preset.as_str() != link.audit_operation_id {
            return Err(LifecycleAdmissionError::AuditEventMismatch {
                receipt: admission.receipt.receipt_id.as_str().to_owned(),
            });
        }
        if link.emitted_event_ids.is_empty() {
            return Err(LifecycleAdmissionError::AuditUnlinked);
        }
        linked.push(LifecycleAdmission {
            operation: admission.operation,
            receipt: admission.receipt.link_audit(preset)?,
        });
    }
    verify_lifecycle_admission_chain(&linked)
}

/// Exact Store-persist projection of one admission.
///
/// Only `CaptureObservation` has a fillable declared shape
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
/// seam binds the stable receipt id/digest/output and the real emitted audit
/// event id at its own persist call-site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreProjection {
    /// Submittable `CaptureObservation{subject}` parameters.
    SubmittableCapture {
        /// Canonical mutation wire name from the closed catalogue.
        operation: &'static str,
        /// Exact declared parameters: `subject` only.
        fields: std::collections::BTreeMap<String, String>,
    },
    /// Store-minted operation: linkage evidence for the seam.
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
pub fn project_for_store(admission: &LifecycleAdmission) -> StoreProjection {
    let receipt = &admission.receipt;
    let operation = match admission.operation {
        LifecycleMutationOperation::CaptureObservation => "CaptureObservation",
        LifecycleMutationOperation::ApplyEpistemicRevision => "ApplyEpistemicRevision",
        LifecycleMutationOperation::ApplyLifecyclePolicy => "ApplyLifecyclePolicy",
        LifecycleMutationOperation::AppendAuditEvent => "AppendAuditEvent",
    };
    if admission.operation == LifecycleMutationOperation::CaptureObservation {
        let mut fields = std::collections::BTreeMap::new();
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
