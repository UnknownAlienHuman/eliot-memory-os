//! Explicit lifecycle receipts for semantic-state transitions (#1905).
//!
//! One raw observation stays a [`LifecycleRole::ObservationCandidate`] until an
//! explicit, receipted transition moves it. Every role/status change carries
//! immutable inputs, source anchors, actor authority, scope/fence, evidence,
//! outcome, and an `AppendAuditEvent` linkage. Corrections are forward
//! revisions: the superseded handle stays addressable, never rewritten.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, ClockReading, SourceId, StateFence};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_evidence::EpistemicStatus;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Failures for lifecycle receipt construction and chain inspection.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum LifecycleError {
    /// A required text field is blank or carries control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// No immutable input records were named.
    #[error("lifecycle receipt names no input records")]
    EmptyInputs,
    /// The same input handle was named twice.
    #[error("lifecycle receipt names a duplicate handle")]
    DuplicateInput,
    /// Handles are present but not in sorted order.
    #[error("lifecycle handles must be in sorted order")]
    UnsortedInputs,
    /// A digest is not lowercase SHA-256 hex.
    #[error("{field} must be a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// The bound state fence is invalid.
    #[error("lifecycle receipt carries an invalid state fence")]
    InvalidFence,
    /// The bound clock reading is inverted.
    #[error("lifecycle receipt carries an invalid clock reading")]
    InvalidClock,
    /// A model-produced paraphrase claims elevated standing without basis.
    #[error("model paraphrase lacks an independent qualifying basis for {role}")]
    ForbiddenElevation { role: String },
    /// A verified standing names no verifier run.
    #[error("verified standing requires a verifier run in the qualifying basis")]
    VerifiedRequiresVerifierRun,
    /// A verifier-backed standing names no verifier run.
    #[error("verifier-backed standing requires a verifier run in the qualifying basis")]
    VerifierBackedRequiresVerifierRun,
    /// A correction names no superseded handle.
    #[error("correction requires a forward supersession link")]
    NotForwardRevision,
    /// A refused promotion changes standing, mints a supersession, or forks a fresh output.
    #[error("refused promotion must hold prior role, status, and output with no supersession")]
    RefusedPromotionMustHold,
    /// A superseded handle is not among the transition inputs.
    #[error("superseded handle is outside the transition inputs")]
    SupersededOutsideInputs,
    /// A new revision reuses a superseded handle as its output.
    #[error("new revision must not reuse a superseded handle")]
    OutputReusesSuperseded,
    /// Evidence and counterevidence name the same handle.
    #[error("evidence and counterevidence must be disjoint")]
    EvidenceOverlap,
    /// A value could not be canonicalized for its digest.
    #[error("cannot canonicalize lifecycle receipt shape")]
    Canonicalization,
    /// A chain holds no receipts.
    #[error("lifecycle chain is empty")]
    EmptyChain,
    /// Chain linkage is broken; the reason names the failing hop.
    #[error("lifecycle chain is broken: {reason}")]
    BrokenChain { reason: String },
    /// A receipt in the chain is not linked through `AppendAuditEvent`.
    #[error("lifecycle receipt is not linked through AppendAuditEvent")]
    AuditUnlinked,
}

fn text(value: &str, field: &'static str) -> Result<(), LifecycleError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(LifecycleError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn opt_text(value: Option<&String>, field: &'static str) -> Result<(), LifecycleError> {
    if let Some(text_value) = value {
        text(text_value, field)?;
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), LifecycleError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(LifecycleError::InvalidDigest { field });
    }
    Ok(())
}

/// Semantic role of a governed representation.
///
/// `ObservationCandidate` is the only standing a raw capture holds by
/// itself. Every other role needs an explicit, receipted transition.
///
/// Named `LifecycleRole` (not `SemanticRole`) to avoid collision with the
/// context-unit `SemanticRole` in `eliot-context-contracts`, which classifies
/// whole context units rather than lifecycle standing.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleRole {
    /// Retained capture; no claim, instruction, or proof standing.
    ObservationCandidate,
    /// Governed proposition with support and counterevidence.
    Claim,
    /// Human- or policy-authorized instruction text.
    Instruction,
    /// Governed multi-step procedure.
    Procedure,
    /// Governed policy text.
    Policy,
    /// Proof-backed representation.
    Proof,
    /// Standing backed by a current verifier run.
    VerifierBacked,
}

impl LifecycleRole {
    /// Elevated roles a bare paraphrase must never inherit.
    pub const fn is_elevated(self) -> bool {
        matches!(
            self,
            Self::Instruction | Self::Procedure | Self::Policy | Self::Proof | Self::VerifierBacked
        )
    }

    const fn wire_name(self) -> &'static str {
        match self {
            Self::ObservationCandidate => "OBSERVATION_CANDIDATE",
            Self::Claim => "CLAIM",
            Self::Instruction => "INSTRUCTION",
            Self::Procedure => "PROCEDURE",
            Self::Policy => "POLICY",
            Self::Proof => "PROOF",
            Self::VerifierBacked => "VERIFIER_BACKED",
        }
    }
}

/// Who or what performed the transition, and on what authority basis.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActorKind {
    /// An authorized human operator.
    HumanOperator,
    /// A deterministic, versioned transformer.
    DeterministicTransformer,
    /// A model-produced paraphrase or synthesis.
    ModelTransformer,
    /// A governed verification run.
    VerifierRun,
    /// A governed policy decision.
    GovernancePolicy,
}

impl ActorKind {
    const fn is_model(self) -> bool {
        matches!(self, Self::ModelTransformer)
    }
}

/// Actor identity plus the authority basis the transition relies on.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActorIdentity {
    /// What kind of actor performed the transition.
    pub kind: ActorKind,
    /// Stable actor identity (operator, transformer version, run id).
    pub identity: String,
    /// Authority basis (role grant, contract id, policy revision).
    pub authority_basis: String,
}

impl ActorIdentity {
    /// Validates identity and authority text.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        text(&self.identity, "actor.identity")?;
        text(&self.authority_basis, "actor.authority_basis")?;
        Ok(())
    }
}

/// Exact source anchor behind the transition inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAnchor {
    /// Source that produced the input records.
    pub source_id: SourceId,
    /// Exact source revision or commit identity, when known.
    pub revision: Option<String>,
    /// Immutable raw evidence handle, when known.
    pub raw_handle: Option<String>,
}

impl SourceAnchor {
    /// Validates optional anchor text.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        opt_text(self.revision.as_ref(), "source_anchor.revision")?;
        opt_text(self.raw_handle.as_ref(), "source_anchor.raw_handle")?;
        Ok(())
    }
}

/// Explicit admission or decision outcome of the transition.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmissionOutcome {
    /// The proposed role/status was admitted.
    Admitted,
    /// Promotion was explicitly refused; the candidate standing holds.
    RefusedPromotion,
    /// A correction admitted as a forward revision/supersession.
    CorrectedForward,
}

/// Independent qualifying basis for an elevated standing.
///
/// A model paraphrase becomes verifier-backed, policy, procedure, or proof
/// only when this basis names an independent verifier run, independent
/// evidence, or an authorizing policy distinct from the paraphrase itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QualifyingBasis {
    /// Independent verifier run qualifying the standing, when applicable.
    pub verifier_run_id: Option<ArtifactId>,
    /// Independent evidence handles distinct from the paraphrase inputs.
    pub independent_evidence: Vec<ArtifactId>,
    /// Authorizing policy revision or decision, when applicable.
    pub authorizing_policy: Option<String>,
}

impl QualifyingBasis {
    /// Validates basis text and handle uniqueness.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        opt_text(
            self.authorizing_policy.as_ref(),
            "qualifying_basis.authorizing_policy",
        )?;
        let seen: BTreeSet<_> = self.independent_evidence.iter().collect();
        if seen.len() != self.independent_evidence.len() {
            return Err(LifecycleError::DuplicateInput);
        }
        Ok(())
    }

    /// Whether the basis is independent of a bare paraphrase.
    pub fn is_independent(&self) -> bool {
        self.verifier_run_id.is_some()
            || !self.independent_evidence.is_empty()
            || self
                .authorizing_policy
                .as_ref()
                .is_some_and(|policy| !policy.trim().is_empty())
    }
}

/// Named constructor arguments for [`LifecycleReceipt::new`].
#[derive(Clone, Debug)]
pub struct LifecycleReceiptParams {
    /// Stable receipt identity, persisted and linked via `AppendAuditEvent`.
    pub receipt_id: ArtifactId,
    /// Immutable input record handles the transition reads.
    pub input_record_ids: Vec<ArtifactId>,
    /// Exact source anchor behind the inputs.
    pub source_anchor: SourceAnchor,
    /// Semantic role before the transition.
    pub prior_role: LifecycleRole,
    /// Semantic role proposed by the transition.
    pub proposed_role: LifecycleRole,
    /// Epistemic status before the transition.
    pub prior_status: EpistemicStatus,
    /// Epistemic status proposed by the transition.
    pub proposed_status: EpistemicStatus,
    /// Actor and authority basis.
    pub actor: ActorIdentity,
    /// Work scope of the transition.
    pub scope: String,
    /// Valid/known/transaction time of the transition.
    pub clock: ClockReading,
    /// State fence the transition was admitted under.
    pub state_fence: StateFence,
    /// Evidence references behind the decision.
    pub evidence_refs: Vec<ArtifactId>,
    /// Counterevidence references preserved by the decision.
    pub counterevidence_refs: Vec<ArtifactId>,
    /// Explicit admission outcome.
    pub outcome: AdmissionOutcome,
    /// Independent qualifying basis for elevated standings.
    pub qualifying_basis: Option<QualifyingBasis>,
    /// Forward supersession links; empty for a genesis capture.
    pub supersedes: Vec<ArtifactId>,
    /// Output record handle produced by the transition.
    pub output_record_id: ArtifactId,
    /// `AppendAuditEvent` linkage, when already recorded.
    pub audit_event_id: Option<ArtifactId>,
    /// Digest of the bounded proof payload behind the transition.
    pub proof_digest: String,
}

/// One explicit semantic-state transition with its stable receipt.
///
/// Deserialization is gated through [`LifecycleReceipt::new`] via the checked
/// wire mirror below, so JSON input cannot bypass sorted-unique ordering,
/// basis validation, or the frozen digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, try_from = "LifecycleReceiptWire")]
pub struct LifecycleReceipt {
    /// Stable receipt identity.
    pub receipt_id: ArtifactId,
    /// Immutable input record handles, in sorted order.
    pub input_record_ids: Vec<ArtifactId>,
    /// Exact source anchor behind the inputs.
    pub source_anchor: SourceAnchor,
    /// Semantic role before the transition.
    pub prior_role: LifecycleRole,
    /// Semantic role proposed by the transition.
    pub proposed_role: LifecycleRole,
    /// Epistemic status before the transition.
    pub prior_status: EpistemicStatus,
    /// Epistemic status proposed by the transition.
    pub proposed_status: EpistemicStatus,
    /// Actor and authority basis.
    pub actor: ActorIdentity,
    /// Work scope of the transition.
    pub scope: String,
    /// Valid/known/transaction time of the transition.
    pub clock: ClockReading,
    /// State fence the transition was admitted under.
    pub state_fence: StateFence,
    /// Evidence references, in sorted order.
    pub evidence_refs: Vec<ArtifactId>,
    /// Counterevidence references, in sorted order.
    pub counterevidence_refs: Vec<ArtifactId>,
    /// Explicit admission outcome.
    pub outcome: AdmissionOutcome,
    /// Independent qualifying basis for elevated standings.
    pub qualifying_basis: Option<QualifyingBasis>,
    /// Forward supersession links, in sorted order.
    pub supersedes: Vec<ArtifactId>,
    /// Output record handle produced by the transition.
    pub output_record_id: ArtifactId,
    /// `AppendAuditEvent` linkage, when already recorded.
    pub audit_event_id: Option<ArtifactId>,
    /// Digest of the bounded proof payload.
    pub proof_digest: String,
    /// Canonical digest of this receipt shape, excluding this field.
    pub digest: String,
}

/// Canonical digest shape of a receipt, excluding the frozen digest field.
#[derive(Serialize)]
struct ReceiptDigestShape<'a> {
    receipt_id: &'a ArtifactId,
    input_record_ids: &'a [ArtifactId],
    source_anchor: &'a SourceAnchor,
    prior_role: &'a LifecycleRole,
    proposed_role: &'a LifecycleRole,
    prior_status: &'a EpistemicStatus,
    proposed_status: &'a EpistemicStatus,
    actor: &'a ActorIdentity,
    scope: &'a str,
    clock: &'a ClockReading,
    state_fence: &'a StateFence,
    evidence_refs: &'a [ArtifactId],
    counterevidence_refs: &'a [ArtifactId],
    outcome: &'a AdmissionOutcome,
    qualifying_basis: &'a Option<QualifyingBasis>,
    supersedes: &'a [ArtifactId],
    output_record_id: &'a ArtifactId,
    audit_event_id: &'a Option<ArtifactId>,
    proof_digest: &'a str,
}

fn sorted_unique(handles: Vec<ArtifactId>) -> Result<Vec<ArtifactId>, LifecycleError> {
    let mut ordered = handles;
    ordered.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    if ordered.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LifecycleError::DuplicateInput);
    }
    Ok(ordered)
}

/// Re-checks sorted-unique ordering on the read path, so `validate` enforces
/// what `new` normalizes even for receipts built outside the constructor.
fn check_sorted_unique(handles: &[ArtifactId]) -> Result<(), LifecycleError> {
    if handles.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LifecycleError::DuplicateInput);
    }
    if handles
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(LifecycleError::UnsortedInputs);
    }
    Ok(())
}

/// Checked wire mirror of [`LifecycleReceipt`]: deserialization validates via `new`.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct LifecycleReceiptWire {
    receipt_id: ArtifactId,
    input_record_ids: Vec<ArtifactId>,
    source_anchor: SourceAnchor,
    prior_role: LifecycleRole,
    proposed_role: LifecycleRole,
    prior_status: EpistemicStatus,
    proposed_status: EpistemicStatus,
    actor: ActorIdentity,
    scope: String,
    clock: ClockReading,
    state_fence: StateFence,
    evidence_refs: Vec<ArtifactId>,
    counterevidence_refs: Vec<ArtifactId>,
    outcome: AdmissionOutcome,
    qualifying_basis: Option<QualifyingBasis>,
    supersedes: Vec<ArtifactId>,
    output_record_id: ArtifactId,
    audit_event_id: Option<ArtifactId>,
    proof_digest: String,
    digest: String,
}

impl TryFrom<LifecycleReceiptWire> for LifecycleReceipt {
    type Error = LifecycleError;

    fn try_from(wire: LifecycleReceiptWire) -> Result<Self, LifecycleError> {
        let receipt = Self::new(LifecycleReceiptParams {
            receipt_id: wire.receipt_id,
            input_record_ids: wire.input_record_ids,
            source_anchor: wire.source_anchor,
            prior_role: wire.prior_role,
            proposed_role: wire.proposed_role,
            prior_status: wire.prior_status,
            proposed_status: wire.proposed_status,
            actor: wire.actor,
            scope: wire.scope,
            clock: wire.clock,
            state_fence: wire.state_fence,
            evidence_refs: wire.evidence_refs,
            counterevidence_refs: wire.counterevidence_refs,
            outcome: wire.outcome,
            qualifying_basis: wire.qualifying_basis,
            supersedes: wire.supersedes,
            output_record_id: wire.output_record_id,
            audit_event_id: wire.audit_event_id,
            proof_digest: wire.proof_digest,
        })?;
        if receipt.digest != wire.digest {
            return Err(LifecycleError::InvalidDigest {
                field: "lifecycle.digest",
            });
        }
        Ok(receipt)
    }
}

impl LifecycleReceipt {
    /// Constructs a receipt after validating every lifecycle field.
    pub fn new(mut params: LifecycleReceiptParams) -> Result<Self, LifecycleError> {
        params.input_record_ids = sorted_unique(params.input_record_ids)?;
        params.evidence_refs = sorted_unique(params.evidence_refs)?;
        params.counterevidence_refs = sorted_unique(params.counterevidence_refs)?;
        params.supersedes = sorted_unique(params.supersedes)?;
        if let Some(basis) = &params.qualifying_basis {
            basis.validate()?;
            let mut ordered = basis.independent_evidence.clone();
            ordered.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            let mut with_order = basis.clone();
            with_order.independent_evidence = ordered;
            params.qualifying_basis = Some(with_order);
        }
        let mut receipt = Self {
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
            digest: String::new(),
        };
        receipt.validate_shape()?;
        receipt.digest = receipt.compute_digest()?;
        Ok(receipt)
    }

    /// Computes the frozen digest over the canonical receipt shape.
    pub fn compute_digest(&self) -> Result<String, LifecycleError> {
        let shape = ReceiptDigestShape {
            receipt_id: &self.receipt_id,
            input_record_ids: &self.input_record_ids,
            source_anchor: &self.source_anchor,
            prior_role: &self.prior_role,
            proposed_role: &self.proposed_role,
            prior_status: &self.prior_status,
            proposed_status: &self.proposed_status,
            actor: &self.actor,
            scope: self.scope.as_str(),
            clock: &self.clock,
            state_fence: &self.state_fence,
            evidence_refs: &self.evidence_refs,
            counterevidence_refs: &self.counterevidence_refs,
            outcome: &self.outcome,
            qualifying_basis: &self.qualifying_basis,
            supersedes: &self.supersedes,
            output_record_id: &self.output_record_id,
            audit_event_id: &self.audit_event_id,
            proof_digest: self.proof_digest.as_str(),
        };
        canonical_json_bytes(&shape)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| LifecycleError::Canonicalization)
    }

    /// Whether this receipt is a forward correction/supersession.
    pub const fn is_correction(&self) -> bool {
        matches!(self.outcome, AdmissionOutcome::CorrectedForward)
    }

    /// Whether the receipt carries its `AppendAuditEvent` linkage.
    pub const fn is_audit_linked(&self) -> bool {
        self.audit_event_id.is_some()
    }

    /// Returns a copy of this receipt linked to one audit event.
    pub fn link_audit(&self, event: ArtifactId) -> Result<Self, LifecycleError> {
        let mut linked = self.clone();
        linked.audit_event_id = Some(event);
        linked.validate_shape()?;
        linked.digest = linked.compute_digest()?;
        Ok(linked)
    }

    /// Validates shape plus the frozen digest.
    pub fn validate(&self) -> Result<(), LifecycleError> {
        self.validate_shape()?;
        let expected = self.compute_digest()?;
        if self.digest != expected {
            return Err(LifecycleError::InvalidDigest {
                field: "lifecycle.digest",
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), LifecycleError> {
        if self.input_record_ids.is_empty() {
            return Err(LifecycleError::EmptyInputs);
        }
        for handles in [
            &self.input_record_ids,
            &self.evidence_refs,
            &self.counterevidence_refs,
            &self.supersedes,
        ] {
            check_sorted_unique(handles)?;
        }
        if let Some(basis) = &self.qualifying_basis {
            basis.validate()?;
            check_sorted_unique(&basis.independent_evidence)?;
        }
        self.source_anchor.validate()?;
        self.actor.validate()?;
        text(&self.scope, "lifecycle.scope")?;
        self.clock
            .validate()
            .map_err(|_| LifecycleError::InvalidClock)?;
        self.state_fence
            .validate()
            .map_err(|_| LifecycleError::InvalidFence)?;
        digest(&self.proof_digest, "lifecycle.proof_digest")?;
        let evidence: BTreeSet<_> = self.evidence_refs.iter().collect();
        for handle in &self.counterevidence_refs {
            if evidence.contains(handle) {
                return Err(LifecycleError::EvidenceOverlap);
            }
        }
        for superseded in &self.supersedes {
            if !self.input_record_ids.contains(superseded) {
                return Err(LifecycleError::SupersededOutsideInputs);
            }
            if superseded == &self.output_record_id {
                return Err(LifecycleError::OutputReusesSuperseded);
            }
        }
        if self.is_correction() && self.supersedes.is_empty() {
            return Err(LifecycleError::NotForwardRevision);
        }
        if self.outcome == AdmissionOutcome::RefusedPromotion
            && (self.proposed_role != self.prior_role
                || self.proposed_status != self.prior_status
                || !self.supersedes.is_empty()
                || !self.input_record_ids.contains(&self.output_record_id))
        {
            return Err(LifecycleError::RefusedPromotionMustHold);
        }
        self.check_paraphrase_guard()?;
        Ok(())
    }

    /// Rejects model paraphrases that claim elevated or verified standing
    /// without an independent qualifying basis, and verifier-backed standing
    /// that names no backing verifier run.
    fn check_paraphrase_guard(&self) -> Result<(), LifecycleError> {
        // A present verifier run is independent of the paraphrase by
        // construction (`QualifyingBasis::is_independent`), so verified
        // standing needs only the run itself.
        if self.proposed_status == EpistemicStatus::Verified
            && self
                .qualifying_basis
                .as_ref()
                .is_none_or(|basis| basis.verifier_run_id.is_none())
        {
            return Err(LifecycleError::VerifiedRequiresVerifierRun);
        }
        // `VerifierBacked` names its basis in the role itself, so every
        // actor — not just a model paraphrase — must name the backing run.
        // An authorizing policy alone never qualifies verifier standing.
        if self.proposed_role == LifecycleRole::VerifierBacked
            && self
                .qualifying_basis
                .as_ref()
                .is_none_or(|basis| basis.verifier_run_id.is_none())
        {
            return Err(LifecycleError::VerifierBackedRequiresVerifierRun);
        }
        if self.proposed_role.is_elevated()
            && self.actor.kind.is_model()
            && !self
                .qualifying_basis
                .as_ref()
                .is_some_and(QualifyingBasis::is_independent)
        {
            return Err(LifecycleError::ForbiddenElevation {
                role: self.proposed_role.wire_name().to_owned(),
            });
        }
        Ok(())
    }
}

/// Inspectable view of one complete chain from a raw observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleChainView {
    /// Ordered receipts from the genesis capture to the current head.
    pub ordered: Vec<LifecycleReceipt>,
    /// Raw observation handle the chain starts from.
    pub original_input: ArtifactId,
    /// Current output handle at the head of the chain.
    pub current_output: ArtifactId,
}

/// Verifies that receipts form one inspectable chain from a raw observation.
///
/// The first receipt must be a genesis capture, every hop must consume the
/// prior output and continue the prior proposed role/status as its own prior
/// state, every superseded handle must resolve to earlier history
/// (so the original stays reconstructible), and every receipt must carry
/// its `AppendAuditEvent` linkage.
pub fn verify_chain(receipts: &[LifecycleReceipt]) -> Result<LifecycleChainView, LifecycleError> {
    // A lone retained genesis is a complete chain (#1905: the raw
    // observation remains an Observation Candidate). Binding first and
    // last separately accepts the singleton; only the empty chain fails.
    // (`let [first, .., last]` cannot bind a one-element slice, which
    // wrongly rejected retained-candidate chains here while the admission
    // layer above already accepted them.)
    let first = receipts.first().ok_or(LifecycleError::EmptyChain)?;
    let last = receipts.last().ok_or(LifecycleError::EmptyChain)?;
    for receipt in receipts {
        receipt.validate()?;
        if !receipt.is_audit_linked() {
            return Err(LifecycleError::AuditUnlinked);
        }
    }
    if !first.supersedes.is_empty() {
        return Err(LifecycleError::BrokenChain {
            reason: "chain must start from a genesis capture".to_owned(),
        });
    }
    let scope = first.scope.clone();
    let mut known: BTreeSet<&ArtifactId> = BTreeSet::new();
    for handle in &first.input_record_ids {
        known.insert(handle);
    }
    known.insert(&first.output_record_id);
    for pair in receipts.windows(2) {
        let (prior, next) = (&pair[0], &pair[1]);
        if next.scope != scope {
            return Err(LifecycleError::BrokenChain {
                reason: "chain scope must not change silently".to_owned(),
            });
        }
        if next.prior_role != prior.proposed_role || next.prior_status != prior.proposed_status {
            return Err(LifecycleError::BrokenChain {
                reason: "hop prior state does not continue the prior proposal".to_owned(),
            });
        }
        if !next.input_record_ids.contains(&prior.output_record_id) {
            return Err(LifecycleError::BrokenChain {
                reason: "hop does not consume the prior output".to_owned(),
            });
        }
        for superseded in &next.supersedes {
            if !known.contains(superseded) {
                return Err(LifecycleError::BrokenChain {
                    reason: "superseded handle is not reconstructible".to_owned(),
                });
            }
        }
        for handle in &next.input_record_ids {
            known.insert(handle);
        }
        known.insert(&next.output_record_id);
    }
    // Defensive only: `validate` above rejects empty inputs on every receipt,
    // including the first, so this fallback is unreachable on valid input.
    let original = first
        .input_record_ids
        .first()
        .ok_or(LifecycleError::EmptyChain)?;
    Ok(LifecycleChainView {
        ordered: receipts.to_vec(),
        original_input: original.clone(),
        current_output: last.output_record_id.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
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

    fn capture_receipt() -> LifecycleReceipt {
        LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id("receipt:capture"),
            input_record_ids: vec![id("obs:raw-1")],
            source_anchor: anchor(),
            prior_role: LifecycleRole::ObservationCandidate,
            proposed_role: LifecycleRole::ObservationCandidate,
            prior_status: EpistemicStatus::Observed,
            proposed_status: EpistemicStatus::Observed,
            actor: actor(ActorKind::DeterministicTransformer),
            scope: "scope".to_owned(),
            clock: clock(),
            state_fence: fence(),
            evidence_refs: vec![id("obs:raw-1")],
            counterevidence_refs: Vec::new(),
            outcome: AdmissionOutcome::Admitted,
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_record_id: id("obs:raw-1"),
            audit_event_id: None,
            proof_digest: digest_of("capture-proof"),
        })
        .expect("valid capture receipt")
    }

    #[test]
    fn one_observation_yields_inspectable_chain() {
        let capture = capture_receipt()
            .link_audit(id("audit:capture"))
            .expect("audit linkage");
        let promotion = LifecycleReceipt::new(LifecycleReceiptParams {
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
            audit_event_id: None,
            proof_digest: digest_of("claim-proof"),
        })
        .expect("valid promotion receipt")
        .link_audit(id("audit:claim"))
        .expect("audit linkage");
        let view = verify_chain(
            std::slice::from_ref(&capture)
                .iter()
                .chain(std::iter::once(&promotion))
                .cloned()
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .expect("inspectable chain");
        assert_eq!(view.original_input, id("obs:raw-1"));
        assert_eq!(view.current_output, id("claim:1"));
        assert_eq!(view.ordered.len(), 2);
        assert_eq!(view.ordered[1].proposed_role, LifecycleRole::Claim);
        assert!(view.ordered.iter().all(LifecycleReceipt::is_audit_linked));
    }

    #[test]
    fn correction_is_forward_supersession_with_original_reconstructible() {
        let capture = capture_receipt()
            .link_audit(id("audit:capture"))
            .expect("audit linkage");
        let correction = LifecycleReceipt::new(LifecycleReceiptParams {
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
            audit_event_id: None,
            proof_digest: digest_of("correction-proof"),
        })
        .expect("valid correction receipt")
        .link_audit(id("audit:correction"))
        .expect("audit linkage");
        assert!(correction.is_correction());
        let view = verify_chain(&[capture.clone(), correction]).expect("forward chain");
        assert_eq!(view.original_input, id("obs:raw-1"));
        assert_eq!(view.current_output, id("obs:raw-2"));
        assert_eq!(view.ordered[0].output_record_id, id("obs:raw-1"));
    }

    #[test]
    fn model_paraphrase_cannot_claim_elevated_standing() {
        let refused = LifecycleReceipt::new(LifecycleReceiptParams {
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
            audit_event_id: None,
            proof_digest: digest_of("paraphrase-proof"),
        });
        assert!(matches!(
            refused,
            Err(LifecycleError::ForbiddenElevation { .. })
        ));
        let qualified = LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id("receipt:paraphrase-q"),
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
            qualifying_basis: Some(QualifyingBasis {
                verifier_run_id: Some(id("run:verifier-1")),
                independent_evidence: vec![id("obs:independent-1")],
                authorizing_policy: None,
            }),
            supersedes: Vec::new(),
            output_record_id: id("proof:1"),
            audit_event_id: None,
            proof_digest: digest_of("paraphrase-proof"),
        })
        .expect("independently qualified paraphrase is admitted");
        assert_eq!(qualified.proposed_role, LifecycleRole::Proof);
    }

    #[test]
    fn verifier_backed_standing_requires_a_verifier_run_for_every_actor() {
        let policy_only = LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id("receipt:policy-only"),
            input_record_ids: vec![id("obs:raw-1")],
            source_anchor: anchor(),
            prior_role: LifecycleRole::ObservationCandidate,
            proposed_role: LifecycleRole::VerifierBacked,
            prior_status: EpistemicStatus::Observed,
            proposed_status: EpistemicStatus::Supported,
            actor: actor(ActorKind::HumanOperator),
            scope: "scope".to_owned(),
            clock: clock(),
            state_fence: fence(),
            evidence_refs: vec![id("obs:raw-1")],
            counterevidence_refs: Vec::new(),
            outcome: AdmissionOutcome::Admitted,
            qualifying_basis: Some(QualifyingBasis {
                verifier_run_id: None,
                independent_evidence: Vec::new(),
                authorizing_policy: Some("policy:r1".to_owned()),
            }),
            supersedes: Vec::new(),
            output_record_id: id("backed:1"),
            audit_event_id: None,
            proof_digest: digest_of("policy-only-proof"),
        });
        assert!(matches!(
            policy_only,
            Err(LifecycleError::VerifierBackedRequiresVerifierRun)
        ));
        let backed = LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id("receipt:backed"),
            input_record_ids: vec![id("obs:raw-1")],
            source_anchor: anchor(),
            prior_role: LifecycleRole::ObservationCandidate,
            proposed_role: LifecycleRole::VerifierBacked,
            prior_status: EpistemicStatus::Observed,
            proposed_status: EpistemicStatus::Supported,
            actor: actor(ActorKind::HumanOperator),
            scope: "scope".to_owned(),
            clock: clock(),
            state_fence: fence(),
            evidence_refs: vec![id("obs:raw-1")],
            counterevidence_refs: Vec::new(),
            outcome: AdmissionOutcome::Admitted,
            qualifying_basis: Some(QualifyingBasis {
                verifier_run_id: Some(id("run:verifier-1")),
                independent_evidence: Vec::new(),
                authorizing_policy: None,
            }),
            supersedes: Vec::new(),
            output_record_id: id("backed:1"),
            audit_event_id: None,
            proof_digest: digest_of("backed-proof"),
        })
        .expect("verifier-backed standing with a backing run is admitted");
        assert_eq!(backed.proposed_role, LifecycleRole::VerifierBacked);
    }

    #[test]
    fn refused_promotion_cannot_fork_a_fresh_output() {
        let forked = LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id("receipt:forked"),
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
            outcome: AdmissionOutcome::RefusedPromotion,
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_record_id: id("obs:fork-1"),
            audit_event_id: None,
            proof_digest: digest_of("forked-proof"),
        });
        assert!(matches!(
            forked,
            Err(LifecycleError::RefusedPromotionMustHold)
        ));
    }

    #[test]
    fn refused_promotion_holds_prior_standing() {
        let changed = LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id("receipt:refused"),
            input_record_ids: vec![id("obs:raw-1")],
            source_anchor: anchor(),
            prior_role: LifecycleRole::ObservationCandidate,
            proposed_role: LifecycleRole::Claim,
            prior_status: EpistemicStatus::Observed,
            proposed_status: EpistemicStatus::Observed,
            actor: actor(ActorKind::HumanOperator),
            scope: "scope".to_owned(),
            clock: clock(),
            state_fence: fence(),
            evidence_refs: vec![id("obs:raw-1")],
            counterevidence_refs: Vec::new(),
            outcome: AdmissionOutcome::RefusedPromotion,
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_record_id: id("obs:raw-1"),
            audit_event_id: None,
            proof_digest: digest_of("refused-proof"),
        });
        assert!(matches!(
            changed,
            Err(LifecycleError::RefusedPromotionMustHold)
        ));
        let held = LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id("receipt:held"),
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
            outcome: AdmissionOutcome::RefusedPromotion,
            qualifying_basis: None,
            supersedes: Vec::new(),
            output_record_id: id("obs:raw-1"),
            audit_event_id: None,
            proof_digest: digest_of("held-proof"),
        })
        .expect("refusal holding prior standing is admitted");
        assert_eq!(held.outcome, AdmissionOutcome::RefusedPromotion);
    }

    #[test]
    fn chain_rejects_discontinuous_prior_state() {
        let capture = capture_receipt()
            .link_audit(id("audit:capture"))
            .expect("audit linkage");
        let disjoint = LifecycleReceipt::new(LifecycleReceiptParams {
            receipt_id: id("receipt:disjoint"),
            input_record_ids: vec![id("obs:raw-1")],
            source_anchor: anchor(),
            prior_role: LifecycleRole::Claim,
            proposed_role: LifecycleRole::Claim,
            prior_status: EpistemicStatus::Supported,
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
            output_record_id: id("claim:9"),
            audit_event_id: None,
            proof_digest: digest_of("disjoint-proof"),
        })
        .expect("individually valid receipt")
        .link_audit(id("audit:disjoint"))
        .expect("audit linkage");
        assert!(matches!(
            verify_chain(&[capture, disjoint]),
            Err(LifecycleError::BrokenChain { .. })
        ));
    }

    #[test]
    fn serde_round_trip_preserves_valid_receipt() {
        let receipt = capture_receipt()
            .link_audit(id("audit:capture"))
            .expect("audit linkage");
        let json = serde_json::to_string(&receipt).expect("serializable receipt");
        let decoded: LifecycleReceipt =
            serde_json::from_str(&json).expect("wire-valid receipt decodes");
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn serde_rejects_tampered_digest_and_duplicate_inputs() {
        let receipt = capture_receipt();
        let mut tampered = serde_json::to_value(&receipt).expect("serializable receipt");
        tampered["digest"] = serde_json::json!("0".repeat(64));
        assert!(serde_json::from_value::<LifecycleReceipt>(tampered).is_err());
        let mut duplicated = serde_json::to_value(&receipt).expect("serializable receipt");
        duplicated["input_record_ids"]
            .as_array_mut()
            .expect("inputs array")
            .push(serde_json::json!("obs:raw-1"));
        assert!(serde_json::from_value::<LifecycleReceipt>(duplicated).is_err());
    }
}
