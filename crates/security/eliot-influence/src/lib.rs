//! The single policy owner for origin-bound influence.
//!
//! This crate evaluates immutable provenance and source-assurance records.  It
//! does not persist content or perform a purge.  Callers must persist the
//! returned receipt and use its explicit closure when updating derived state.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::{
    EpistemicUse, InfluenceDependencyClosure, InfluenceState, RevocationReason, SourceAssurance,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.security.influence";
pub const CONTRACT_VERSION: &str = "eliot-influence-v1";

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceLevel {
    Stored,
    Available,
    Delivered,
    Acknowledged,
    Used,
    VerifiedUse,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRecord {
    pub subject_ref: String,
    pub origin_ref: String,
    pub source_assurance: SourceAssurance,
    pub parent_refs: Vec<String>,
    pub transformation_ref: Option<String>,
    pub state_fence: StateFence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
/// Public policy wire shape intentionally retains independent boolean gates.
#[allow(clippy::struct_excessive_bools)]
pub struct InfluencePolicy {
    pub policy_id: String,
    pub revision: u64,
    pub state_fence: StateFence,
    pub require_verified_integrity: bool,
    pub require_current_freshness: bool,
    pub allow_unknown_independence: bool,
    pub allow_instruction_taint: bool,
    pub minimum_level: InfluenceLevel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceRequest {
    pub request_id: String,
    pub subject_ref: String,
    pub requested_level: InfluenceLevel,
    pub policy: InfluencePolicy,
    pub provenance: ProvenanceRecord,
    pub dependency_closure: InfluenceDependencyClosure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceDisposition {
    Allowed,
    Restricted,
    Quarantined,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceDecision {
    pub request_id: String,
    pub request_digest: String,
    pub subject_ref: String,
    pub disposition: InfluenceDisposition,
    pub allowed_level: InfluenceLevel,
    pub reasons: Vec<InfluenceReason>,
    pub origin_ref: String,
    pub policy_id: String,
    pub state_fence: StateFence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceReason {
    IntegrityNotVerified,
    SourceStale,
    SourceQuarantined,
    SourceUnknown,
    InstructionTainted,
    WrongScope,
    DependencyRevoked,
    DependencyQuarantined,
    IncompleteLineage,
    PolicyFenceMismatch,
    RequestedLevelCapped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    pub request_id: String,
    pub root_ref: String,
    pub reason: RevocationReason,
    pub state_fence: StateFence,
    pub graph: Vec<InfluenceEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceEdge {
    pub source_ref: String,
    pub dependent_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationReceipt {
    pub request_id: String,
    pub request_digest: String,
    pub root_ref: String,
    pub affected_refs: Vec<String>,
    pub closures: Vec<InfluenceDependencyClosure>,
    pub state_fence: StateFence,
}

impl InfluencePolicy {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.policy_id, "policy_id")?;
        self.state_fence
            .validate()
            .map_err(|_| InfluenceError::InvalidField("state_fence"))?;
        Ok(())
    }
}

impl InfluenceRequest {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.request_id, "request_id")?;
        text(&self.subject_ref, "subject_ref")?;
        self.policy.validate()?;
        self.provenance.validate()?;
        self.dependency_closure
            .validate()
            .map_err(|_| InfluenceError::InvalidClosure)?;
        if self.provenance.subject_ref != self.subject_ref
            || self.dependency_closure.root_ref != self.provenance.origin_ref
            || self.provenance.state_fence != self.policy.state_fence
            || self.dependency_closure.state_fence != self.policy.state_fence
        {
            return Err(InfluenceError::FenceOrLineageMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, InfluenceError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceError::Canonicalization)
    }
}

impl ProvenanceRecord {
    pub fn validate(&self) -> Result<(), InfluenceError> {
        text(&self.subject_ref, "provenance.subject_ref")?;
        text(&self.origin_ref, "provenance.origin_ref")?;
        self.source_assurance
            .validate()
            .map_err(|_| InfluenceError::InvalidSourceAssurance)?;
        self.state_fence
            .validate()
            .map_err(|_| InfluenceError::InvalidField("provenance.state_fence"))?;
        unique(&self.parent_refs, "parent_refs")?;
        if let Some(reference) = &self.transformation_ref {
            text(reference, "transformation_ref")?;
        }
        if self.source_assurance.state_fence != self.state_fence {
            return Err(InfluenceError::FenceOrLineageMismatch);
        }
        Ok(())
    }
}

pub fn decide(request: &InfluenceRequest) -> Result<InfluenceDecision, InfluenceError> {
    let digest = request.digest()?;
    let source = &request.provenance.source_assurance;
    let mut reasons = Vec::new();
    if request.dependency_closure.current_influence == InfluenceState::Revoked {
        reasons.push(InfluenceReason::DependencyRevoked);
    } else if request.dependency_closure.current_influence == InfluenceState::Quarantined {
        reasons.push(InfluenceReason::DependencyQuarantined);
    } else if request.dependency_closure.current_influence == InfluenceState::Unknown {
        // Fail-closed: an unknown dependency state proves nothing, so it
        // quarantines like an explicit quarantine instead of allowing use.
        reasons.push(InfluenceReason::DependencyQuarantined);
    }
    if request.policy.require_verified_integrity
        && !matches!(
            source.integrity,
            eliot_security_contracts::IntegrityStatus::Verified
        )
    {
        reasons.push(InfluenceReason::IntegrityNotVerified);
    }
    if request.policy.require_current_freshness
        && !matches!(
            source.freshness,
            eliot_security_contracts::FreshnessStatus::Current
        )
    {
        reasons.push(InfluenceReason::SourceStale);
    }
    if !matches!(
        source.quarantine,
        eliot_security_contracts::QuarantineState::None
            | eliot_security_contracts::QuarantineState::Released
    ) {
        reasons.push(InfluenceReason::SourceQuarantined);
    }
    if !request.policy.allow_instruction_taint
        && source.instruction_taint != eliot_security_contracts::InstructionTaint::Cleared
    {
        reasons.push(InfluenceReason::InstructionTainted);
    }
    if !request.policy.allow_unknown_independence
        && matches!(
            source.independence,
            eliot_security_contracts::IndependenceLevel::Unknown
        )
    {
        reasons.push(InfluenceReason::SourceUnknown);
    }
    if request.provenance.parent_refs.is_empty() && request.provenance.transformation_ref.is_some()
    {
        reasons.push(InfluenceReason::IncompleteLineage);
    }
    let blocked = reasons.iter().any(|reason| {
        matches!(
            reason,
            InfluenceReason::DependencyRevoked
                | InfluenceReason::DependencyQuarantined
                | InfluenceReason::SourceQuarantined
                | InfluenceReason::WrongScope
        )
    });
    let restricted = !reasons.is_empty();
    let allowed_level = if blocked {
        InfluenceLevel::Stored
    } else if restricted {
        InfluenceLevel::Available.min(request.policy.minimum_level)
    } else {
        request.requested_level.min(request.policy.minimum_level)
    };
    if allowed_level != request.requested_level {
        reasons.push(InfluenceReason::RequestedLevelCapped);
    }
    let disposition = if reasons
        .iter()
        .any(|reason| matches!(reason, InfluenceReason::DependencyRevoked))
    {
        InfluenceDisposition::Revoked
    } else if blocked {
        InfluenceDisposition::Quarantined
    } else if restricted {
        InfluenceDisposition::Restricted
    } else {
        InfluenceDisposition::Allowed
    };
    Ok(InfluenceDecision {
        request_id: request.request_id.clone(),
        request_digest: digest,
        subject_ref: request.subject_ref.clone(),
        disposition,
        allowed_level,
        reasons,
        origin_ref: request.provenance.origin_ref.clone(),
        policy_id: request.policy.policy_id.clone(),
        state_fence: request.policy.state_fence.clone(),
    })
}

pub fn revoke(request: &RevocationRequest) -> Result<RevocationReceipt, InfluenceError> {
    text(&request.request_id, "request_id")?;
    text(&request.root_ref, "root_ref")?;
    request
        .state_fence
        .validate()
        .map_err(|_| InfluenceError::InvalidField("state_fence"))?;
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for edge in &request.graph {
        text(&edge.source_ref, "edge.source_ref")?;
        text(&edge.dependent_ref, "edge.dependent_ref")?;
        adjacency
            .entry(&edge.source_ref)
            .or_default()
            .push(&edge.dependent_ref);
    }
    let mut affected = BTreeSet::new();
    let mut queue = VecDeque::from([request.root_ref.as_str()]);
    while let Some(reference) = queue.pop_front() {
        if !affected.insert(reference.to_owned()) {
            continue;
        }
        if let Some(dependents) = adjacency.get(reference) {
            queue.extend(dependents.iter().copied());
        }
    }
    let affected_refs: Vec<String> = affected.into_iter().collect();
    let closures = affected_refs
        .iter()
        .map(|subject| InfluenceDependencyClosure {
            closure_id: format!("{}:{}", request.request_id, subject),
            root_ref: request.root_ref.clone(),
            dependent_refs: affected_refs.clone(),
            invalidation_reason: Some(request.reason),
            current_influence: InfluenceState::Revoked,
            state_fence: request.state_fence.clone(),
            revision: 0,
        })
        .collect::<Vec<_>>();
    for closure in &closures {
        closure
            .validate()
            .map_err(|_| InfluenceError::InvalidClosure)?;
    }
    let request_digest = canonical_json_bytes(request)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| InfluenceError::Canonicalization)?;
    Ok(RevocationReceipt {
        request_id: request.request_id.clone(),
        request_digest,
        root_ref: request.root_ref.clone(),
        affected_refs,
        closures,
        state_fence: request.state_fence.clone(),
    })
}

// ---------------------------------------------------------------------------
// Issue 1904: reachable influence runtime path.
//
// Allowed influence must flow through one reachable staged path:
//
//   context-admission -> pending-injection -> material-decision -> result-binding
//
// Every stage calls the same mandatory policy gate (`policy_gate`) and carries
// a digest-bound receipt from the previous stage, so no stage is reachable by
// skipping its predecessor. The gate returns an allow / deny / degraded-use
// verdict with explicit reasons. Retrieval (`retrieve_view`) takes only a
// shared reference and never mutates support or influence.
// ---------------------------------------------------------------------------

/// Wire/schema revision of the staged influence runtime path.
pub const RUNTIME_PATH_VERSION: &str = "eliot-influence-runtime-v1";

/// Requested runtime use on the reachable influence path.
///
/// Each use maps to the minimum [`EpistemicUse`] that must be present in the
/// subject's allowed set: exploratory reads need `OBSERVATION`, material
/// decision input and confirmatory acceptance need `CANDIDATE_EVIDENCE`, and
/// verifier input needs `VERIFICATION_INPUT`. Confirmatory acceptance
/// additionally requires an explicit qualifying transition
/// (`qualified_for_confirmatory`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeUse {
    ExploratoryRead,
    DecisionInput,
    VerifierInput,
    ConfirmatoryAcceptance,
}

impl RuntimeUse {
    fn required_use(self) -> EpistemicUse {
        match self {
            Self::ExploratoryRead => EpistemicUse::Observation,
            Self::DecisionInput | Self::ConfirmatoryAcceptance => EpistemicUse::CandidateEvidence,
            Self::VerifierInput => EpistemicUse::VerificationInput,
        }
    }

    fn rank(use_: EpistemicUse) -> u8 {
        match use_ {
            EpistemicUse::Observation => 0,
            EpistemicUse::AttributedInput => 1,
            EpistemicUse::CandidateEvidence => 2,
            EpistemicUse::VerificationInput => 3,
        }
    }
}

/// Boundary stage of the reachable path. Receipt order enforces reachability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeStage {
    ContextAdmission,
    PendingInjection,
    MaterialDecision,
    ResultBinding,
}

/// Allow / deny / degraded-use outcome of the mandatory policy gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeVerdictKind {
    Allow,
    DegradedUse,
    Deny,
}

/// Explicit reason carried by a runtime verdict. Deny and degraded-use
/// verdicts always carry at least one reason naming the missing allowance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeReason {
    RecordNotRetrievable,
    InfluenceNotActive {
        state: InfluenceState,
    },
    EpistemicUseNotAllowed {
        requested: EpistemicUse,
        allowed: Vec<EpistemicUse>,
    },
    ExploratoryOnlyCannotSatisfyVerifier,
    ExploratoryOnlyCannotSatisfyConfirmatory,
    VerifierRequiresVerificationInput,
    ConfirmatoryRequiresQualification,
    UseCappedToExploratory,
}

/// Subject gated by the runtime path.
///
/// `support_revision` names the support state and `influence` names the
/// influence state; neither is mutated by retrieval. A qualifying transition
/// produces a new subject value and leaves the original untouched.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSubject {
    pub subject_ref: String,
    pub origin_ref: String,
    pub allowed_uses: Vec<EpistemicUse>,
    pub influence: InfluenceState,
    pub retrievable: bool,
    pub qualified_for_confirmatory: bool,
    pub support_revision: u64,
    pub state_fence: StateFence,
}

impl RuntimeSubject {
    /// Build a subject, rejecting blank references and an empty use set.
    ///
    /// New subjects start unqualified for confirmatory acceptance; only an
    /// explicit [`qualify_transition`] can set the qualification flag.
    pub fn new(
        subject_ref: String,
        origin_ref: String,
        allowed_uses: Vec<EpistemicUse>,
        influence: InfluenceState,
        retrievable: bool,
        support_revision: u64,
        state_fence: StateFence,
    ) -> Result<Self, InfluenceRuntimeError> {
        let subject = Self {
            subject_ref,
            origin_ref,
            allowed_uses,
            influence,
            retrievable,
            qualified_for_confirmatory: false,
            support_revision,
            state_fence,
        };
        subject.validate()?;
        Ok(subject)
    }

    /// Build a subject from live contract records so allowed influence stays
    /// bound to source assurance and the dependency closure.
    pub fn from_contracts(
        subject_ref: String,
        provenance: &ProvenanceRecord,
        closure: &InfluenceDependencyClosure,
        retrievable: bool,
        support_revision: u64,
    ) -> Result<Self, InfluenceRuntimeError> {
        provenance
            .validate()
            .map_err(|_| InfluenceRuntimeError::InvalidField("provenance"))?;
        closure
            .validate()
            .map_err(|_| InfluenceRuntimeError::InvalidField("dependency_closure"))?;
        Self::new(
            subject_ref,
            provenance.origin_ref.clone(),
            provenance.source_assurance.allowed_epistemic_use.clone(),
            closure.current_influence,
            retrievable,
            support_revision,
            provenance.state_fence.clone(),
        )
    }

    pub fn validate(&self) -> Result<(), InfluenceRuntimeError> {
        if self.subject_ref.trim().is_empty() || self.subject_ref.chars().any(char::is_control) {
            return Err(InfluenceRuntimeError::InvalidField("subject_ref"));
        }
        if self.origin_ref.trim().is_empty() || self.origin_ref.chars().any(char::is_control) {
            return Err(InfluenceRuntimeError::InvalidField("origin_ref"));
        }
        if self.allowed_uses.is_empty() {
            return Err(InfluenceRuntimeError::InvalidField("allowed_uses"));
        }
        self.state_fence
            .validate()
            .map_err(|_| InfluenceRuntimeError::InvalidField("state_fence"))?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }

    fn max_rank(&self) -> u8 {
        self.allowed_uses
            .iter()
            .copied()
            .map(RuntimeUse::rank)
            .max()
            .unwrap_or(0)
    }

    fn is_exploratory_only(&self) -> bool {
        self.max_rank() <= RuntimeUse::rank(EpistemicUse::Observation)
    }
}

/// Read-only retrieval view. Constructed only through [`retrieve_view`], which
/// takes a shared reference, so retrieval cannot mutate support or influence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeView {
    pub subject_ref: String,
    pub origin_ref: String,
    pub allowed_uses: Vec<EpistemicUse>,
    pub influence: InfluenceState,
    pub retrievable: bool,
    pub support_revision: u64,
}

/// Retrieve a read-only view without mutating support or influence.
///
/// Takes only `&RuntimeSubject` (no `&mut`, no interior mutability), so the
/// caller's subject value is unchanged by retrieval.
#[must_use]
pub fn retrieve_view(subject: &RuntimeSubject) -> RuntimeView {
    RuntimeView {
        subject_ref: subject.subject_ref.clone(),
        origin_ref: subject.origin_ref.clone(),
        allowed_uses: subject.allowed_uses.clone(),
        influence: subject.influence,
        retrievable: subject.retrievable,
        support_revision: subject.support_revision,
    }
}

/// Allow / deny / degraded-use verdict of the mandatory policy gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuntimeVerdict {
    pub subject_ref: String,
    pub subject_digest: String,
    pub requested: RuntimeUse,
    pub kind: RuntimeVerdictKind,
    pub reasons: Vec<RuntimeReason>,
    pub allowed_fallback: Option<RuntimeUse>,
    pub state_fence: StateFence,
}

impl RuntimeVerdict {
    #[must_use]
    pub fn is_allow(&self) -> bool {
        matches!(self.kind, RuntimeVerdictKind::Allow)
    }
}

/// Mandatory policy gate for the reachable influence runtime path.
///
/// Every boundary (`admit_context`, `inject_pending`, `decide_material`,
/// `bind_result`) calls this gate; there is no other admission route. Allow
/// carries no reasons; deny and degraded-use always state at least one
/// reason naming the missing allowance.
pub fn policy_gate(
    subject: &RuntimeSubject,
    requested: RuntimeUse,
) -> Result<RuntimeVerdict, InfluenceRuntimeError> {
    subject.validate()?;
    let subject_digest = subject.digest()?;
    let stated =
        |kind: RuntimeVerdictKind, reasons: Vec<RuntimeReason>, fallback: Option<RuntimeUse>| {
            RuntimeVerdict {
                subject_ref: subject.subject_ref.clone(),
                subject_digest: subject_digest.clone(),
                requested,
                kind,
                reasons,
                allowed_fallback: fallback,
                state_fence: subject.state_fence.clone(),
            }
        };

    if !subject.retrievable {
        return Ok(stated(
            RuntimeVerdictKind::Deny,
            vec![RuntimeReason::RecordNotRetrievable],
            None,
        ));
    }
    if subject.influence != InfluenceState::Active {
        return Ok(stated(
            RuntimeVerdictKind::Deny,
            vec![RuntimeReason::InfluenceNotActive {
                state: subject.influence,
            }],
            None,
        ));
    }

    let required = requested.required_use();
    let max_rank = subject.max_rank();
    if max_rank >= RuntimeUse::rank(required) {
        if matches!(requested, RuntimeUse::ConfirmatoryAcceptance)
            && !subject.qualified_for_confirmatory
        {
            return Ok(stated(
                RuntimeVerdictKind::DegradedUse,
                vec![RuntimeReason::ConfirmatoryRequiresQualification],
                Some(RuntimeUse::DecisionInput),
            ));
        }
        return Ok(stated(RuntimeVerdictKind::Allow, Vec::new(), None));
    }

    let not_allowed = RuntimeReason::EpistemicUseNotAllowed {
        requested: required,
        allowed: subject.allowed_uses.clone(),
    };
    if subject.is_exploratory_only() {
        let specific = match requested {
            RuntimeUse::ExploratoryRead => None,
            RuntimeUse::DecisionInput => Some(RuntimeReason::UseCappedToExploratory),
            RuntimeUse::VerifierInput => Some(RuntimeReason::ExploratoryOnlyCannotSatisfyVerifier),
            RuntimeUse::ConfirmatoryAcceptance => {
                Some(RuntimeReason::ExploratoryOnlyCannotSatisfyConfirmatory)
            }
        };
        let mut reasons = vec![not_allowed];
        if let Some(reason) = specific {
            reasons.push(reason);
        }
        return Ok(stated(RuntimeVerdictKind::Deny, reasons, None));
    }
    let (reasons, fallback) = match requested {
        RuntimeUse::ExploratoryRead => (vec![not_allowed], None),
        RuntimeUse::DecisionInput => (
            vec![not_allowed, RuntimeReason::UseCappedToExploratory],
            Some(RuntimeUse::ExploratoryRead),
        ),
        RuntimeUse::VerifierInput => (
            vec![
                not_allowed,
                RuntimeReason::VerifierRequiresVerificationInput,
            ],
            Some(RuntimeUse::DecisionInput),
        ),
        RuntimeUse::ConfirmatoryAcceptance => (
            vec![
                not_allowed,
                RuntimeReason::ConfirmatoryRequiresQualification,
            ],
            Some(RuntimeUse::DecisionInput),
        ),
    };
    let kind = if fallback.is_some() {
        RuntimeVerdictKind::DegradedUse
    } else {
        RuntimeVerdictKind::Deny
    };
    Ok(stated(kind, reasons, fallback))
}

/// Explicit qualifying transition: evidence-backed promotion of allowed use.
///
/// Takes a shared reference and returns a new subject; the input is never
/// mutated. Adding a decision-grade use (`CANDIDATE_EVIDENCE` or stronger)
/// with a non-blank evidence reference also sets the confirmatory
/// qualification flag. Support revision and influence are carried over
/// unchanged: qualification changes what may be used, never the support or
/// influence state itself.
pub fn qualify_transition(
    subject: &RuntimeSubject,
    added: EpistemicUse,
    evidence_ref: &str,
) -> Result<RuntimeSubject, InfluenceRuntimeError> {
    subject.validate()?;
    if evidence_ref.trim().is_empty() || evidence_ref.chars().any(char::is_control) {
        return Err(InfluenceRuntimeError::InvalidField("evidence_ref"));
    }
    if subject.influence != InfluenceState::Active {
        return Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::MaterialDecision,
            subject: subject.subject_ref.clone(),
            reasons: vec![RuntimeReason::InfluenceNotActive {
                state: subject.influence,
            }],
        });
    }
    let mut allowed = subject.allowed_uses.clone();
    if !allowed.contains(&added) {
        allowed.push(added);
        allowed.sort_by_key(|use_| RuntimeUse::rank(*use_));
    }
    let qualified = subject.qualified_for_confirmatory
        || RuntimeUse::rank(added) >= RuntimeUse::rank(EpistemicUse::CandidateEvidence);
    let mut next = RuntimeSubject::new(
        subject.subject_ref.clone(),
        subject.origin_ref.clone(),
        allowed,
        subject.influence,
        subject.retrievable,
        subject.support_revision,
        subject.state_fence.clone(),
    )?;
    next.qualified_for_confirmatory = qualified;
    Ok(next)
}

/// Context-admission boundary: admits a retrievable subject for exploratory
/// read. This is the only entry to the reachable path.
pub fn admit_context(subject: &RuntimeSubject) -> Result<AdmissionReceipt, InfluenceRuntimeError> {
    let verdict = policy_gate(subject, RuntimeUse::ExploratoryRead)?;
    if !verdict.is_allow() {
        return Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::ContextAdmission,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
        });
    }
    Ok(AdmissionReceipt {
        subject_ref: subject.subject_ref.clone(),
        subject_digest: verdict.subject_digest,
        verdict_kind: verdict.kind,
        state_fence: subject.state_fence.clone(),
    })
}

/// Pending-injection boundary: stages an admitted subject for use. Requires
/// the admission receipt for the same subject digest and state fence, and
/// re-runs the gate.
pub fn inject_pending(
    subject: &RuntimeSubject,
    admission: &AdmissionReceipt,
) -> Result<PendingReceipt, InfluenceRuntimeError> {
    let digest = subject.digest()?;
    if admission.subject_digest != digest || admission.subject_ref != subject.subject_ref {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::PendingInjection,
        });
    }
    if admission.state_fence != subject.state_fence {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::PendingInjection,
        });
    }
    if !matches!(admission.verdict_kind, RuntimeVerdictKind::Allow) {
        return Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::PendingInjection,
            subject: subject.subject_ref.clone(),
            reasons: vec![RuntimeReason::RecordNotRetrievable],
        });
    }
    let verdict = policy_gate(subject, RuntimeUse::ExploratoryRead)?;
    if !verdict.is_allow() {
        return Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::PendingInjection,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
        });
    }
    Ok(PendingReceipt {
        subject_ref: subject.subject_ref.clone(),
        subject_digest: digest,
        admission_digest: admission.digest()?,
        state_fence: subject.state_fence.clone(),
    })
}

/// Validated admission digest for a subject.
///
/// Every later stage re-validates the admission receipt from the subject
/// itself: same subject reference and digest, same state fence, and an allow
/// verdict. A forged or stale admission (matching digest but arbitrary fence,
/// or a digest from a previous subject revision) fails here.
fn validated_admission_digest(
    subject: &RuntimeSubject,
    admission: &AdmissionReceipt,
    stage: RuntimeStage,
) -> Result<String, InfluenceRuntimeError> {
    let digest = subject.digest()?;
    if admission.subject_ref != subject.subject_ref || admission.subject_digest != digest {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    if admission.state_fence != subject.state_fence {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    if !matches!(admission.verdict_kind, RuntimeVerdictKind::Allow) {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    admission
        .digest()
        .map_err(|_| InfluenceRuntimeError::Canonicalization)
}

/// Validated pending digest for a subject and its admission.
///
/// Checks the pending receipt against the subject (reference, digest, fence)
/// and binds it to the validated admission via `admission_digest`. A forged
/// pending receipt with a matching subject digest but an arbitrary fence or
/// predecessor digest fails here, as does a stale pending from a previous
/// subject revision.
fn validated_pending_digest(
    subject: &RuntimeSubject,
    pending: &PendingReceipt,
    admission: &AdmissionReceipt,
    stage: RuntimeStage,
) -> Result<String, InfluenceRuntimeError> {
    let expected_admission = validated_admission_digest(subject, admission, stage)?;
    let digest = subject.digest()?;
    if pending.subject_ref != subject.subject_ref || pending.subject_digest != digest {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    if pending.state_fence != subject.state_fence {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    if pending.admission_digest != expected_admission {
        return Err(InfluenceRuntimeError::BindingMismatch { stage });
    }
    pending
        .digest()
        .map_err(|_| InfluenceRuntimeError::Canonicalization)
}

/// Material-decision boundary: consumes a pending receipt as decision or
/// verifier input. The validated admission receipt must accompany the pending
/// receipt so the pending fence and predecessor digest are bound to the same
/// subject revision. A retrievable-but-restricted record is denied here with a
/// stated reason. Degraded-use is reported as an error carrying the degraded
/// verdict so the caller can only proceed at the stated fallback use.
pub fn decide_material(
    subject: &RuntimeSubject,
    pending: &PendingReceipt,
    admission: &AdmissionReceipt,
    requested: RuntimeUse,
) -> Result<DecisionReceipt, InfluenceRuntimeError> {
    if !matches!(
        requested,
        RuntimeUse::DecisionInput | RuntimeUse::VerifierInput
    ) {
        return Err(InfluenceRuntimeError::InvalidUseForStage {
            stage: RuntimeStage::MaterialDecision,
            requested,
        });
    }
    let digest = subject.digest()?;
    let expected_pending =
        validated_pending_digest(subject, pending, admission, RuntimeStage::MaterialDecision)?;
    if pending.subject_digest != digest || pending.subject_ref != subject.subject_ref {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::MaterialDecision,
        });
    }
    let verdict = policy_gate(subject, requested)?;
    match verdict.kind {
        RuntimeVerdictKind::Allow => Ok(DecisionReceipt {
            subject_ref: subject.subject_ref.clone(),
            subject_digest: digest,
            pending_digest: expected_pending,
            requested,
            verdict_kind: verdict.kind,
            state_fence: subject.state_fence.clone(),
        }),
        RuntimeVerdictKind::DegradedUse => Err(InfluenceRuntimeError::Degraded {
            stage: RuntimeStage::MaterialDecision,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
            fallback: verdict.allowed_fallback,
        }),
        RuntimeVerdictKind::Deny => Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::MaterialDecision,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
        }),
    }
}

/// Result-binding boundary: binds a material decision as a verifier or
/// confirmatory result. The validated pending and admission receipts must
/// accompany the decision so the decision fence and predecessor digest are
/// bound to the same subject revision, and the binding use must not exceed
/// the decision use (a `DECISION_INPUT` receipt cannot yield a
/// `VERIFIER_INPUT` binding). An exploratory-only record cannot satisfy
/// verifier or confirmatory acceptance here without a qualifying transition.
pub fn bind_result(
    subject: &RuntimeSubject,
    decision: &DecisionReceipt,
    pending: &PendingReceipt,
    admission: &AdmissionReceipt,
    requested: RuntimeUse,
) -> Result<BindingReceipt, InfluenceRuntimeError> {
    if !matches!(
        requested,
        RuntimeUse::VerifierInput | RuntimeUse::ConfirmatoryAcceptance
    ) {
        return Err(InfluenceRuntimeError::InvalidUseForStage {
            stage: RuntimeStage::ResultBinding,
            requested,
        });
    }
    let digest = subject.digest()?;
    let expected_pending =
        validated_pending_digest(subject, pending, admission, RuntimeStage::ResultBinding)?;
    if decision.subject_digest != digest || decision.subject_ref != subject.subject_ref {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    if decision.state_fence != subject.state_fence {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    if decision.pending_digest != expected_pending {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    if !matches!(decision.verdict_kind, RuntimeVerdictKind::Allow) {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    if RuntimeUse::rank(requested.required_use())
        > RuntimeUse::rank(decision.requested.required_use())
    {
        return Err(InfluenceRuntimeError::BindingMismatch {
            stage: RuntimeStage::ResultBinding,
        });
    }
    let verdict = policy_gate(subject, requested)?;
    match verdict.kind {
        RuntimeVerdictKind::Allow => Ok(BindingReceipt {
            subject_ref: subject.subject_ref.clone(),
            subject_digest: digest,
            decision_digest: decision.digest()?,
            requested,
            state_fence: subject.state_fence.clone(),
        }),
        RuntimeVerdictKind::DegradedUse => Err(InfluenceRuntimeError::Degraded {
            stage: RuntimeStage::ResultBinding,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
            fallback: verdict.allowed_fallback,
        }),
        RuntimeVerdictKind::Deny => Err(InfluenceRuntimeError::Denied {
            stage: RuntimeStage::ResultBinding,
            subject: subject.subject_ref.clone(),
            reasons: verdict.reasons,
        }),
    }
}

/// Digest-bound admission receipt: context-admission boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    pub subject_ref: String,
    pub subject_digest: String,
    pub verdict_kind: RuntimeVerdictKind,
    pub state_fence: StateFence,
}

impl AdmissionReceipt {
    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }
}

/// Digest-bound pending receipt: pending-injection boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PendingReceipt {
    pub subject_ref: String,
    pub subject_digest: String,
    pub admission_digest: String,
    pub state_fence: StateFence,
}

impl PendingReceipt {
    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }
}

/// Digest-bound decision receipt: material-decision boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub subject_ref: String,
    pub subject_digest: String,
    pub pending_digest: String,
    pub requested: RuntimeUse,
    pub verdict_kind: RuntimeVerdictKind,
    pub state_fence: StateFence,
}

impl DecisionReceipt {
    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }
}

/// Digest-bound binding receipt: result-binding boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingReceipt {
    pub subject_ref: String,
    pub subject_digest: String,
    pub decision_digest: String,
    pub requested: RuntimeUse,
    pub state_fence: StateFence,
}

impl BindingReceipt {
    pub fn digest(&self) -> Result<String, InfluenceRuntimeError> {
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| InfluenceRuntimeError::Canonicalization)
    }
}

/// Runtime path failure. Deny and degraded-use always carry the stated gate
/// reasons; nothing on this path panics on policy input.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum InfluenceRuntimeError {
    #[error("invalid runtime field: {0}")]
    InvalidField(&'static str),
    #[error("runtime use denied")]
    Denied {
        stage: RuntimeStage,
        subject: String,
        reasons: Vec<RuntimeReason>,
    },
    #[error("runtime use degraded to a weaker allowance")]
    Degraded {
        stage: RuntimeStage,
        subject: String,
        reasons: Vec<RuntimeReason>,
        fallback: Option<RuntimeUse>,
    },
    #[error("runtime path binding mismatch")]
    BindingMismatch { stage: RuntimeStage },
    #[error("runtime use is not valid at this stage")]
    InvalidUseForStage {
        stage: RuntimeStage,
        requested: RuntimeUse,
    },
    #[error("runtime record cannot be canonically serialized")]
    Canonicalization,
}

fn text(value: &str, field: &'static str) -> Result<(), InfluenceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(InfluenceError::InvalidField(field))
    } else {
        Ok(())
    }
}
fn unique(values: &[String], field: &'static str) -> Result<(), InfluenceError> {
    let mut set = BTreeSet::new();
    if values.iter().any(|value| !set.insert(value)) {
        Err(InfluenceError::DuplicateReference(field))
    } else {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum InfluenceError {
    #[error("invalid influence field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate influence reference in {0}")]
    DuplicateReference(&'static str),
    #[error("source assurance is invalid")]
    InvalidSourceAssurance,
    #[error("influence dependency closure is invalid")]
    InvalidClosure,
    #[error("influence provenance or state fence does not match")]
    FenceOrLineageMismatch,
    #[error("influence request cannot be canonically serialized")]
    Canonicalization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_security_contracts::{
        CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
        InstructionTaint, IntegrityStatus, PrivacyClass, QuarantineState,
    };

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> StateFence {
        let lineage = match EpochLineageId::new(TEST_LINEAGE) {
            Ok(lineage) => lineage,
            Err(error) => panic!("valid test lineage: {error:?}"),
        };
        let Some(ordinal) = std::num::NonZeroU64::new(7) else {
            panic!("nonzero test epoch ordinal")
        };
        let epoch = match EpochId::new(lineage, ordinal) {
            Ok(epoch) => epoch,
            Err(error) => panic!("valid test epoch: {error:?}"),
        };
        let generation = match ResourceGeneration::new(3) {
            Ok(generation) => generation,
            Err(error) => panic!("valid test generation: {error:?}"),
        };
        StateFence::new(epoch, generation)
    }

    fn clean_assurance(fence: &StateFence) -> SourceAssurance {
        SourceAssurance {
            source_ref: "source:test".to_string(),
            provenance_ref: "provenance:test".to_string(),
            integrity: IntegrityStatus::Verified,
            freshness: FreshnessStatus::Current,
            competence: CompetenceLevel::DomainVerified,
            independence: IndependenceLevel::Independent,
            privacy_class: PrivacyClass::Public,
            instruction_taint: InstructionTaint::Cleared,
            allowed_epistemic_use: vec![EpistemicUse::Observation],
            allowed_effects: vec![EffectCeiling::ReadOnly],
            required_verifier: None,
            quarantine: QuarantineState::None,
            state_fence: fence.clone(),
        }
    }

    fn test_closure(fence: &StateFence, state: InfluenceState) -> InfluenceDependencyClosure {
        InfluenceDependencyClosure {
            closure_id: "closure:test".to_string(),
            root_ref: "origin:test".to_string(),
            dependent_refs: vec!["origin:test".to_string(), "derived:test".to_string()],
            invalidation_reason: if state == InfluenceState::Active {
                None
            } else {
                Some(RevocationReason::Erasure)
            },
            current_influence: state,
            state_fence: fence.clone(),
            revision: 1,
        }
    }

    fn test_request(state: InfluenceState) -> InfluenceRequest {
        let fence = test_fence();
        let policy = InfluencePolicy {
            policy_id: "policy:test".to_string(),
            revision: 1,
            state_fence: fence.clone(),
            require_verified_integrity: false,
            require_current_freshness: false,
            allow_unknown_independence: true,
            allow_instruction_taint: true,
            minimum_level: InfluenceLevel::VerifiedUse,
        };
        let provenance = ProvenanceRecord {
            subject_ref: "subject:test".to_string(),
            origin_ref: "origin:test".to_string(),
            source_assurance: clean_assurance(&fence),
            parent_refs: vec!["parent:test".to_string()],
            transformation_ref: None,
            state_fence: fence.clone(),
        };
        InfluenceRequest {
            request_id: "request:test".to_string(),
            subject_ref: "subject:test".to_string(),
            requested_level: InfluenceLevel::VerifiedUse,
            policy,
            provenance,
            dependency_closure: test_closure(&fence, state),
        }
    }

    #[test]
    fn revoked_closure_blocks_use() {
        let decision = match decide(&test_request(InfluenceState::Revoked)) {
            Ok(decision) => decision,
            Err(error) => panic!("revoked decide succeeds: {error:?}"),
        };
        assert_eq!(decision.disposition, InfluenceDisposition::Revoked);
        assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
        assert!(
            decision
                .reasons
                .contains(&InfluenceReason::DependencyRevoked)
        );
    }

    #[test]
    fn revocation_output_blocks_decide() {
        let fence = test_fence();
        let receipt = match revoke(&RevocationRequest {
            request_id: "revoke:test".to_string(),
            root_ref: "origin:test".to_string(),
            reason: RevocationReason::Erasure,
            state_fence: fence.clone(),
            graph: vec![
                InfluenceEdge {
                    source_ref: "origin:test".to_string(),
                    dependent_ref: "derived:test".to_string(),
                },
                InfluenceEdge {
                    source_ref: "derived:test".to_string(),
                    dependent_ref: "leaf:test".to_string(),
                },
            ],
        }) {
            Ok(receipt) => receipt,
            Err(error) => panic!("revoke succeeds: {error:?}"),
        };
        assert!(receipt.affected_refs.contains(&"origin:test".to_string()));
        assert!(receipt.affected_refs.contains(&"derived:test".to_string()));
        assert!(receipt.affected_refs.contains(&"leaf:test".to_string()));
        for closure in &receipt.closures {
            assert_eq!(closure.current_influence, InfluenceState::Revoked);
        }
        let Some(revoked) = receipt
            .closures
            .iter()
            .find(|closure| closure.root_ref == "origin:test")
        else {
            panic!("revocation covers its root")
        };
        let mut request = test_request(InfluenceState::Active);
        request.dependency_closure = revoked.clone();
        request.provenance.origin_ref = revoked.root_ref.clone();
        request.dependency_closure.closure_id = "closure:test".to_string();
        let decision = match decide(&request) {
            Ok(decision) => decision,
            Err(error) => panic!("revoked closure decide succeeds: {error:?}"),
        };
        assert_eq!(decision.disposition, InfluenceDisposition::Revoked);
        assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
    }

    #[test]
    fn unknown_closure_fails_closed() {
        let decision = match decide(&test_request(InfluenceState::Unknown)) {
            Ok(decision) => decision,
            Err(error) => panic!("unknown decide succeeds: {error:?}"),
        };
        assert_eq!(decision.disposition, InfluenceDisposition::Quarantined);
        assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
        assert!(
            decision
                .reasons
                .contains(&InfluenceReason::DependencyQuarantined)
        );
    }

    #[test]
    fn quarantined_closure_quarantines() {
        let decision = match decide(&test_request(InfluenceState::Quarantined)) {
            Ok(decision) => decision,
            Err(error) => panic!("quarantined decide succeeds: {error:?}"),
        };
        assert_eq!(decision.disposition, InfluenceDisposition::Quarantined);
        assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
    }

    fn runtime_subject(
        allowed: Vec<EpistemicUse>,
        influence: InfluenceState,
        retrievable: bool,
    ) -> RuntimeSubject {
        let fence = test_fence();
        match RuntimeSubject::new(
            "subject:runtime".to_string(),
            "origin:runtime".to_string(),
            allowed,
            influence,
            retrievable,
            11,
            fence,
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("valid runtime subject: {error:?}"),
        }
    }

    fn qualified_subject(allowed: Vec<EpistemicUse>) -> RuntimeSubject {
        let base = runtime_subject(allowed, InfluenceState::Active, true);
        match qualify_transition(
            &base,
            EpistemicUse::CandidateEvidence,
            "evidence:test-qualification",
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("test qualification succeeds: {error:?}"),
        }
    }

    fn deny_reasons(result: Result<DecisionReceipt, InfluenceRuntimeError>) -> Vec<RuntimeReason> {
        match result {
            Ok(_) => panic!("expected denial, got allowance"),
            Err(InfluenceRuntimeError::Denied { reasons, .. }) => reasons,
            Err(other) => panic!("expected denial, got {other:?}"),
        }
    }

    #[test]
    fn retrievable_but_restricted_denied_as_decision_input_with_reason() {
        let subject = runtime_subject(
            vec![EpistemicUse::Observation],
            InfluenceState::Active,
            true,
        );
        // Retrievable: exploratory admission through the reachable path succeeds.
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("exploratory admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("pending injection succeeds: {error:?}"),
        };
        // Restricted: the same record is denied as material decision input,
        // and the verdict states the missing allowance.
        let verdict = match policy_gate(&subject, RuntimeUse::DecisionInput) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates: {error:?}"),
        };
        assert_eq!(verdict.kind, RuntimeVerdictKind::Deny);
        let missing = verdict.reasons.iter().any(|reason| {
            matches!(
                reason,
                RuntimeReason::EpistemicUseNotAllowed {
                    requested: EpistemicUse::CandidateEvidence,
                    ..
                }
            )
        });
        assert!(
            missing,
            "denial states the missing use: {:?}",
            verdict.reasons
        );
        let reasons = deny_reasons(decide_material(
            &subject,
            &pending,
            &admission,
            RuntimeUse::DecisionInput,
        ));
        assert!(
            reasons
                .iter()
                .any(|reason| matches!(reason, RuntimeReason::EpistemicUseNotAllowed { .. }))
        );
    }

    #[test]
    fn exploratory_only_needs_qualifying_transition_for_verifier_and_confirmatory() {
        let subject = runtime_subject(
            vec![EpistemicUse::Observation],
            InfluenceState::Active,
            true,
        );
        let verifier_verdict = match policy_gate(&subject, RuntimeUse::VerifierInput) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates verifier use: {error:?}"),
        };
        assert_eq!(verifier_verdict.kind, RuntimeVerdictKind::Deny);
        assert!(
            verifier_verdict
                .reasons
                .contains(&RuntimeReason::ExploratoryOnlyCannotSatisfyVerifier)
        );
        let confirmatory_verdict = match policy_gate(&subject, RuntimeUse::ConfirmatoryAcceptance) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates confirmatory use: {error:?}"),
        };
        assert_eq!(confirmatory_verdict.kind, RuntimeVerdictKind::Deny);
        assert!(
            confirmatory_verdict
                .reasons
                .contains(&RuntimeReason::ExploratoryOnlyCannotSatisfyConfirmatory)
        );

        // Qualifying transition promotes the copy; the original stays exploratory-only.
        let qualified = match qualify_transition(
            &subject,
            EpistemicUse::CandidateEvidence,
            "evidence:analyst-review-1",
        ) {
            Ok(qualified) => qualified,
            Err(error) => panic!("qualification succeeds: {error:?}"),
        };
        assert_eq!(subject.allowed_uses, vec![EpistemicUse::Observation]);
        assert!(!subject.qualified_for_confirmatory);
        let confirmatory_after = match policy_gate(&qualified, RuntimeUse::ConfirmatoryAcceptance) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates qualified confirmatory: {error:?}"),
        };
        assert_eq!(confirmatory_after.kind, RuntimeVerdictKind::Allow);
        // Candidate evidence alone still cannot satisfy verifier input: it
        // degrades to decision input instead of allowing silently.
        let verifier_after = match policy_gate(&qualified, RuntimeUse::VerifierInput) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates qualified verifier: {error:?}"),
        };
        assert_eq!(verifier_after.kind, RuntimeVerdictKind::DegradedUse);
        assert_eq!(
            verifier_after.allowed_fallback,
            Some(RuntimeUse::DecisionInput)
        );

        let verified = match qualify_transition(
            &qualified,
            EpistemicUse::VerificationInput,
            "evidence:verifier-run-7",
        ) {
            Ok(verified) => verified,
            Err(error) => panic!("verifier qualification succeeds: {error:?}"),
        };
        let verifier_final = match policy_gate(&verified, RuntimeUse::VerifierInput) {
            Ok(verdict) => verdict,
            Err(error) => panic!("gate evaluates verified use: {error:?}"),
        };
        assert_eq!(verifier_final.kind, RuntimeVerdictKind::Allow);

        // Full reachable path succeeds only after the qualifying transition.
        let admission = match admit_context(&verified) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&verified, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&verified, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("material decision succeeds: {error:?}"),
            };
        match bind_result(
            &verified,
            &decision,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => {}
            Err(error) => panic!("result binding succeeds: {error:?}"),
        }
    }

    #[test]
    fn retrieval_never_mutates_support_or_influence() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let before_digest = match subject.digest() {
            Ok(digest) => digest,
            Err(error) => panic!("subject digests: {error:?}"),
        };
        let view = retrieve_view(&subject);
        assert_eq!(view.subject_ref, subject.subject_ref);
        assert_eq!(view.allowed_uses, subject.allowed_uses);
        assert_eq!(view.influence, subject.influence);
        assert_eq!(view.support_revision, subject.support_revision);
        assert_eq!(view.retrievable, subject.retrievable);
        // Exercise the whole reachable path against the same subject value.
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&subject, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision succeeds: {error:?}"),
            };
        match bind_result(
            &subject,
            &decision,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => {}
            Err(error) => panic!("binding succeeds: {error:?}"),
        }
        let again = retrieve_view(&subject);
        assert_eq!(again, view);
        let after_digest = match subject.digest() {
            Ok(digest) => digest,
            Err(error) => panic!("subject digests after use: {error:?}"),
        };
        assert_eq!(before_digest, after_digest);
        assert_eq!(subject.influence, InfluenceState::Active);
        assert_eq!(subject.support_revision, 11);
    }

    #[test]
    fn runtime_path_is_reachable_in_order_only() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let other = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        // A pending stage bound to one subject cannot inject another digest.
        let mut foreign = admission.clone();
        foreign.subject_ref = "subject:other".to_string();
        match inject_pending(&other, &foreign) {
            Ok(_) => panic!("foreign injection must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
        // Material decision rejects a use that does not belong at its stage.
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        match decide_material(
            &subject,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("wrong-stage use must fail"),
            Err(InfluenceRuntimeError::InvalidUseForStage { .. }) => {}
            Err(other) => panic!("expected invalid stage use, got {other:?}"),
        }
    }

    fn test_fence_with_generation(generation: u64) -> StateFence {
        let lineage = match EpochLineageId::new(TEST_LINEAGE) {
            Ok(lineage) => lineage,
            Err(error) => panic!("valid test lineage: {error:?}"),
        };
        let Some(ordinal) = std::num::NonZeroU64::new(7) else {
            panic!("nonzero test epoch ordinal")
        };
        let epoch = match EpochId::new(lineage, ordinal) {
            Ok(epoch) => epoch,
            Err(error) => panic!("valid test epoch: {error:?}"),
        };
        let generation = match ResourceGeneration::new(generation) {
            Ok(generation) => generation,
            Err(error) => panic!("valid test generation: {error:?}"),
        };
        StateFence::new(epoch, generation)
    }

    fn test_fence_alt() -> StateFence {
        test_fence_with_generation(9)
    }

    fn runtime_subject_with_fence(
        allowed: Vec<EpistemicUse>,
        influence: InfluenceState,
        retrievable: bool,
        fence: StateFence,
        support_revision: u64,
    ) -> RuntimeSubject {
        match RuntimeSubject::new(
            "subject:runtime".to_string(),
            "origin:runtime".to_string(),
            allowed,
            influence,
            retrievable,
            support_revision,
            fence,
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("valid runtime subject: {error:?}"),
        }
    }

    fn qualified_subject_with_fence(
        allowed: Vec<EpistemicUse>,
        fence: StateFence,
    ) -> RuntimeSubject {
        let base = runtime_subject_with_fence(allowed, InfluenceState::Active, true, fence, 11);
        match qualify_transition(
            &base,
            EpistemicUse::CandidateEvidence,
            "evidence:test-qualification",
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("test qualification succeeds: {error:?}"),
        }
    }

    fn expect_binding_mismatch(result: Result<(), InfluenceRuntimeError>, case: &str) {
        match result {
            Ok(()) => panic!("{case} must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("{case}: expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn inject_pending_rejects_forged_fence() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let mut forged = admission.clone();
        forged.state_fence = test_fence_alt();
        expect_binding_mismatch(
            inject_pending(&subject, &forged).map(|_| ()),
            "forged admission fence",
        );
    }

    #[test]
    fn inject_pending_rejects_stale_admission() {
        let old = qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence());
        let old_admission = match admit_context(&old) {
            Ok(admission) => admission,
            Err(error) => panic!("old admission succeeds: {error:?}"),
        };
        let new =
            qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence_alt());
        expect_binding_mismatch(
            inject_pending(&new, &old_admission).map(|_| ()),
            "stale admission from previous fence",
        );
    }

    #[test]
    fn decide_material_rejects_forged_pending_fence() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let mut forged = pending.clone();
        forged.state_fence = test_fence_alt();
        match decide_material(&subject, &forged, &admission, RuntimeUse::DecisionInput) {
            Ok(_) => panic!("forged pending fence must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn decide_material_rejects_forged_admission_digest() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let mut forged = pending.clone();
        forged.admission_digest = "0".repeat(64);
        match decide_material(&subject, &forged, &admission, RuntimeUse::DecisionInput) {
            Ok(_) => panic!("forged admission digest must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn decide_material_rejects_stale_chain() {
        let old = qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence());
        let old_admission = match admit_context(&old) {
            Ok(admission) => admission,
            Err(error) => panic!("old admission succeeds: {error:?}"),
        };
        let old_pending = match inject_pending(&old, &old_admission) {
            Ok(pending) => pending,
            Err(error) => panic!("old injection succeeds: {error:?}"),
        };
        let new =
            qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence_alt());
        let new_admission = match admit_context(&new) {
            Ok(admission) => admission,
            Err(error) => panic!("new admission succeeds: {error:?}"),
        };
        match decide_material(
            &new,
            &old_pending,
            &new_admission,
            RuntimeUse::DecisionInput,
        ) {
            Ok(_) => panic!("stale pending must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
        match decide_material(
            &new,
            &old_pending,
            &old_admission,
            RuntimeUse::DecisionInput,
        ) {
            Ok(_) => panic!("stale pending plus stale admission must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bind_result_rejects_forged_decision_fence() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&subject, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision succeeds: {error:?}"),
            };
        let mut forged = decision.clone();
        forged.state_fence = test_fence_alt();
        match bind_result(
            &subject,
            &forged,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("forged decision fence must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bind_result_rejects_forged_pending_digest() {
        let subject = qualified_subject(vec![EpistemicUse::CandidateEvidence]);
        let admission = match admit_context(&subject) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&subject, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision =
            match decide_material(&subject, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision succeeds: {error:?}"),
            };
        let mut forged = decision.clone();
        forged.pending_digest = "0".repeat(64);
        match bind_result(
            &subject,
            &forged,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("forged pending digest must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bind_result_rejects_stale_chain() {
        let old = qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence());
        let old_admission = match admit_context(&old) {
            Ok(admission) => admission,
            Err(error) => panic!("old admission succeeds: {error:?}"),
        };
        let old_pending = match inject_pending(&old, &old_admission) {
            Ok(pending) => pending,
            Err(error) => panic!("old injection succeeds: {error:?}"),
        };
        let old_decision = match decide_material(
            &old,
            &old_pending,
            &old_admission,
            RuntimeUse::DecisionInput,
        ) {
            Ok(decision) => decision,
            Err(error) => panic!("old decision succeeds: {error:?}"),
        };
        let new =
            qualified_subject_with_fence(vec![EpistemicUse::CandidateEvidence], test_fence_alt());
        let new_admission = match admit_context(&new) {
            Ok(admission) => admission,
            Err(error) => panic!("new admission succeeds: {error:?}"),
        };
        let new_pending = match inject_pending(&new, &new_admission) {
            Ok(pending) => pending,
            Err(error) => panic!("new injection succeeds: {error:?}"),
        };
        match bind_result(
            &new,
            &old_decision,
            &new_pending,
            &new_admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("stale decision must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
        match bind_result(
            &new,
            &old_decision,
            &old_pending,
            &old_admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => panic!("fully stale chain must fail"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
    }

    #[test]
    fn bind_result_rejects_decision_input_for_verifier_binding() {
        let base = runtime_subject_with_fence(
            vec![EpistemicUse::CandidateEvidence],
            InfluenceState::Active,
            true,
            test_fence(),
            11,
        );
        let qualified = match qualify_transition(
            &base,
            EpistemicUse::CandidateEvidence,
            "evidence:test-qualification",
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("test qualification succeeds: {error:?}"),
        };
        let verified = match qualify_transition(
            &qualified,
            EpistemicUse::VerificationInput,
            "evidence:verifier-run-7",
        ) {
            Ok(subject) => subject,
            Err(error) => panic!("verifier qualification succeeds: {error:?}"),
        };
        let admission = match admit_context(&verified) {
            Ok(admission) => admission,
            Err(error) => panic!("admission succeeds: {error:?}"),
        };
        let pending = match inject_pending(&verified, &admission) {
            Ok(pending) => pending,
            Err(error) => panic!("injection succeeds: {error:?}"),
        };
        let decision_input =
            match decide_material(&verified, &pending, &admission, RuntimeUse::DecisionInput) {
                Ok(decision) => decision,
                Err(error) => panic!("decision input succeeds: {error:?}"),
            };
        assert_eq!(decision_input.requested, RuntimeUse::DecisionInput);
        match bind_result(
            &verified,
            &decision_input,
            &pending,
            &admission,
            RuntimeUse::VerifierInput,
        ) {
            Ok(_) => panic!("decision-input receipt must not yield verifier binding"),
            Err(InfluenceRuntimeError::BindingMismatch { .. }) => {}
            Err(other) => panic!("expected binding mismatch, got {other:?}"),
        }
        let verifier_decision =
            match decide_material(&verified, &pending, &admission, RuntimeUse::VerifierInput) {
                Ok(decision) => decision,
                Err(error) => panic!("verifier decision succeeds: {error:?}"),
            };
        match bind_result(
            &verified,
            &verifier_decision,
            &pending,
            &admission,
            RuntimeUse::VerifierInput,
        ) {
            Ok(_) => {}
            Err(error) => panic!("verifier decision binds verifier use: {error:?}"),
        }
        match bind_result(
            &verified,
            &decision_input,
            &pending,
            &admission,
            RuntimeUse::ConfirmatoryAcceptance,
        ) {
            Ok(_) => {}
            Err(error) => panic!("decision input binds confirmatory use: {error:?}"),
        }
    }
}
