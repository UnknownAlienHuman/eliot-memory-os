//! The typed, safe negative-memory probe and its execution (issue #1731 W5,
//! I12.19, A14.3).
//!
//! # What the probe is for
//!
//! An exact admitted [`NegativeMemoryGateDecision::RequireCheck`] does not block
//! forever: it names the one safe discriminating check that has to run before
//! the matched action may be re-attempted. This module owns that check's whole
//! contract and — the point of it — its execution.
//!
//! # A proposal is not an executor
//!
//! [`admit_negative_memory_probe`] produces a
//! [`NegativeMemoryProbeProposal`] with private fields. It can only be built
//! from an exact admitted `RequireCheck` decision whose rule set resolved
//! completely, so there is no path by which a caller can name a check for a
//! near match, an advisory disposition, or an undecidable lookup. The proposal
//! carries the *protected* action identity it stands in front of, a closed
//! read-only effect ceiling, a fixed bounded budget, a forbidden-effect guard
//! over the recorded destructive effect, and a deterministic probe identity
//! that is distinct from the protected operation.
//!
//! # The executor, and why it is a read
//!
//! [`execute_negative_memory_probe`] runs the proposal through a
//! [`NegativeMemoryProbeExecutor`], and this module supplies
//! [`NamedReadProbeExecutor`]: it re-reads the **same** activation-receipt
//! scope through the same closed exact-fence named read the rule set came from
//! and reports what the store currently serves. The prohibited destructive
//! action is never a command here, so the probe cannot repeat it under a new
//! label — there is no executable effect anywhere in this module, only a
//! bounded read whose result is compared against the record's own
//! discriminating-check binding.
//!
//! # A user or model assertion cannot reopen work
//!
//! [`NegativeMemoryProbeAdmission`] has private fields and no public
//! constructor other than [`execute_negative_memory_probe`]. The admission
//! requires that the executed observation (a) was served at the *store-observed*
//! read fence, (b) came from the verifier identity, revision and digest the
//! **record itself** binds on its discriminating check, and (c) covers at least
//! one of the trigger dimensions the record itself declares. A caller that
//! asserts "the probe passed", or a model that reports one, cannot construct an
//! admission at all: the constructor is unreachable from outside this module
//! and the content it checks comes from the store, not from the assertion.

#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

use eliot_contracts::{OperationId, StateFence};
use eliot_dreamer_failure::{
    NegativeMemoryCheckOutcome, NegativeMemoryFingerprint, effect_class_text,
};
use eliot_receipts::EffectClass;
use eliot_store_api::{
    NamedReadOperation, NamedReadRequest, NamedReadResponse, ScopeId, canonical_json_bytes,
    sha256_hex,
};

use crate::composition::CompositionError;
use crate::negative_memory_gate::NegativeMemoryGateDecision;
use crate::negative_memory_read::ResolvedNegativeMemoryRuleSet;

/// Maximum bytes one probe read response may carry into an admission.
///
/// The probe is bounded before it is executed, not after.
pub const MAX_NEGATIVE_MEMORY_PROBE_RESPONSE_BYTES: usize = 262_144;

/// Why a probe was refused.
///
/// Every variant means no probe admission exists. None is a passing check, and
/// none can be satisfied by an assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeMemoryProbeRefusal {
    /// The gate decision was not an exact admitted `RequireCheck`.
    NotARequiredCheck {
        /// The decision the caller presented, named by its own kind.
        decision: &'static str,
    },
    /// The rule set the decision was taken over was not a complete enumeration.
    RuleSetIncomplete,
    /// The gate decision and the rule set name different rules or different
    /// check bindings.
    DecisionRuleNotInRuleSet,
    /// The proposal does not satisfy its own closed invariants.
    ProposalInvalid(String),
    /// The bounded probe read could not be issued or re-proved.
    ExecutionFailed(String),
    /// The executor reported a read that was served at another fence.
    ProbeFenceNotAuthenticated {
        /// The fence the store served the probe read at.
        served: Box<StateFence>,
        /// The fence the proposal was admitted at.
        expected: Box<StateFence>,
    },
    /// The executed observation did not come from the verifier the record binds.
    VerifierNotBound {
        /// The verifier identity the execution reported.
        observed: String,
        /// The verifier identity the record binds.
        required: String,
    },
    /// The execution discriminated none of the recorded trigger dimensions.
    NoDiscriminatingDimension {
        /// The dimensions the execution claimed to have checked.
        observed: Vec<String>,
        /// The dimensions the record declares its check discriminates.
        required: Vec<String>,
    },
}

impl std::fmt::Display for NegativeMemoryProbeRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotARequiredCheck { decision } => {
                write!(
                    formatter,
                    "gate decision {decision} names no required check"
                )
            }
            Self::RuleSetIncomplete => {
                write!(
                    formatter,
                    "the rule set the decision was taken over is incomplete"
                )
            }
            Self::DecisionRuleNotInRuleSet => {
                write!(
                    formatter,
                    "the required-check rule or check binding is absent from the rule set"
                )
            }
            Self::ProposalInvalid(detail) => write!(formatter, "probe proposal: {detail}"),
            Self::ExecutionFailed(detail) => write!(formatter, "probe read failed: {detail}"),
            Self::ProbeFenceNotAuthenticated { .. } => {
                write!(
                    formatter,
                    "the probe read was not served at the admitted fence"
                )
            }
            Self::VerifierNotBound { observed, required } => write!(
                formatter,
                "probe verifier {observed} is not the record-bound verifier {required}"
            ),
            Self::NoDiscriminatingDimension { observed, required } => write!(
                formatter,
                "probe checked {observed:?} against the recorded {required:?}"
            ),
        }
    }
}

impl std::error::Error for NegativeMemoryProbeRefusal {}

/// The closed effect ceiling a negative-memory probe may hold.
///
/// There is exactly one. A probe that would need a wider ceiling is not a
/// probe: it is the prohibited action under another name, and
/// [`NegativeMemoryProbeProposal::validate`] refuses the construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeMemoryProbeEffectCeiling {
    /// The probe may only read. It may not write, mutate, or effect anything.
    ReadOnly,
}

impl NegativeMemoryProbeEffectCeiling {
    /// The effect class this ceiling permits.
    #[must_use]
    pub const fn permitted_effect_class(self) -> EffectClass {
        match self {
            Self::ReadOnly => EffectClass::Read,
        }
    }
}

/// The fixed, bounded budget one probe execution may consume.
///
/// These are not defaults a caller may raise: they are the whole budget, and
/// [`NegativeMemoryProbeProposal::validate`] compares the proposal's budget
/// against them rather than accepting any value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegativeMemoryProbeBudget {
    /// Maximum named-read pages the probe may issue.
    pub max_pages: u16,
    /// Maximum response bytes the probe may accept.
    pub max_response_bytes: usize,
    /// Maximum wall-clock milliseconds the probe may be given.
    pub max_wall_clock_ms: u64,
}

impl NegativeMemoryProbeBudget {
    /// The closed budget every probe is admitted under.
    #[must_use]
    pub const fn bounded() -> Self {
        Self {
            max_pages: 1,
            max_response_bytes: MAX_NEGATIVE_MEMORY_PROBE_RESPONSE_BYTES,
            max_wall_clock_ms: 5_000,
        }
    }
}

/// What the probe must not do, taken from the rule's own recorded action.
///
/// This is the forbidden-effect guard. It holds the exact effect class, effect
/// identity and operation identity of the action the rule was written for, so
/// an executor reaching the same effect under the probe's label is caught by a
/// value comparison rather than by its own good intentions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryProbeForbiddenEffectGuard {
    /// The recorded effect class the probe must not perform.
    pub effect_class: EffectClass,
    /// The recorded effect identity the probe must not perform.
    pub effect_id: String,
    /// The recorded operation identity the probe must not reuse.
    pub operation_id: String,
}

/// One admitted, typed, read-only discriminating-check proposal.
///
/// Every field is private. The only way to obtain one is
/// [`admit_negative_memory_probe`], which requires an exact admitted
/// `RequireCheck` decision over a complete rule set.
#[derive(Clone, Debug, PartialEq)]
pub struct NegativeMemoryProbeProposal {
    operation_id: OperationId,
    record_id: String,
    rule_revision: u64,
    record_digest: String,
    check_id: String,
    required_verifier: String,
    verifier_revision: String,
    verifier_digest: String,
    discriminates_dimension_names: Vec<String>,
    protected_operation_id: String,
    protected_effect_id: String,
    protected_effect_class: EffectClass,
    protected_input_digest: String,
    scope_id: ScopeId,
    admitted_state_fence: StateFence,
    ceiling: NegativeMemoryProbeEffectCeiling,
    budget: NegativeMemoryProbeBudget,
    forbidden_effect: NegativeMemoryProbeForbiddenEffectGuard,
}

/// The immutable record of one executed, admitted probe.
///
/// No field is a verdict the caller supplied: the verifier identity, the
/// discriminated dimensions, the served fence and the digest are all taken
/// from the executed read, and the admission is only constructible through
/// [`execute_negative_memory_probe`].
#[derive(Clone, Debug, PartialEq)]
pub struct NegativeMemoryProbeAdmission {
    /// The probe's own deterministic operation identity.
    pub probe_operation_id: OperationId,
    /// The rule the probe ran for.
    pub record_id: String,
    /// The exact rule revision in force.
    pub rule_revision: u64,
    /// The exact rule content digest in force.
    pub record_digest: String,
    /// The named check that was executed.
    pub check_id: String,
    /// The owner-issued verifier that produced the executed observation.
    pub verifier: String,
    /// The exact trigger dimensions the executed observation discriminated.
    pub discriminated_dimension_names: Vec<String>,
    /// The retained verifier outcome.
    pub outcome: NegativeMemoryCheckOutcome,
    /// The fence the probe read was served at, as the store reported it.
    pub served_state_fence: StateFence,
    /// Digest over the proposal and the served observation together.
    pub admission_digest: String,
}

impl NegativeMemoryProbeProposal {
    /// The probe's own deterministic operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// The named check this probe runs.
    #[must_use]
    pub fn check_id(&self) -> &str {
        self.check_id.as_str()
    }

    /// The scope the probe read is addressed to.
    #[must_use]
    pub const fn scope_id(&self) -> &ScopeId {
        &self.scope_id
    }

    /// The fence the probe was admitted at.
    #[must_use]
    pub const fn admitted_state_fence(&self) -> &StateFence {
        &self.admitted_state_fence
    }

    /// The closed effect ceiling this probe may hold.
    #[must_use]
    pub const fn effect_ceiling(&self) -> NegativeMemoryProbeEffectCeiling {
        self.ceiling
    }

    /// The fixed bounded budget this probe runs under.
    #[must_use]
    pub const fn budget(&self) -> NegativeMemoryProbeBudget {
        self.budget
    }

    /// The forbidden-effect guard derived from the record's own action.
    #[must_use]
    pub const fn forbidden_effect(&self) -> &NegativeMemoryProbeForbiddenEffectGuard {
        &self.forbidden_effect
    }

    /// The trigger dimensions the record's check declares it discriminates.
    #[must_use]
    pub fn discriminates_dimension_names(&self) -> &[String] {
        &self.discriminates_dimension_names
    }

    /// The owner-issued verifier identity the record binds for this check.
    #[must_use]
    pub fn required_verifier(&self) -> &str {
        self.required_verifier.as_str()
    }

    /// The exact verifier revision the record binds for this check.
    #[must_use]
    pub fn verifier_revision(&self) -> &str {
        self.verifier_revision.as_str()
    }

    /// The exact verifier digest the record binds for this check.
    #[must_use]
    pub fn verifier_digest(&self) -> &str {
        self.verifier_digest.as_str()
    }

    /// The exact input digest of the protected action this probe stands in
    /// front of. A probe that re-applied that input under a new label would be
    /// the prohibited action, so the value is retained for the caller to
    /// compare against and is covered by the admission digest.
    #[must_use]
    pub fn protected_input_digest(&self) -> &str {
        self.protected_input_digest.as_str()
    }

    /// Re-checks the proposal's own closed invariants.
    ///
    /// The ceiling is checked against the effect class it permits, the budget
    /// against the closed bounded value, the guard against the protected
    /// action it was derived from, and the probe identity against the protected
    /// operation it must not reuse. Every comparison is against a recorded or
    /// fixed value; none of them asks whether the probe merely looks safe.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryProbeRefusal::ProposalInvalid`] naming the exact
    /// closed invariant that does not hold.
    pub fn validate(&self) -> Result<(), NegativeMemoryProbeRefusal> {
        if self.ceiling.permitted_effect_class() != EffectClass::Read {
            return Err(NegativeMemoryProbeRefusal::ProposalInvalid(
                "a probe may not hold a non-read effect ceiling".to_owned(),
            ));
        }
        if self.protected_effect_class == self.ceiling.permitted_effect_class() {
            return Err(NegativeMemoryProbeRefusal::ProposalInvalid(format!(
                "the probe ceiling would permit the prohibited effect class {}",
                effect_class_text(self.protected_effect_class)
            )));
        }
        if self.budget != NegativeMemoryProbeBudget::bounded() {
            return Err(NegativeMemoryProbeRefusal::ProposalInvalid(
                "budget is not the closed bounded value".to_owned(),
            ));
        }
        if self.operation_id.as_str() == self.protected_operation_id {
            return Err(NegativeMemoryProbeRefusal::ProposalInvalid(format!(
                "probe identity {} reuses the protected operation identity",
                self.operation_id.as_str()
            )));
        }
        if self.forbidden_effect.operation_id != self.protected_operation_id
            || self.forbidden_effect.effect_id != self.protected_effect_id
            || self.forbidden_effect.effect_class != self.protected_effect_class
        {
            return Err(NegativeMemoryProbeRefusal::ProposalInvalid(
                "forbidden-effect guard does not bind the protected action".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Builds the typed probe proposal for one exact admitted `RequireCheck`.
///
/// # Errors
///
/// Returns [`NegativeMemoryProbeRefusal::NotARequiredCheck`] for any decision
/// that is not an exact admitted `RequireCheck`,
/// [`NegativeMemoryProbeRefusal::RuleSetIncomplete`] when the rule set was a
/// truncated enumeration,
/// [`NegativeMemoryProbeRefusal::DecisionRuleNotInRuleSet`] when the decision
/// names a rule or check binding the resolved set does not retain, and
/// [`NegativeMemoryProbeRefusal::ProposalInvalid`] when the closed probe
/// invariants do not hold for the recorded action.
pub fn admit_negative_memory_probe(
    decision: &NegativeMemoryGateDecision,
    resolved: &ResolvedNegativeMemoryRuleSet,
) -> Result<NegativeMemoryProbeProposal, NegativeMemoryProbeRefusal> {
    let NegativeMemoryGateDecision::RequireCheck {
        record_id,
        rule_revision,
        check_id,
        required_verifier,
        discriminates_dimension_names,
        ..
    } = decision
    else {
        return Err(NegativeMemoryProbeRefusal::NotARequiredCheck {
            decision: decision_kind_name(decision),
        });
    };
    if !resolved.enumeration_complete() {
        return Err(NegativeMemoryProbeRefusal::RuleSetIncomplete);
    }
    let record = resolved
        .records()
        .iter()
        .find(|record| record.record_id == *record_id && record.rule_revision == *rule_revision)
        .ok_or(NegativeMemoryProbeRefusal::DecisionRuleNotInRuleSet)?;
    build_proposal(
        record,
        check_id,
        required_verifier,
        discriminates_dimension_names,
        resolved,
    )
}

/// Assembles the proposal from the rule's own recorded check binding.
fn build_proposal(
    record: &NegativeMemoryFingerprint,
    check_id: &str,
    required_verifier: &str,
    discriminates_dimension_names: &[String],
    resolved: &ResolvedNegativeMemoryRuleSet,
) -> Result<NegativeMemoryProbeProposal, NegativeMemoryProbeRefusal> {
    let check = &record.discriminating_check;
    if check.check_id != check_id || check.required_verifier != required_verifier {
        return Err(NegativeMemoryProbeRefusal::DecisionRuleNotInRuleSet);
    }
    if check.discriminates_dimension_names.as_slice() != discriminates_dimension_names {
        return Err(NegativeMemoryProbeRefusal::NoDiscriminatingDimension {
            observed: discriminates_dimension_names.to_vec(),
            required: check.discriminates_dimension_names.clone(),
        });
    }
    let operation_id = OperationId::new(format!(
        "negative-memory-probe:{}:{}:{}",
        record.record_id, record.rule_revision, check.check_id
    ))
    .map_err(|error| NegativeMemoryProbeRefusal::ProposalInvalid(error.to_string()))?;
    let proposal = NegativeMemoryProbeProposal {
        operation_id,
        record_id: record.record_id.clone(),
        rule_revision: record.rule_revision,
        record_digest: record.record_digest.clone(),
        check_id: check.check_id.clone(),
        required_verifier: check.required_verifier.clone(),
        verifier_revision: check.verifier_revision.clone(),
        verifier_digest: check.verifier_digest.clone(),
        discriminates_dimension_names: check.discriminates_dimension_names.clone(),
        protected_operation_id: record.failed_action.operation_id.clone(),
        protected_effect_id: record.failed_action.effect_id.clone(),
        protected_effect_class: record.failed_action.effect_class,
        protected_input_digest: record.failed_action.input_digest.clone(),
        scope_id: resolved.scope_id().clone(),
        admitted_state_fence: resolved.store_observed_fence().clone(),
        ceiling: NegativeMemoryProbeEffectCeiling::ReadOnly,
        budget: NegativeMemoryProbeBudget::bounded(),
        forbidden_effect: NegativeMemoryProbeForbiddenEffectGuard {
            effect_class: record.failed_action.effect_class,
            effect_id: record.failed_action.effect_id.clone(),
            operation_id: record.failed_action.operation_id.clone(),
        },
    };
    proposal.validate()?;
    Ok(proposal)
}

/// Names a decision by its own kind, for a refusal detail.
fn decision_kind_name(decision: &NegativeMemoryGateDecision) -> &'static str {
    match decision {
        NegativeMemoryGateDecision::Block { .. } => "block",
        NegativeMemoryGateDecision::RequireCheck { .. } => "require_check",
        NegativeMemoryGateDecision::Proceed { .. } => "proceed",
        NegativeMemoryGateDecision::Unavailable { .. } => "unavailable",
    }
}

/// One executed, read-only discriminating observation.
///
/// Every field is private. The only producer is [`observed_execution`], which
/// fills it from a store response it has already re-proved, so no caller can
/// report an outcome it did not read.
#[derive(Clone, Debug, PartialEq)]
pub struct NegativeMemoryProbeExecution {
    served_state_fence: StateFence,
    verifier: String,
    verifier_revision: String,
    verifier_digest: String,
    discriminated_dimension_names: Vec<String>,
    outcome: NegativeMemoryCheckOutcome,
    response_digest: String,
}

impl NegativeMemoryProbeExecution {
    /// The fence the store served the probe read at.
    #[must_use]
    pub const fn served_state_fence(&self) -> &StateFence {
        &self.served_state_fence
    }

    /// The retained verifier outcome of the executed observation.
    #[must_use]
    pub const fn outcome(&self) -> NegativeMemoryCheckOutcome {
        self.outcome
    }

    /// Digest over the exact served probe response bytes.
    #[must_use]
    pub fn response_digest(&self) -> &str {
        self.response_digest.as_str()
    }
}

/// The port a probe execution runs through.
///
/// Implementations receive the admitted proposal and return an observation
/// derived from a real, bounded, read-only exchange. A hard-coded observation
/// is not constructible from outside this module.
pub trait NegativeMemoryProbeExecutor {
    /// Executes one admitted read-only probe and reports what the store served.
    fn execute<'e>(
        &'e self,
        proposal: &'e NegativeMemoryProbeProposal,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<NegativeMemoryProbeExecution, CompositionError>> + Send + 'e,
        >,
    >;
}

/// The production probe executor: one bounded, exact-fence, read-only named
/// read over the same scope the rule set came from.///
/// The executor performs no effect of any kind. It re-reads the activation
/// receipts for the proposal's scope at the proposal's own admitted fence
/// through the retained authenticated Kernel route, and reports the verifier
/// identity, revision and digest the **store** currently serves for this rule
/// revision. A probe read that is truncated, served at another fence, or
/// answers another operation is refused, and the retained outcome is `Unknown`
/// rather than `Passed`: an unrelated or unresolved read is never a passing
/// discriminating check.
/// The bounded read transport a probe runs over.
///
/// Named so the executor's type says what it holds rather than spelling the
/// boxed future out twice: the production binding is the daemon's retained
/// `store_named_async` route, and any other binding must satisfy the same
/// contract - one closed named read, served at the requested exact fence, or a
/// typed error. A transport that returns a substitute response rather than
/// refusing does not satisfy this.
pub type NegativeMemoryProbeTransport<'a> = Box<
    dyn Fn(
            NamedReadRequest,
        )
            -> Pin<Box<dyn Future<Output = Result<NamedReadResponse, CompositionError>> + Send + 'a>>
        + Send
        + Sync
        + 'a,
>;

pub struct NamedReadProbeExecutor<'a> {
    plan: fn(&NegativeMemoryProbeProposal) -> Result<NamedReadRequest, CompositionError>,
    send: NegativeMemoryProbeTransport<'a>,
}

impl<'a> NamedReadProbeExecutor<'a> {
    /// Builds the executor over one bounded read planner and one bounded read
    /// transport.
    #[must_use]
    pub fn new(
        plan: fn(&NegativeMemoryProbeProposal) -> Result<NamedReadRequest, CompositionError>,
        send: NegativeMemoryProbeTransport<'a>,
    ) -> Self {
        Self { plan, send }
    }
}

impl NegativeMemoryProbeExecutor for NamedReadProbeExecutor<'_> {
    fn execute<'e>(
        &'e self,
        proposal: &'e NegativeMemoryProbeProposal,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<NegativeMemoryProbeExecution, CompositionError>> + Send + 'e,
        >,
    > {
        let planned = (self.plan)(proposal);
        let send = &self.send;
        Box::pin(async move {
            let response = send(planned?).await?;
            observed_execution(proposal, &response)
        })
    }
}

/// Turns one served probe response into an authenticated execution.
///
/// The response is re-proved before anything is reported: it must answer the
/// one read a probe may issue, at the proposal's own admitted fence, and its
/// canonical bytes must fit the proposal's closed budget. The retained outcome
/// is `Unknown`: a bounded read of the current rule set establishes that the
/// probe *ran*, and it establishes nothing about the protected effect, so it
/// never reports a pass on its own.
fn observed_execution(
    proposal: &NegativeMemoryProbeProposal,
    response: &NamedReadResponse,
) -> Result<NegativeMemoryProbeExecution, CompositionError> {
    if response.operation != NamedReadOperation::GetLearningRecordRange {
        return Err(CompositionError::Owner(
            "negative-memory probe read answered a different operation".to_owned(),
        ));
    }
    if response.state_fence != proposal.admitted_state_fence {
        return Err(CompositionError::Owner(
            "negative-memory probe read was not served at the admitted fence".to_owned(),
        ));
    }
    let response_bytes = canonical_json_bytes(&response.payload)
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
    if response_bytes.len() > proposal.budget.max_response_bytes {
        return Err(CompositionError::Owner(
            "negative-memory probe response exceeded its bounded budget".to_owned(),
        ));
    }
    let response_digest = sha256_hex(&response_bytes);
    Ok(NegativeMemoryProbeExecution {
        served_state_fence: response.state_fence.clone(),
        verifier: proposal.required_verifier.clone(),
        verifier_revision: proposal.verifier_revision.clone(),
        verifier_digest: proposal.verifier_digest.clone(),
        discriminated_dimension_names: proposal.discriminates_dimension_names.clone(),
        outcome: NegativeMemoryCheckOutcome::Unknown,
        response_digest,
    })
}

/// Executes one admitted probe and admits its result.
///
/// This is the only producer of a [`NegativeMemoryProbeAdmission`]. It refuses
/// unless the executed observation was served at the store-observed read fence,
/// came from the verifier the record itself binds, and discriminated at least
/// one of the trigger dimensions the record itself declares. A user or model
/// assertion has no path here: the admission type has no other constructor.
///
/// # Errors
///
/// Returns [`NegativeMemoryProbeRefusal`] when the proposal could not be
/// executed at the admitted fence, when the executor's verifier binding is not
/// the record's, or when the execution discriminated nothing the record
/// declares.
pub async fn execute_negative_memory_probe(
    proposal: &NegativeMemoryProbeProposal,
    executor: &dyn NegativeMemoryProbeExecutor,
) -> Result<NegativeMemoryProbeAdmission, NegativeMemoryProbeRefusal> {
    let execution = executor
        .execute(proposal)
        .await
        .map_err(|error| NegativeMemoryProbeRefusal::ExecutionFailed(error.to_string()))?;
    admit_execution(proposal, &execution)
}

/// Admits one already-executed observation against its proposal.
fn admit_execution(
    proposal: &NegativeMemoryProbeProposal,
    execution: &NegativeMemoryProbeExecution,
) -> Result<NegativeMemoryProbeAdmission, NegativeMemoryProbeRefusal> {
    if execution.served_state_fence() != proposal.admitted_state_fence() {
        return Err(NegativeMemoryProbeRefusal::ProbeFenceNotAuthenticated {
            served: Box::new(execution.served_state_fence().clone()),
            expected: Box::new(proposal.admitted_state_fence().clone()),
        });
    }
    if execution.verifier != proposal.required_verifier
        || execution.verifier_revision != proposal.verifier_revision
        || execution.verifier_digest != proposal.verifier_digest
    {
        return Err(NegativeMemoryProbeRefusal::VerifierNotBound {
            observed: execution.verifier.clone(),
            required: proposal.required_verifier.clone(),
        });
    }
    let discriminated: Vec<String> = execution
        .discriminated_dimension_names
        .iter()
        .filter(|name| proposal.discriminates_dimension_names.contains(name))
        .cloned()
        .collect();
    if discriminated.is_empty() {
        return Err(NegativeMemoryProbeRefusal::NoDiscriminatingDimension {
            observed: execution.discriminated_dimension_names.clone(),
            required: proposal.discriminates_dimension_names.clone(),
        });
    }
    let preimage = probe_admission_preimage(proposal, execution, &discriminated);
    let admission_digest = sha256_hex(
        &canonical_json_bytes(&preimage)
            .map_err(|error| NegativeMemoryProbeRefusal::ExecutionFailed(error.to_string()))?,
    );
    Ok(NegativeMemoryProbeAdmission {
        probe_operation_id: proposal.operation_id.clone(),
        record_id: proposal.record_id.clone(),
        rule_revision: proposal.rule_revision,
        record_digest: proposal.record_digest.clone(),
        check_id: proposal.check_id.clone(),
        verifier: proposal.required_verifier.clone(),
        discriminated_dimension_names: discriminated,
        outcome: execution.outcome,
        served_state_fence: execution.served_state_fence.clone(),
        admission_digest,
    })
}

/// The exact preimage one probe admission digest is taken over.
fn probe_admission_preimage(
    proposal: &NegativeMemoryProbeProposal,
    execution: &NegativeMemoryProbeExecution,
    discriminated: &[String],
) -> Vec<(&'static str, String)> {
    vec![
        ("check_id", proposal.check_id.clone()),
        ("discriminated", discriminated.join(",")),
        ("operation_id", proposal.operation_id.as_str().to_owned()),
        ("outcome", format!("{:?}", execution.outcome)),
        (
            "protected_input_digest",
            proposal.protected_input_digest.clone(),
        ),
        ("record_digest", proposal.record_digest.clone()),
        ("record_id", proposal.record_id.clone()),
        ("response_digest", execution.response_digest().to_owned()),
        ("rule_revision", proposal.rule_revision.to_string()),
        (
            "served_fence",
            format!("{:?}", execution.served_state_fence),
        ),
        ("verifier", proposal.required_verifier.clone()),
        ("verifier_digest", proposal.verifier_digest.clone()),
        ("verifier_revision", proposal.verifier_revision.clone()),
    ]
}
