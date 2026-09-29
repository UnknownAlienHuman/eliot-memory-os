//! Governor-owned negative-memory gate contract (issue #1731
//! W4, I12.19, I1.8, I12.16).
//!
//! # Where this gate sits and why
//!
//! The gate lives in the **Governor**, not in Kernel. `crates/kernel/AGENTS.md`
//! states the boundary Kernel holds itself to: "Kernel validates immutable
//! identity, principal, epoch/fence, ordering, transition/effect class… It does
//! not reinterpret policy, `WorkScope`, task, plan, verifier or finish." The
//! matcher ([`match_negative_memory`]) is a Smart *semantic* owner, and I1.8's
//! canonical write path is:
//!
//! ```text
//! agent/module/tool observation
//! → eliotd semantic admission and PreparedTransition
//! → Kernel mechanical authority/fence/idempotency/order validation
//! → ORS staging and Ordering Scope reservation
//! → named store transaction commits …
//! ```
//!
//! This gate is the `eliotd`/Governor semantic-admission step, immediately
//! **before** the `PreparedTransition` is handed to Kernel. It therefore runs
//! strictly before `store_apply_operation` and its `gateway.apply(...)`, in the
//! layer that is allowed to interpret policy — never inside Kernel and never
//! inside the store bridge.
//!
//! [`evaluate_negative_memory_gate`] is invoked by the explicit
//! [`GovernorComposition::commit_canonical_gated_by_negative_memory`](crate::composition::GovernorComposition::commit_canonical_gated_by_negative_memory)
//! wrapper. The ordinary [`GovernorComposition::commit_canonical`](crate::composition::GovernorComposition::commit_canonical)
//! method remains ungated, and source tracing found no production caller of
//! the gated wrapper. This owner-side contract therefore does not claim that a
//! current external effect contour is wired to it. The WASM request loop
//! (#2568), native worker (#1911), and Doctor repair execution have separate
//! dispatch owners and require their own explicit integration.
//!
//! # What the gate does, in order
//!
//! 1. **Validate the resolved rule snapshot's own integrity.** Every rule the
//!    caller resolved runs [`NegativeMemoryFingerprint::validate`] — the
//!    *original* recorded value's own validator, which re-derives the recorded
//!    `record_digest` over the recorded fields. Recomputing a digest over
//!    something else is never accepted, and a record that fails validation
//!    becomes an explicit undecidable reason, never a no-match.
//! 2. **Run the bounded pure matcher** [`match_negative_memory`] over that
//!    snapshot. The function is pure: no I/O, no clock, no model call.
//! 3. **Revalidate the rule-set revision at dispatch** against the caller's
//!    independent second observation, so an intervening invalidation between
//!    the lookup and the dispatch can neither leave a stale block in place nor
//!    become a bypass (see "Staleness" below).
//! 4. **Return a typed disposition** derived from the matcher's own outcome
//!    *and* an owner-admitted action policy bound to that exact record revision
//!    and content digest. The matcher's `NegativeMemoryMatchKind` alone grants
//!    nothing: a match becomes a block only when an owner-admitted
//!    [`NegativeMemoryActionPolicy`] agrees.
//!
//! [`NegativeMemoryGateInput::read`] carries the expected closed named-read
//! snapshot (`GetLearningRecordRange` filtered to activation receipts), with
//! its exact `StateFence`. The current source has no production resolver for
//! this input: the effect owner must provide the real named-read result and
//! bind it to the same canonical request before invoking the gated wrapper.
//!
//! # The four dispositions (I12.19: exact blocks, similarity only warns)
//!
//! * [`NegativeMemoryGateDisposition::Block`] — an exact admitted match whose
//!   admitted disposition is `Block`. The action is refused.
//! * [`NegativeMemoryGateDisposition::RequireCheck`] — an exact admitted match
//!   whose admitted disposition is `RequireCheck`. The action is refused and
//!   the decision names the **safe discriminating check** recorded on the
//!   matched rule.
//! * [`NegativeMemoryGateDisposition::Proceed`] with a
//!   [`NegativeMemoryProceedWarning`] — a **near** match, or an advisory
//!   disposition. The action proceeds to ordinary authorization. It is a
//!   warning, not permission: the caller's own authorization is unchanged and
//!   nothing here widens it.
//! * [`NegativeMemoryGateDisposition::Unavailable`] — the lookup was incomplete, a
//!   rule was unvalidatable, a required policy was absent, or the revision
//!   moved. This follows the explicit unavailable/incomplete rule: it is
//!   **neither** a fabricated exact match **nor** a fabricated no-match, and it
//!   refuses the effect until the snapshot is resolvable.
//!
//! A complete enumeration with no applicable rule is
//! [`NegativeMemoryGateDisposition::Proceed`] with no warning, and that is the only
//! way absence is certified — the matcher's
//!   [`NegativeMemoryMatchKind::certifies_rule_absence`] is the sole source of
//!   that fact and the gate re-uses it rather than re-deriving "no rule".
//!
//! # Staleness and bypass (I12.16 Fence A / Fence B)
//!
//! [`NegativeMemoryCandidateRead::rule_set_revision`] is the Fence A reading the
//! caller captured before comparing. The gate requires the caller's dispatch
//! revalidation [`NegativeMemoryGateInput::revalidated_rule_set_revision`] to
//! equal it. If they differ, the rule set churned between lookup and dispatch
//! and the gate returns [`NegativeMemoryGateDisposition::Unavailable`] with
//! [`NegativeMemoryGateRefusal::RuleSetRevisionMoved`]: it does not dispatch on
//! the stale snapshot (which would leave a stale block in force) and it does not
//! dispatch on the fresh one without re-comparing (which would be a bypass).
//! An absent revalidation is refused as
//! [`NegativeMemoryGateRefusal::RuleSetRevisionAbsent`], so "I did not look
//! again" can never be read as "nothing changed".
//!
//! The gate requires exact equality among the candidate read's `StateFence`,
//! the gate input fence and the canonical envelope's request fence. A previous
//! generation's snapshot therefore cannot be reused as current.
//!
//! # Absence of a policy is not permission and not a block
//!
//! An exact match with **no** owner-admitted action policy bound to that exact
//! record revision and digest yields
//! [`NegativeMemoryGateDisposition::Unavailable`] with
//! [`NegativeMemoryGateRefusal::AdmittedPolicyAbsent`]. A record's existence,
//! and a record's digest matching, grant nothing — that is the explicit boundary
//! in `NegativeMemoryActionPolicy`'s own documentation, and this gate is where it
//! is enforced.

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_dreamer_failure::{
    NegativeMemoryActionPolicy, NegativeMemoryCandidateRead, NegativeMemoryDisposition,
    NegativeMemoryFingerprint, NegativeMemoryHorizonDomain, NegativeMemoryMatchBound,
    NegativeMemoryMatchResult, NegativeMemoryOutcome, NegativeMemoryRecordDefect,
    NegativeMemorySubject, match_negative_memory, negative_memory_record_defect,
};
use eliot_store_api::StateFence;

use crate::composition::CompositionError;
use crate::negative_memory_probe::{
    NegativeMemoryProbeProposal, admit_negative_memory_probe,
};

/// A near-match or advisory warning that accompanies a proceed.
///
/// It carries the exact record identity, its rule revision and the fields that
/// differed, so the warning is never a bare "something matched" and can never be
/// presented as governing authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryProceedWarning {
    /// Immutable record identity of the near-matched or advisory rule.
    pub record_id: String,
    /// The exact rule revision of that record.
    pub rule_revision: u64,
    /// Exact compared field names whose two sides are known and different.
    pub differing_field_names: Vec<String>,
    /// True when the compared rule set was not a complete bounded enumeration.
    pub enumeration_incomplete: bool,
}

/// Why the gate could not decide, or refused.
///
/// Every cause keeps its own variant. No variant may be read as a `NoMatch`,
/// and none is a fabricated exact match.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeMemoryGateRefusal {
    /// A delivered record failed its own `validate()`. The enumeration is
    /// therefore incomplete and absence cannot be certified.
    RuleRecordUnvalidatable {
        /// The record identity.
        record_id: String,
        /// Its rule revision.
        rule_revision: u64,
        /// Closed defect class produced by the record's own validator.
        defect: NegativeMemoryRecordDefect,
    },
    /// An exact match had no owner-admitted action policy bound to that exact
    /// record revision and content digest.
    AdmittedPolicyAbsent {
        /// The exactly matched record identity.
        record_id: String,
        /// The exactly matched rule revision.
        rule_revision: u64,
    },
    /// The admitted policy value failed its own validation, or does not bind
    /// the matched record.
    AdmittedPolicyInvalid {
        /// The record identity the policy was bound to.
        record_id: String,
        /// Exact detail.
        detail: String,
    },
    /// The rule-set revision moved between the lookup read and the dispatch
    /// revalidation, so the snapshot the comparison used is not current.
    RuleSetRevisionMoved {
        /// Revision observed before comparing.
        observed: u64,
        /// Revision observed at dispatch revalidation.
        revalidated: u64,
    },
    /// The caller supplied no dispatch-time rule-set revision, so nothing could
    /// be revalidated and staleness cannot be excluded.
    RuleSetRevisionAbsent,
    /// The matcher or one of its inputs failed validation.
    MatchNotDecidable {
        /// Exact detail.
        detail: String,
    },
    /// The bounded enumeration was incomplete, so the absence of an applicable
    /// rule is not certified and a fabricated no-match is refused.
    EnumerationIncomplete {
        /// Exact detail.
        detail: String,
    },
    /// The supplied subject, candidate snapshot or dispatch request is not
    /// bound to the exact canonical request that would be committed.
    RequestBindingMismatch {
        /// Exact failed binding field or calculation.
        detail: String,
    },
}

/// The typed disposition produced by matching and policy admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeMemoryGateDisposition {
    /// The exact matched action is blocked. The effect must not proceed.
    Block {
        /// Immutable record identity of the blocking rule.
        record_id: String,
        /// The exact rule revision that is in force.
        rule_revision: u64,
        /// The admitted policy identity.
        policy_id: String,
        /// The rule-set revision that was revalidated at dispatch.
        rule_set_revision: u64,
    },
    /// The exact matched action may not proceed until the named admitted
    /// discriminating check has produced its result.
    RequireCheck {
        /// Immutable record identity of the blocking rule.
        record_id: String,
        /// The exact rule revision that is in force.
        rule_revision: u64,
        /// The admitted policy identity.
        policy_id: String,
        /// The **safe discriminating check** the matched rule declares.
        check_id: String,
        /// The owner-issued verifier that must produce the check result.
        required_verifier: String,
        /// The recorded trigger dimensions this check discriminates.
        discriminates_dimension_names: Vec<String>,
        /// Governor-admitted, typed read-only proposal for the exact named
        /// check. It preserves the protected action identities and carries
        /// its own effect ceiling, budget and verifier binding.
        probe: NegativeMemoryProbeProposal,
        /// The rule-set revision that was revalidated at dispatch.
        rule_set_revision: u64,
    },
    /// The action proceeds to ordinary authorization. The optional warning is
    /// advisory only and confers nothing.
    Proceed {
        /// A near-match or advisory warning, when one applies.
        warning: Option<NegativeMemoryProceedWarning>,
    },
    /// The lookup could not be decided. The effect must not proceed on a
    /// fabricated match or a fabricated absence.
    Unavailable {
        /// The exact reason the gate could not decide.
        refusal: NegativeMemoryGateRefusal,
    },
}

/// Exact request/action/snapshot identity carried with every gate outcome.
///
/// Fields are private so callers cannot manufacture a transferable `Proceed`.
/// The Governor creates this binding from the same subject, named read and
/// canonical envelope that it evaluates, then compares it again immediately
/// before dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryGateBinding {
    operation_id: String,
    canonical_request_digest: String,
    action_id: String,
    action_operation_id: String,
    action_effect_id: String,
    action_input_digest: String,
    subject_digest: String,
    scope_id: String,
    task_id: String,
    read_handle: String,
    read_rule_set_revision: String,
    read_rule_set_digest: String,
    state_fence: StateFence,
}

impl NegativeMemoryGateBinding {
    fn capture(input: &NegativeMemoryGateInput<'_>, envelope: &CanonicalWriteEnvelope) -> Self {
        Self {
            operation_id: envelope.operation_id.as_str().to_owned(),
            canonical_request_digest: envelope.canonical_request_hash().unwrap_or_default(),
            action_id: input.subject.action.action_id.clone(),
            action_operation_id: input.subject.action.operation_id.clone(),
            action_effect_id: input.subject.action.effect_id.clone(),
            action_input_digest: input.subject.action.input_digest.clone(),
            subject_digest: input.subject.computed_digest().unwrap_or_default(),
            scope_id: envelope.scope_id.as_str().to_owned(),
            task_id: input.subject.applicability.task_id.clone(),
            read_handle: input.read.read_handle.clone(),
            read_rule_set_revision: input.read.rule_set_revision.clone(),
            read_rule_set_digest: input.read.rule_set_digest.clone(),
            state_fence: envelope.request.state_fence.clone(),
        }
    }

    /// Canonical operation identity this decision protects.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Digest of the exact canonical request envelope this decision protects.
    #[must_use]
    pub fn canonical_request_digest(&self) -> &str {
        &self.canonical_request_digest
    }

    /// Stable action identity bound by the compared subject.
    #[must_use]
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Operation identity declared by the compared action subject.
    #[must_use]
    pub fn action_operation_id(&self) -> &str {
        &self.action_operation_id
    }

    /// Effect identity bound by the compared subject.
    #[must_use]
    pub fn action_effect_id(&self) -> &str {
        &self.action_effect_id
    }

    /// Input digest bound by the compared action.
    #[must_use]
    pub fn action_input_digest(&self) -> &str {
        &self.action_input_digest
    }

    /// Digest of the exact typed action subject that was compared.
    #[must_use]
    pub fn subject_digest(&self) -> &str {
        &self.subject_digest
    }

    /// Scope identity that was both compared and dispatched.
    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    /// Task identity that was both compared and dispatched.
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// Named read handle and rule snapshot revision used by the comparison.
    #[must_use]
    pub fn read_handle(&self) -> &str {
        &self.read_handle
    }

    /// Revision head observed by the bounded candidate read.
    #[must_use]
    pub fn read_rule_set_revision(&self) -> &str {
        &self.read_rule_set_revision
    }

    /// Digest over the exact pages delivered by the bounded candidate read.
    #[must_use]
    pub fn read_rule_set_digest(&self) -> &str {
        &self.read_rule_set_digest
    }

    /// Exact StateFence bound to the read and canonical request.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    fn validate_for_dispatch(
        &self,
        input: &NegativeMemoryGateInput<'_>,
        envelope: &CanonicalWriteEnvelope,
    ) -> Result<(), NegativeMemoryGateRefusal> {
        validate_request_binding(input, envelope)?;
        if self != &Self::capture(input, envelope) {
            return Err(NegativeMemoryGateRefusal::RequestBindingMismatch {
                detail: "gate decision binding changed after comparison".to_owned(),
            });
        }
        Ok(())
    }

}

/// A gate result bound to the exact request, action, scope, read and fence.
///
/// The disposition is private and cannot be separated from its binding. Every
/// successful result, including an unadorned no-match `Proceed`, carries the
/// same non-transferable evidence through the canonical write call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryGateDecision {
    disposition: NegativeMemoryGateDisposition,
    binding: NegativeMemoryGateBinding,
}

impl NegativeMemoryGateDecision {
    /// The typed outcome of the bounded matcher and policy admission.
    #[must_use]
    pub const fn disposition(&self) -> &NegativeMemoryGateDisposition {
        &self.disposition
    }

    /// Exact request, action, snapshot and fence binding for this outcome.
    #[must_use]
    pub const fn binding(&self) -> &NegativeMemoryGateBinding {
        &self.binding
    }

    pub(crate) fn validate_for_dispatch(
        &self,
        input: &NegativeMemoryGateInput<'_>,
        envelope: &CanonicalWriteEnvelope,
    ) -> Result<(), NegativeMemoryGateRefusal> {
        self.binding.validate_for_dispatch(input, envelope)
    }

    /// Whether this decision refuses the effect before it reaches the store.
    ///
    /// A near-match warning does **not** refuse: it proceeds to ordinary
    /// authorization, which is a separate and unchanged check.
    #[must_use]
    pub const fn refuses_effect(&self) -> bool {
        matches!(
            &self.disposition,
            NegativeMemoryGateDisposition::Block { .. }
                | NegativeMemoryGateDisposition::RequireCheck { .. }
                | NegativeMemoryGateDisposition::Unavailable { .. }
        )
    }
}

/// Everything one gate evaluation needs.
///
/// Every field is either owner-supplied or owner-resolved through the existing
/// named read. Nothing is inferred from a display name, a similarity score, or
/// the presence of a Context packet.
#[derive(Clone, Debug)]
pub struct NegativeMemoryGateInput<'a> {
    /// The pending action to compare, in owner-issued identities only.
    pub subject: &'a NegativeMemorySubject,
    /// The caller's explicit clock/revision reading of the horizon's domain.
    pub observed_horizon: &'a NegativeMemoryHorizonDomain,
    /// The named bound the enumeration runs under.
    pub bound: &'a NegativeMemoryMatchBound,
    /// The current applicable rule snapshot, resolved through bounded named
    /// reads. Its `rule_set_revision` is the I12.16 Fence A reading.
    pub read: &'a NegativeMemoryCandidateRead,
    /// The rule-set revision the caller re-read at dispatch (I12.16 Fence B).
    ///
    /// This is the anti-staleness input: it must equal
    /// [`NegativeMemoryCandidateRead::rule_set_revision`], or the gate refuses
    /// rather than dispatching on a stale or unverified snapshot.
    pub revalidated_rule_set_revision: Option<u64>,
    /// The owner-admitted action policies, one per live rule revision.
    ///
    /// A policy's presence is the only thing that can turn a match into a
    /// disposition; it is not itself sufficient and is validated against the
    /// matched record before use.
    pub admitted_policies: &'a [NegativeMemoryActionPolicy],
    /// The request's own State Fence the snapshot was read at.
    pub state_fence: &'a StateFence,
}

fn refused(refusal: NegativeMemoryGateRefusal) -> NegativeMemoryGateDisposition {
    NegativeMemoryGateDisposition::Unavailable { refusal }
}

/// Evaluates the negative-memory gate for one pending action and returns the
/// typed disposition the admission path must apply.
///
/// This is a **total, pure** function: it performs no I/O, opens no store, reads
/// no clock and makes no model call, and it always returns a
/// [`NegativeMemoryGateDecision`] — never an error. The rule snapshot and its
/// dispatch revalidation are supplied by the caller through the existing named
/// read. The caller must not dispatch when
/// [`NegativeMemoryGateDecision::refuses_effect`] is true.
///
/// The order of the checks is the order of the guarantees:
///
/// 1. the dispatch revalidation is compared against the snapshot's Fence A
///    revision, so neither a stale block nor an unverified bypass survives;
/// 2. every rule in the snapshot is validated with its **own** validator, and
///    one failure makes the whole lookup undecidable rather than a narrower
///    match;
/// 3. the bounded matcher runs;
/// 4. the matcher's outcome is joined with an owner-admitted policy, which is
///    validated against the matched record before it is trusted.
pub fn evaluate_negative_memory_gate(
    input: &NegativeMemoryGateInput<'_>,
    envelope: &CanonicalWriteEnvelope,
) -> NegativeMemoryGateDecision {
    let binding = NegativeMemoryGateBinding::capture(input, envelope);
    let disposition = match validate_request_binding(input, envelope) {
        Ok(()) => evaluate_negative_memory_disposition(input),
        Err(refusal) => refused(refusal),
    };
    NegativeMemoryGateDecision {
        disposition,
        binding,
    }
}

fn evaluate_negative_memory_disposition(
    input: &NegativeMemoryGateInput<'_>,
) -> NegativeMemoryGateDisposition {
    if let Some(decision) = revalidate_rule_set_revision(input) {
        return decision;
    }
    if let Some(decision) = validate_every_rule(input.read) {
        return decision;
    }
    let matched = match_negative_memory(
        input.subject,
        input.observed_horizon,
        input.read,
        input.bound,
    );
    let result = match matched {
        Ok(result) => result,
        Err(violation) => {
            return refused(NegativeMemoryGateRefusal::MatchNotDecidable {
                detail: violation.to_string(),
            });
        }
    };
    decide(input, &result)
}

fn validate_request_binding(
    input: &NegativeMemoryGateInput<'_>,
    envelope: &CanonicalWriteEnvelope,
) -> Result<(), NegativeMemoryGateRefusal> {
    let canonical_request_digest = envelope
        .canonical_request_hash()
        .map_err(|error| NegativeMemoryGateRefusal::RequestBindingMismatch {
            detail: format!("canonical request digest could not be computed: {error}"),
        })?;
    if input.subject.action.operation_id != envelope.operation_id.as_str() {
        return Err(NegativeMemoryGateRefusal::RequestBindingMismatch {
            detail: "pending action operation_id differs from the canonical envelope".to_owned(),
        });
    }
    if input.subject.canonical_request_digest != canonical_request_digest {
        return Err(NegativeMemoryGateRefusal::RequestBindingMismatch {
            detail: "pending action subject is not bound to the canonical request digest".to_owned(),
        });
    }
    if input.subject.applicability.scope_id != envelope.scope_id.as_str() {
        return Err(NegativeMemoryGateRefusal::RequestBindingMismatch {
            detail: "pending action scope differs from the canonical envelope scope".to_owned(),
        });
    }
    let request_task = envelope
        .task_id
        .as_deref()
        .or_else(|| envelope.request.task_id.as_ref().map(|task| task.as_str()));
    if request_task != Some(input.subject.applicability.task_id.as_str()) {
        return Err(NegativeMemoryGateRefusal::RequestBindingMismatch {
            detail: "pending action task differs from or is absent in the canonical request".to_owned(),
        });
    }
    if input.subject.action.target_id != input.subject.applicability.target_id {
        return Err(NegativeMemoryGateRefusal::RequestBindingMismatch {
            detail: "pending action and applicability target identities differ".to_owned(),
        });
    }
    if input.subject.action.effect_class != envelope.requested_effect_ceiling
        || input.subject.applicability.effect_class != envelope.requested_effect_ceiling
    {
        return Err(NegativeMemoryGateRefusal::RequestBindingMismatch {
            detail: "pending action effect class differs from the canonical request effect ceiling"
                .to_owned(),
        });
    }
    if input.state_fence != &envelope.request.state_fence
        || input.read.state_fence != envelope.request.state_fence
    {
        return Err(NegativeMemoryGateRefusal::RequestBindingMismatch {
            detail: "candidate snapshot, gate request, and canonical envelope do not share the exact StateFence"
                .to_owned(),
        });
    }
    Ok(())
}

/// Returns a refusal when the dispatch-time revalidation does not equal the
/// snapshot's own Fence A revision, and `None` when it does.
///
/// Both values are owner-observed revisions of the *same* rule scope. An absent
/// revalidation is refused, so a caller that never looked again cannot be read
/// as a caller that observed no change.
fn revalidate_rule_set_revision(
    input: &NegativeMemoryGateInput<'_>,
) -> Option<NegativeMemoryGateDisposition> {
    let Some(revalidated) = input.revalidated_rule_set_revision else {
        return Some(refused(NegativeMemoryGateRefusal::RuleSetRevisionAbsent));
    };
    let observed: u64 = match input.read.rule_set_revision.parse() {
        Ok(observed) => observed,
        Err(_) => {
            return Some(refused(NegativeMemoryGateRefusal::MatchNotDecidable {
                detail: format!(
                    "rule snapshot carries a non-numeric rule-set revision {:?}",
                    input.read.rule_set_revision
                ),
            }));
        }
    };
    if observed != revalidated {
        return Some(refused(NegativeMemoryGateRefusal::RuleSetRevisionMoved {
            observed,
            revalidated,
        }));
    }
    None
}

/// Returns a refusal when any delivered rule fails its own validator, and
/// `None` when every rule validates.
///
/// This is the integrity check that must not be replaced: it calls
/// [`NegativeMemoryFingerprint::validate`], which re-derives the recorded
/// `record_digest` from the recorded fields and verifies the causal ceiling and
/// evidence coverage. One unvalidatable record makes the whole enumeration
/// undecidable, so the lookup can never certify absence.
fn validate_every_rule(read: &NegativeMemoryCandidateRead) -> Option<NegativeMemoryGateDisposition> {
    for page in &read.delivered_pages {
        for rule in &page.rules {
            if let Err(violation) = rule.validate() {
                return Some(refused(
                    NegativeMemoryGateRefusal::RuleRecordUnvalidatable {
                        record_id: rule.record_id.clone(),
                        rule_revision: rule.rule_revision,
                        defect: negative_memory_record_defect(&violation),
                    },
                ));
            }
        }
    }
    None
}

/// Joins the matcher's outcome with the owner-admitted policy.
fn decide(
    input: &NegativeMemoryGateInput<'_>,
    result: &NegativeMemoryMatchResult,
) -> NegativeMemoryGateDisposition {
    let rule_set_revision = input.revalidated_rule_set_revision.unwrap_or_default();
    let kind = result.outcome.kind();
    if !kind.certifies_rule_absence()
        && matches!(
            result.enumeration,
            eliot_dreamer_failure::EnumerationCoverage::Incomplete { .. }
        )
    {
        return refused(NegativeMemoryGateRefusal::EnumerationIncomplete {
            detail: "bounded rule enumeration did not cover the queried rule scope".to_owned(),
        });
    }
    match &result.outcome {
        NegativeMemoryOutcome::Incomplete { observed } => {
            refused(NegativeMemoryGateRefusal::EnumerationIncomplete {
                detail: format!(
                    "matcher could not decide: {} undecidable record(s), {} reason(s)",
                    observed.undecidable_record_count,
                    observed.reasons.len()
                ),
            })
        }
        NegativeMemoryOutcome::NoMatch { .. } => {
            NegativeMemoryGateDisposition::Proceed { warning: None }
        }
        NegativeMemoryOutcome::Near { matched } => NegativeMemoryGateDisposition::Proceed {
            warning: Some(NegativeMemoryProceedWarning {
                record_id: matched.record_id.clone(),
                rule_revision: matched.rule_revision,
                differing_field_names: matched.differing_field_names.clone(),
                enumeration_incomplete: false,
            }),
        },
        NegativeMemoryOutcome::Exact { matched } => decide_exact(input, matched, rule_set_revision),
    }
}

/// Decides the effect of one exact admitted match.
///
/// The match identifies *which* rule matched; it grants nothing by itself. This
/// requires an owner-admitted [`NegativeMemoryActionPolicy`] bound to that exact
/// record identity, rule revision and content digest, validated with its own
/// `validate()` and `validate_binding()`, and then applies that policy's
/// disposition. `Advisory` is a warning and proceeds; `Block` and `RequireCheck`
/// refuse.
fn decide_exact(
    input: &NegativeMemoryGateInput<'_>,
    matched: &eliot_dreamer_failure::ExactMatch,
    rule_set_revision: u64,
) -> NegativeMemoryGateDisposition {
    let Some(record) = find_matched_record(input, matched) else {
        return refused(NegativeMemoryGateRefusal::MatchNotDecidable {
            detail: format!(
                "matcher reported exact match {}:{} but the validated snapshot retains no such rule",
                matched.record_id, matched.rule_revision
            ),
        });
    };
    let Some(policy) = input.admitted_policies.iter().find(|policy| {
        policy.binding.record_id == record.record_id
            && policy.binding.rule_revision == record.rule_revision
            && policy.binding.record_digest == record.record_digest
    }) else {
        return refused(NegativeMemoryGateRefusal::AdmittedPolicyAbsent {
            record_id: record.record_id.clone(),
            rule_revision: record.rule_revision,
        });
    };
    if let Err(violation) = policy.validate() {
        return refused(NegativeMemoryGateRefusal::AdmittedPolicyInvalid {
            record_id: record.record_id.clone(),
            detail: violation.to_string(),
        });
    }
    if let Err(violation) = policy.validate_binding(record) {
        return refused(NegativeMemoryGateRefusal::AdmittedPolicyInvalid {
            record_id: record.record_id.clone(),
            detail: violation.to_string(),
        });
    }
    match policy.disposition {
        NegativeMemoryDisposition::Block => NegativeMemoryGateDisposition::Block {
            record_id: record.record_id.clone(),
            rule_revision: record.rule_revision,
            policy_id: policy.policy_id.clone(),
            rule_set_revision,
        },
        NegativeMemoryDisposition::RequireCheck => NegativeMemoryGateDisposition::RequireCheck {
            record_id: record.record_id.clone(),
            rule_revision: record.rule_revision,
            policy_id: policy.policy_id.clone(),
            check_id: record.discriminating_check.check_id.clone(),
            required_verifier: record.discriminating_check.required_verifier.clone(),
            discriminates_dimension_names: record
                .discriminating_check
                .discriminates_dimension_names
                .clone(),
            probe: match admit_negative_memory_probe(
                record,
                policy,
                input.subject,
                input.read,
                input.state_fence,
            ) {
                Ok(probe) => probe,
                Err(refusal) => {
                    return refused(NegativeMemoryGateRefusal::MatchNotDecidable {
                        detail: format!("safe check proposal admission failed: {refusal:?}"),
                    });
                }
            },
            rule_set_revision,
        },
        // An advisory policy on an exact match is a warning, never a block: the
        // policy owner explicitly declined blocking power.
        NegativeMemoryDisposition::Advisory => NegativeMemoryGateDisposition::Proceed {
            warning: Some(NegativeMemoryProceedWarning {
                record_id: record.record_id.clone(),
                rule_revision: record.rule_revision,
                differing_field_names: Vec::new(),
                enumeration_incomplete: false,
            }),
        },
    }
}

/// Recovers the exact matched record from the validated snapshot.
///
/// The matcher reports the matched record's identity, revision and content
/// digest; this looks up the record itself in the snapshot it just compared, so
/// the disposition is decided against the record's own recorded discriminating
/// check rather than against anything the caller supplied alongside the match.
fn find_matched_record<'r>(
    input: &'r NegativeMemoryGateInput<'_>,
    matched: &eliot_dreamer_failure::ExactMatch,
) -> Option<&'r NegativeMemoryFingerprint> {
    for page in &input.read.delivered_pages {
        for rule in &page.rules {
            if rule.record_id == matched.record_id
                && rule.rule_revision == matched.rule_revision
                && rule.record_digest == matched.record_digest
            {
                return Some(rule);
            }
        }
    }
    None
}

/// Converts a refusing decision into the fail-closed composition error the
/// admission path returns, preserving the exact refusal and the exact rule or
/// check identity.
///
/// The gate is total and has no error type of its own at this boundary; this is
/// the single place a refusal becomes a `CompositionError`, so no call site can
/// silently discard it. `Proceed` yields `None`.
pub(crate) fn refusal_as_composition_error(
    decision: &NegativeMemoryGateDecision,
) -> Option<CompositionError> {
    match decision.disposition() {
        NegativeMemoryGateDisposition::Unavailable { refusal } => Some(CompositionError::Recovery(
            format!("negative-memory gate refused the effect: {refusal:?}"),
        )),
        NegativeMemoryGateDisposition::Block {
            record_id,
            rule_revision,
            policy_id,
            ..
        } => Some(CompositionError::Recovery(format!(
            "negative-memory gate blocked the effect: rule {record_id} revision {rule_revision} under admitted policy {policy_id}"
        ))),
        NegativeMemoryGateDisposition::RequireCheck {
            record_id,
            rule_revision,
            check_id,
            ..
        } => Some(CompositionError::Recovery(format!(
            "negative-memory gate requires the admitted discriminating check {check_id} for rule {record_id} revision {rule_revision}"
        ))),
        NegativeMemoryGateDisposition::Proceed { .. } => None,
    }
}
