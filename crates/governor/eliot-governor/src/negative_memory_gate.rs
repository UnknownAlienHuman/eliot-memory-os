//! Governor-owned negative-memory gate on the real effect path (issue #1731
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
//! [`evaluate_negative_memory_gate`] is invoked by
//! [`GovernorComposition::commit_canonical_gated_by_negative_memory`](crate::composition::GovernorComposition::commit_canonical_gated_by_negative_memory),
//! the explicit gated wrapper whose gate input is a required parameter, so a
//! caller that has not resolved an owner-observed rule set cannot reach the
//! canonical dispatch through it at all.
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
//! The rule snapshot is resolved by [`crate::negative_memory_read`], which
//! plans and resolves the existing closed named read
//! ([`eliot_store_api::learning_record_read_request`] on
//! [`NamedReadOperation::GetLearningRecordRange`] filtered to
//! [`LearningRecordKind::ActivationReceipt`] at the request's exact fence) and
//! returns a [`ResolvedNegativeMemoryRuleSet`] whose fields are private. No
//! new database, no new named operation and no catalogue change are involved.
//!
//! # The read fence is authenticated, not merely equal
//!
//! The rule read is issued `ExactFence` at the fence the request is admitted
//! at, and the store echoes the fence it served. The resolver copies that
//! **store-observed** fence into the rule set, and this gate compares it
//! against [`NegativeMemoryGateInput::state_fence`] — the pending canonical
//! request's own fence. A caller cannot choose the read fence: the store either
//! serves at the live fence or refuses, and a response answering a different
//! fence is refused before a rule set exists. A mismatch is
//! [`NegativeMemoryGateRefusal::ReadFenceNotAuthenticated`], which is neither a
//! stale-block dispatch nor a bypass.
//!
//! # The four dispositions (I12.19: exact blocks, similarity only warns)
//!
//! * [`NegativeMemoryGateDecision::Block`] — an exact admitted match whose
//!   admitted disposition is `Block`. The action is refused.
//! * [`NegativeMemoryGateDecision::RequireCheck`] — an exact admitted match
//!   whose admitted disposition is `RequireCheck`. The action is refused and
//!   the decision names the **safe discriminating check** recorded on the
//!   matched rule.
//! * [`NegativeMemoryGateDecision::Proceed`] with a
//!   [`NegativeMemoryProceedWarning`] — a **near** match, or an advisory
//!   disposition. The action proceeds to ordinary authorization. It is a
//!   warning, not permission: the caller's own authorization is unchanged and
//!   nothing here widens it.
//! * [`NegativeMemoryGateDecision::Unavailable`] — the lookup was incomplete, a
//!   rule was unvalidatable, a required policy was absent, or the revision
//!   moved. This follows the explicit unavailable/incomplete rule: it is
//!   **neither** a fabricated exact match **nor** a fabricated no-match, and it
//!   refuses the effect until the snapshot is resolvable.
//!
//! A complete enumeration with no applicable rule is
//! [`NegativeMemoryGateDecision::Proceed`] with no warning, and that is the only
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
//! and the gate returns [`NegativeMemoryGateDecision::Unavailable`] with
//! [`NegativeMemoryGateRefusal::RuleSetRevisionMoved`]: it does not dispatch on
//! the stale snapshot (which would leave a stale block in force) and it does not
//! dispatch on the fresh one without re-comparing (which would be a bypass).
//! An absent revalidation is refused as
//! [`NegativeMemoryGateRefusal::RuleSetRevisionAbsent`], so "I did not look
//! again" can never be read as "nothing changed".
//!
//! The `StateFence` is bound by the read itself: the named read is issued
//! `ExactFence` at the request's own fence, the store's echoed fence is carried
//! on the resolved rule set, and the gate compares the two rather than trusting
//! a caller-presented read fence.
//!
//! # Absence of a policy is not permission and not a block
//!
//! An exact match with **no** owner-admitted action policy bound to that exact
//! record revision and digest yields
//! [`NegativeMemoryGateDecision::Unavailable`] with
//! [`NegativeMemoryGateRefusal::AdmittedPolicyAbsent`]. A record's existence,
//! and a record's digest matching, grant nothing — that is the explicit boundary
//! in `NegativeMemoryActionPolicy`'s own documentation, and this gate is where it
//! is enforced.

use eliot_dreamer_failure::{
    NegativeMemoryCandidateRead, NegativeMemoryDisposition, NegativeMemoryFingerprint,
    NegativeMemoryHorizonDomain, NegativeMemoryMatchBound, NegativeMemoryMatchResult,
    NegativeMemoryOutcome, NegativeMemoryRecordDefect, NegativeMemorySubject,
    match_negative_memory, negative_memory_record_defect,
};
use eliot_store_api::StateFence;

use crate::composition::CompositionError;
use crate::negative_memory_read::ResolvedNegativeMemoryRuleSet;

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
    /// The fence the store observed while serving the rule read is not the fence
    /// this request is admitted at.
    ///
    /// This is the authenticated read-fence refusal. The read fence is not a
    /// caller assertion that happens to match: it is what the store echoed for
    /// the exact-fence read, and it is compared here against the canonical
    /// request's own State Fence. A snapshot read at another generation can
    /// neither be dispatched on nor be presented as current.
    ReadFenceNotAuthenticated {
        /// The fence the store reported for the rule read.
        read: Box<StateFence>,
        /// The fence this request is admitted at.
        request: Box<StateFence>,
    },
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
}

/// The typed disposition the gate returns to the admission path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeMemoryGateDecision {
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

impl NegativeMemoryGateDecision {
    /// Whether this decision refuses the effect before it reaches the store.
    ///
    /// A near-match warning does **not** refuse: it proceeds to ordinary
    /// authorization, which is a separate and unchanged check.
    #[must_use]
    pub const fn refuses_effect(&self) -> bool {
        matches!(
            self,
            Self::Block { .. } | Self::RequireCheck { .. } | Self::Unavailable { .. }
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
    /// The current applicable rule set, resolved through one bounded exact-fence
    /// named read.
    ///
    /// Its private fields are filled only by
    /// [`resolve_negative_memory_rule_read`](crate::negative_memory_read::resolve_negative_memory_rule_read),
    /// so the rules, the admitted policies and the read fence all come from the
    /// same owner-observed read. `rule_set_revision()` is the I12.16 Fence A
    /// reading and `store_observed_fence()` is the fence the **store** echoed.
    pub resolved: &'a ResolvedNegativeMemoryRuleSet,
    /// The rule-set revision the caller re-read at dispatch (I12.16 Fence B).
    ///
    /// This is the anti-staleness input: it must equal
    /// [`ResolvedNegativeMemoryRuleSet::rule_set_revision`], or the gate
    /// refuses rather than dispatching on a stale or unverified snapshot.
    pub revalidated_rule_set_revision: Option<u64>,
    /// The State Fence the pending canonical request is admitted at.
    ///
    /// This is **this operation's own** fence, and it is compared against
    /// [`ResolvedNegativeMemoryRuleSet::store_observed_fence`]. The comparison
    /// is therefore between an owner-observed read fence and the content of the
    /// request being admitted, not between two values the caller supplied
    /// together.
    pub state_fence: &'a StateFence,
}

fn refused(refusal: NegativeMemoryGateRefusal) -> NegativeMemoryGateDecision {
    NegativeMemoryGateDecision::Unavailable { refusal }
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
) -> NegativeMemoryGateDecision {
    if let Some(decision) = authenticate_read_fence(input) {
        return decision;
    }
    if let Some(decision) = revalidate_rule_set_revision(input) {
        return decision;
    }
    if let Some(decision) = validate_every_rule(input.resolved.read()) {
        return decision;
    }
    let matched = match_negative_memory(
        input.subject,
        input.observed_horizon,
        input.resolved.read(),
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

/// Returns a refusal when the store-observed read fence is not the fence this
/// request is admitted at, and `None` when they are the same fence.
///
/// This is the authentication step. The read fence is what the **store**
/// echoed while serving the bounded exact-fence read; the request fence is the
/// content of the canonical write being admitted. Comparing those two is a
/// measurement against owner-issued evidence, which is what makes the read
/// fence more than a value the caller happened to pass in. An earlier spelling
/// compared the caller's own read fence with the caller's own request fence,
/// which no substitution could distinguish.
fn authenticate_read_fence(
    input: &NegativeMemoryGateInput<'_>,
) -> Option<NegativeMemoryGateDecision> {
    let read = input.resolved.store_observed_fence();
    if read == input.state_fence {
        return None;
    }
    Some(refused(
        NegativeMemoryGateRefusal::ReadFenceNotAuthenticated {
            read: Box::new(read.clone()),
            request: Box::new(input.state_fence.clone()),
        },
    ))
}

/// Returns a refusal when the dispatch-time revalidation does not equal the
/// snapshot's own Fence A revision, and `None` when it does.
///
/// Both values are owner-observed revisions of the *same* rule scope: the
/// snapshot's is the scope revision head the store reported for the read, and
/// the revalidation is the caller's second reading of that same head. An absent
/// revalidation is refused, so a caller that never looked again cannot be read
/// as a caller that observed no change.
fn revalidate_rule_set_revision(
    input: &NegativeMemoryGateInput<'_>,
) -> Option<NegativeMemoryGateDecision> {
    let Some(revalidated) = input.revalidated_rule_set_revision else {
        return Some(refused(NegativeMemoryGateRefusal::RuleSetRevisionAbsent));
    };
    let observed = input.resolved.rule_set_revision();
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
fn validate_every_rule(read: &NegativeMemoryCandidateRead) -> Option<NegativeMemoryGateDecision> {
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
) -> NegativeMemoryGateDecision {
    let rule_set_revision = input.revalidated_rule_set_revision.unwrap_or_default();
    let kind = result.outcome.kind();
    if !kind.certifies_rule_absence()
        && matches!(
            result.enumeration,
            eliot_dreamer_failure::EnumerationCoverage::Incomplete { .. }
        )
        || !input.resolved.enumeration_complete()
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
            NegativeMemoryGateDecision::Proceed { warning: None }
        }
        NegativeMemoryOutcome::Near { matched } => NegativeMemoryGateDecision::Proceed {
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
) -> NegativeMemoryGateDecision {
    let Some(record) = find_matched_record(input.resolved, matched) else {
        return refused(NegativeMemoryGateRefusal::MatchNotDecidable {
            detail: format!(
                "matcher reported exact match {}:{} but the validated snapshot retains no such rule",
                matched.record_id, matched.rule_revision
            ),
        });
    };
    let Some(policy) = input.resolved.policies().iter().find(|policy| {
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
        NegativeMemoryDisposition::Block => NegativeMemoryGateDecision::Block {
            record_id: record.record_id.clone(),
            rule_revision: record.rule_revision,
            policy_id: policy.policy_id.clone(),
            rule_set_revision,
        },
        NegativeMemoryDisposition::RequireCheck => NegativeMemoryGateDecision::RequireCheck {
            record_id: record.record_id.clone(),
            rule_revision: record.rule_revision,
            policy_id: policy.policy_id.clone(),
            check_id: record.discriminating_check.check_id.clone(),
            required_verifier: record.discriminating_check.required_verifier.clone(),
            discriminates_dimension_names: record
                .discriminating_check
                .discriminates_dimension_names
                .clone(),
            rule_set_revision,
        },
        // An advisory policy on an exact match is a warning, never a block: the
        // policy owner explicitly declined blocking power.
        NegativeMemoryDisposition::Advisory => NegativeMemoryGateDecision::Proceed {
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
fn find_matched_record(
    resolved: &ResolvedNegativeMemoryRuleSet,
    matched: &eliot_dreamer_failure::ExactMatch,
) -> Option<&NegativeMemoryFingerprint> {
    for page in &resolved.read().delivered_pages {
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
pub fn refusal_as_composition_error(
    decision: &NegativeMemoryGateDecision,
) -> Option<CompositionError> {
    match decision {
        NegativeMemoryGateDecision::Unavailable { refusal } => Some(CompositionError::Recovery(
            format!("negative-memory gate refused the effect: {refusal:?}"),
        )),
        NegativeMemoryGateDecision::Block {
            record_id,
            rule_revision,
            policy_id,
            ..
        } => Some(CompositionError::Recovery(format!(
            "negative-memory gate blocked the effect: rule {record_id} revision {rule_revision} under admitted policy {policy_id}"
        ))),
        NegativeMemoryGateDecision::RequireCheck {
            record_id,
            rule_revision,
            check_id,
            ..
        } => Some(CompositionError::Recovery(format!(
            "negative-memory gate requires the admitted discriminating check {check_id} for rule {record_id} revision {rule_revision}"
        ))),
        NegativeMemoryGateDecision::Proceed { .. } => None,
    }
}

/// The exact refusal message one decision carries, when it refuses.
///
/// This is the fail-closed message an outer action caller reports. It is the
/// same conversion [`Self::refusal_as_composition_error`] performs, without the
/// error wrapper, so a caller that only reports a refusal does not have to
/// unwrap a `CompositionError` to learn which rule or check refused it. A
/// `Proceed` decision yields `None`.
#[must_use]
pub fn negative_memory_gate_refusal_message(
    decision: &NegativeMemoryGateDecision,
) -> Option<String> {
    refusal_as_composition_error(decision).map(|error| error.to_string())
}
