//! Bounded deterministic Watchdog rule evaluations.
//!
//! This module owns the *finite rule table* deterministic supervision applies.
//! Every rule that may ever be evaluated is a row of it, and each row states the
//! observations the rule requires, the identities it correlates on, its bound,
//! its threshold, the Signal it yields and the strongest proposal it may ever
//! produce. A rule that is not a row of this table is not applicable.
//!
//! Applicability is stated per row and stated honestly. A rule whose competent
//! sensor or owner join does not exist yet is retained as an explicitly named
//! missing-implementation obligation rather than as a covered rule, so
//! "missing coverage yields a supervision gap" cannot decay into "missing
//! coverage means nothing is wrong". An obligation never reads as a finding: it
//! records that a coverage source is absent, and it never names a principal as
//! responsible for an observation nobody could make.
//!
//! The descriptor an evaluation reads comes from this table rather than from a
//! private constant in the module that implements the rule, so applicability
//! cannot be asserted in one place and contradicted in another.
//!
//! Exactly one row is [`RuleImplementation::CompetentlyCovered`] today: the
//! coordinator's typed provider host-event sequence-gap observation. The
//! coordinator package is deliberately not a dependency of this pure core:
//! STITCH projects the fields only after matching
//! `CoordinatorEvent::ProviderHostEventGap`, and supplies the owner-issued
//! `SignalTarget`, profile, clock, coverage and revisions that the event itself
//! does not carry.

use crate::episode::{FailureClass, FailureEpisodeIdentity, FailureEpisodeKey};
use crate::signals::{
    AcknowledgementFact, EvidenceRef, ExpectedRevision, ObservedTime, ProfileRevision,
    RecordedValue, ReopenCondition, RuleRevision, Signal, SignalAttribution, SignalDelivery,
    SignalDisposition, SignalId, SignalProcessing, SignalReferences, SignalRevision,
    SignalSeverity, SignalTarget, SignalValidationError, SourceEventRef,
};

/// Exact identity of the one rule this core evaluates today.
pub const PROVIDER_HOST_EVENT_GAP_RULE_ID: &str = "provider_host_event_sequence_gap";

/// Immutable revision of that rule's applicability contract.
pub const PROVIDER_HOST_EVENT_GAP_RULE_REVISION: u64 = 1;

/// Closed statement of how one rule in the finite table obtains its evidence.
///
/// There is no third case. A rule is either evaluated from a competent
/// owner-supplied sensor, or it is an explicitly retained obligation naming the
/// exact missing join. Nothing maps an obligation onto a covered rule, and
/// nothing maps an absent sensor onto an absence of violations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleImplementation {
    /// A competent owner-supplied sensor exists and this core evaluates the rule
    /// from it.
    CompetentlyCovered,
    /// No competent sensor or owner join exists yet.
    ///
    /// `obligation` names the exact sensor or owner join the rule still
    /// requires, so an unevaluated rule is a recorded, reviewable gap rather
    /// than an invisible one.
    MissingCompetentCoverage {
        /// The exact sensor or owner join this rule still requires.
        obligation: &'static str,
    },
}

/// One row of the finite Watchdog rule table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchdogRule {
    /// Stable rule identity; also the identity a failure episode keys on.
    pub rule_id: &'static str,
    /// Positive immutable revision of this rule's applicability contract.
    pub revision: u64,
    /// The observations this rule requires, named by their owner-issued
    /// identities rather than by prose a caller could fabricate.
    pub required_observations: &'static str,
    /// Which subject, scope and interval those observations correlate within.
    pub correlation: &'static str,
    /// What bounds the rule, and what it refuses rather than trims.
    pub bound: &'static str,
    /// The exact threshold at which the rule fires.
    pub threshold: &'static str,
    /// The Signal, or the typed non-Signal result, the rule yields.
    pub result: &'static str,
    /// The strongest proposal this rule may ever produce.
    pub permissible_proposal: &'static str,
    /// Whether this rule is evaluated today, or an explicit missing join.
    pub implementation: RuleImplementation,
}

/// The finite rule table deterministic supervision applies.
///
/// It is closed: a rule absent from here cannot be evaluated, because the
/// evaluation reads its descriptor from this table. It is also explicit about
/// incompleteness — nine of the ten rows record the exact sensor or owner join
/// that is still missing, which is a retained obligation and never a coverage
/// claim.
pub const WATCHDOG_RULE_TABLE: [WatchdogRule; 10] = [
    WatchdogRule {
        rule_id: PROVIDER_HOST_EVENT_GAP_RULE_ID,
        revision: PROVIDER_HOST_EVENT_GAP_RULE_REVISION,
        required_observations: "owner-supplied attempt, event, sequence pair, SignalTarget, state fence, and competent coverage",
        correlation: "one provider event within one attempt and owner-supplied SignalTarget; preserve the context StateFence separately",
        bound: "one source event per evaluation; no recurrence accumulation",
        threshold: "observed_sequence is greater than expected_sequence; the proven skip count is the difference",
        result: "warning Signal candidate for a provider host-event sequence supervision gap",
        permissible_proposal: "candidate-only signal routing or coverage inspection; no effect authority",
        implementation: RuleImplementation::CompetentlyCovered,
    },
    WatchdogRule {
        rule_id: "workspace_change_integration_gap",
        revision: 1,
        required_observations: "an owner-issued WorkspaceInstance identity, an owner-issued attempt identity, and the workspace-change event the integration owner itself recorded",
        correlation: "one workspace-change event within one WorkspaceInstance and one attempt; the subject is the owner-issued WorkspaceInstance identity, never a cwd string, an arbitrary path or hook text",
        bound: "one event per evaluation; bounded distinct WorkspaceInstance identities per scope; refuse rather than trim an already-accepted identity",
        threshold: "the integration owner recorded a workspace change whose expected participant set was never admitted; the proven gap is the missing participant count",
        result: "warning supervision-gap Signal candidate; a missing participant is a coverage gap and never an accusation against an unknown principal",
        permissible_proposal: "candidate-only signal routing, or a request to re-admit the missing participant through its owner; no process control",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "no competent sensor supplies WorkspaceInstance and attempt identities for a workspace-change event; the WorkspaceInstance owner must project the observed participant set before this rule can be evaluated",
        },
    },
    WatchdogRule {
        rule_id: "workspace_scope_drift",
        revision: 1,
        required_observations: "the owner-issued expected ScopeBinding and the owner-issued observed ScopeBinding for one attempt, both supplied by the guard owner, plus that attempt's fence identity",
        correlation: "one attempt within one scope, compared only on owner-issued WorkspaceInstance, attempt and fence identities; never on cwd text, hook text or a path",
        bound: "one attempt per evaluation; the comparison is bounded by the guard owner's own leg set and never widened here",
        threshold: "any identity leg the guard owner classifies as differing; the proven drift is that one leg, never a whole-scope verdict",
        result: "blocking Signal candidate naming the exact differing leg and the dependent attempts and context revisions the guard owner can freeze",
        permissible_proposal: "a request to the existing guard and rebind owner to freeze only the dependent scope, attempt and effects; no self-declared containment and no freeze outside the dependent set",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "crates/governor/eliot-workscope/src/guard.rs::identity_legs and ::rebind_with_receipt decide drift for the Governor but expose no watchdog-callable observation of the differing leg and its dependents",
        },
    },
    WatchdogRule {
        rule_id: "stale_context_after_invalidation",
        revision: 1,
        required_observations: "the invalidation event identity and revision issued by the context owner, and the exact context revision one admitted effect was bound to",
        correlation: "one effect attempt within one context revision; the invalidated revision is compared by owner-issued identity and never inferred from a timestamp",
        bound: "one invalidation per effect attempt; bounded distinct invalidation identities; refuse rather than trim",
        threshold: "the admitted effect's expected context revision is strictly older than the owner's current invalidation revision",
        result: "warning stale-context Signal candidate carrying both revisions and the exact effect attempt",
        permissible_proposal: "a request to re-admit or narrow the dependent effect through its owner; never a direct effect, and never a fabricated current-revision default for missing history",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "no context owner publishes an invalidation revision that binds to an already-admitted effect attempt, so there is no comparable pair of revisions to decide on",
        },
    },
    WatchdogRule {
        rule_id: "repeated_action_failure",
        revision: 1,
        required_observations: "distinct source event identities admitted against one failure episode, each with its separately recorded payload digest",
        correlation: "one failure episode keyed on rule identity and revision, scope, actual subject identity, observed generation and discriminating failure class",
        bound: "bounded distinct source events and bounded reopen history per episode; refuse rather than drop an accepted identity",
        threshold: "a distinct-evidence count that reaches the owner-issued attention policy threshold for the Signal's own severity",
        result: "the immutable Signal revision plus the exact distinct evidence identities this revision contributed",
        permissible_proposal: "one linked publication intent; a retransmission contributes no evidence and can never cross the threshold by itself",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "no production caller supplies a failure-episode admission and an owner-issued attention policy into crates/supervision/eliot-watchdog-core/src/publication.rs::evaluate_publication_intent; the existing intent owner bins/eliot-watchdog/src/watchdog_spool/intent.rs must persist the resulting intent in the same spool transaction as the episode record",
        },
    },
    WatchdogRule {
        rule_id: "orphan_descendant_after_parent_terminal",
        revision: 1,
        required_observations: "the owner-issued parent attempt identity and fence, and the owner-issued descendant identities that fence actually covered",
        correlation: "one descendant attempt within the parent fence it was admitted under; the fence identity is the correlation key",
        bound: "one descendant set per evaluation; the owner supplies the covered set and this core never widens it",
        threshold: "a descendant is observed whose admitted fence is no longer current for its parent",
        result: "warning orphan-descendant Signal candidate naming the exact descendant identity and the exact fence that no longer covers it",
        permissible_proposal: "a request to the owning fence and rebind owner for that dependent descendant set only; unrelated attempts stay available and no global process stop is proposable",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "no owner reports which fence covered which descendant, so the covered descendant set this rule compares against does not exist as an observation",
        },
    },
    WatchdogRule {
        rule_id: "admitted_envelope_overrun",
        revision: 1,
        required_observations: "the envelope identity and revision admitted by the envelope owner, and the exact attempt identities that envelope itself admitted",
        correlation: "one envelope against its own admitted attempt set; membership is decided by the envelope owner's admission and never by a caller's list",
        bound: "narrowing or cancelling is bounded by the admitted subtree exactly; an attempt the envelope never admitted is out of this rule's reach in both directions",
        threshold: "an observed effect outside the envelope's admitted attempt set, or an admitted attempt count above the envelope's own declared bound",
        result: "blocking overrun Signal candidate carrying the admitted set and the exact out-of-set observation",
        permissible_proposal: "a request to narrow or cancel only the admitted subtree through its owner; never a global kill, and never an attempt the envelope did not admit",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "no owner exposes the admitted attempt set of an envelope as a watchdog-readable observation, so an overrun cannot be distinguished from an unadmitted attempt",
        },
    },
    WatchdogRule {
        rule_id: "persistent_agent_observation_gap",
        revision: 1,
        required_observations: "the owner-issued agent observation identities, the owner-issued coverage reference claimed for that agent, and the owner-issued external-change identities for the same subject and interval",
        correlation: "one agent subject within one interval; an absent observation is compared against the coverage the owner claimed, never against an assumed cadence",
        bound: "one interval per evaluation; bounded distinct observation identities; refuse rather than trim",
        threshold: "the owner-claimed coverage covers an interval in which no observation exists AND at least one owner-issued external change occurred in that interval",
        result: "supervision-gap Signal candidate; an agent with no observation and no external change in the interval is explicitly not a violation and produces no candidate at all",
        permissible_proposal: "candidate-only signal routing, or a request to the coverage owner to instrument the gap; no process control, and no model inference inside this heartbeat decision",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "no competent sensor supplies the claimed coverage and the owner-issued external-change identities for one agent interval together, so the second half of the threshold has no input",
        },
    },
    WatchdogRule {
        rule_id: "hook_chain_failure",
        revision: 1,
        required_observations: "owner-issued hook chain event identities with their recorded outcomes, supplied by the hook-chain owner",
        correlation: "one hook chain within one admitted context revision; the hook's own recorded outcome is the evidence, and hook text is never parsed by this core",
        bound: "one chain per evaluation; bounded distinct hook event identities; refuse rather than trim",
        threshold: "a chain stage the hook owner itself recorded as failed or not reached",
        result: "warning hook-chain supervision-gap Signal candidate carrying the exact stage identity",
        permissible_proposal: "candidate-only signal routing, or a request to the hook-chain owner; hook-supplied text can never become an action, a target or an authority",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "issue #1758 has not yet projected a typed hook-chain observation this core can read; nothing here parses hook text, and no forged hook-supplied action is proposable",
        },
    },
    WatchdogRule {
        rule_id: "named_bypass_class_without_competent_coverage",
        revision: 1,
        required_observations: "the competent coverage reference for the named bypass class and the owner-issued observation that class actually emits; a class with no competent coverage has no observation at all",
        correlation: "one named bypass class within one subject and scope; the class identity is the correlation key and is never free text",
        bound: "one class per evaluation; absent coverage is a supervision gap and never an accusation against an unknown principal",
        threshold: "competent coverage exists AND the owner emitted that class's observation; without competent coverage this rule has no threshold decision to make",
        result: "supervision-gap Signal candidate recording the missing coverage; it is never a finding that a bypass is absent",
        permissible_proposal: "candidate-only signal routing, or a request to the coverage owner; no accusation, no hard-security verdict, and no model inference inside this decision",
        implementation: RuleImplementation::MissingCompetentCoverage {
            obligation: "the named bypass classes have no competent coverage source yet, because issue #1758 owns the hook-chain and bypass evidence; this row is retained so their absence stays an explicit gap instead of an implicit pass",
        },
    },
];

/// Returns the finite rule table this core applies.
///
/// This is the same closed table every evaluation reads its descriptor from, so
/// a caller inspecting applicability sees exactly what the evaluations are bound
/// to and nothing more.
#[must_use]
pub const fn watchdog_rule_table() -> &'static [WatchdogRule] {
    &WATCHDOG_RULE_TABLE
}

/// Returns the table row naming `rule_id`, or `None` when no row names it.
///
/// A rule that is not a row of the finite table has no applicability contract,
/// so it cannot be evaluated and cannot be cited as one.
#[must_use]
pub fn find_watchdog_rule(rule_id: &str) -> Option<&'static WatchdogRule> {
    watchdog_rule_table()
        .iter()
        .find(|rule| rule.rule_id == rule_id)
}

/// Returns the row for `rule_id` only when the table names it at exactly
/// `revision` and records it as [`RuleImplementation::CompetentlyCovered`].
///
/// This is the only route from a rule identity to an applicability descriptor,
/// which is what keeps the table load-bearing: a row that is missing, revised
/// away, or recorded as an unmet obligation cannot be evaluated, so no rule can
/// quietly run without stating what it requires and what it may propose.
///
/// # Errors
///
/// Returns [`SignalValidationError::RuleNotApplicable`] when the table does not
/// name `rule_id` at `revision`, or records its implementation as
/// [`RuleImplementation::MissingCompetentCoverage`].
pub fn covered_rule(
    rule_id: &str,
    revision: u64,
) -> Result<&'static WatchdogRule, SignalValidationError> {
    find_watchdog_rule(rule_id)
        .filter(|rule| {
            rule.revision == revision
                && rule.implementation == RuleImplementation::CompetentlyCovered
        })
        .ok_or(SignalValidationError::RuleNotApplicable)
}

/// Owner-issued provider attempt identity from `ProviderHostEventGap`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAttemptIdentity(pub String);

/// Owner-issued provider event identity from `ProviderHostEventGap`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderEventIdentity(pub String);

/// Exact relevant `StateFence` fields projected by their owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateFenceProjection {
    pub authority_lineage_id: String,
    pub authority_sequence: u64,
    pub resource_generation: u64,
    pub task_revision: Option<String>,
    pub policy_revision: Option<String>,
    pub integration_revision: Option<String>,
}

/// Explicit reference to the competent sequence-gap sensor.
///
/// STITCH may construct this only from the coordinator event variant whose
/// producer emitted a forward sequence jump. The coverage reference is
/// supplied by the integration owner; this type does not invent it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompetentIntegrationCoverage {
    pub coverage_id: String,
    pub source_sensor: IntegrationGapSensor,
}

/// Closed source-sensor class accepted by this rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationGapSensor {
    CoordinatorProviderHostEventGap,
}

/// Owner-supplied values needed to complete a Signal candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationGapSignalContext {
    /// Exact source-owner supplied subject, scope and generation.
    pub target: SignalTarget,
    pub profile: ProfileRevision,
    pub observed_at: ObservedTime,
    pub coverage: CompetentIntegrationCoverage,
    pub expected_context_revision: ExpectedRevision,
    pub expected_authority_revision: ExpectedRevision,
}

/// Typed projection of one `CoordinatorEvent::ProviderHostEventGap`.
///
/// The first four fields must be copied from that exact event by STITCH. The
/// state fence is copied from its `ExecutionContext`; other signal context is
/// separately supplied by the owning integration because it is absent from
/// the event payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationGapObservation {
    pub attempt: ProviderAttemptIdentity,
    pub event: ProviderEventIdentity,
    pub expected_sequence: u64,
    pub observed_sequence: u64,
    pub state_fence: StateFenceProjection,
    pub signal_context: IntegrationGapSignalContext,
}

/// Why an input did not prove a provider host-event sequence gap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationGapUnknown {
    EmptyAttemptIdentity,
    EmptyEventIdentity,
    AttemptMismatch,
    InvalidSequenceOrder,
    EmptyFenceIdentity,
    ZeroFenceGeneration,
    ZeroExpectedSequence,
}

/// Evidence-only result from evaluating the provider host-event gap rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrationGapEvaluation {
    /// One forward sequence skip is proved by the owner-supplied observation.
    GapDetected(Box<IntegrationGapSignalCandidate>),
    /// The source projection did not prove a forward gap.
    Unknown(IntegrationGapUnknown),
}

/// Complete immutable Signal candidate plus its exact typed source projection.
///
/// This value is evidence only. It cannot declare a canonical Problem or
/// Incident, authorize containment, or prove a workspace-change gap or bypass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrationGapSignalCandidate {
    pub signal: Signal,
    pub attempt: ProviderAttemptIdentity,
    pub event: ProviderEventIdentity,
    pub expected_sequence: u64,
    pub observed_sequence: u64,
    pub skipped_sequence_count: u64,
    pub state_fence: StateFenceProjection,
    pub competent_coverage: CompetentIntegrationCoverage,
}

/// Evaluates one typed owner projection without persistence or effect authority.
///
/// STITCH is the external caller. It matches the exact coordinator event
/// variant and passes its attempt/event IDs, sequence pair and context fence,
/// along with owner-issued `SignalTarget` and signal metadata. Callers must not derive
/// those identities from cwd strings, arbitrary paths, or hook text.
///
/// The rule descriptor this evaluation applies is read from the finite table
/// through [`covered_rule`], so this function cannot run at all unless the table
/// records the rule at this exact revision as competently covered.
///
/// # Errors
///
/// Returns [`SignalValidationError::RuleNotApplicable`] when the finite table no
/// longer records this rule at [`PROVIDER_HOST_EVENT_GAP_RULE_REVISION`] as
/// competently covered, and [`SignalValidationError`] when the owner-issued
/// signal context cannot form a valid Signal revision.
pub fn evaluate_provider_host_event_gap(
    observation: IntegrationGapObservation,
) -> Result<IntegrationGapEvaluation, crate::signals::SignalValidationError> {
    let rule = covered_rule(
        PROVIDER_HOST_EVENT_GAP_RULE_ID,
        PROVIDER_HOST_EVENT_GAP_RULE_REVISION,
    )?;
    let skipped_sequence_count = match prove_sequence_gap(&observation) {
        Ok(count) => count,
        Err(unknown) => return Ok(IntegrationGapEvaluation::Unknown(unknown)),
    };
    let signal = build_signal(&observation, rule)?;

    Ok(IntegrationGapEvaluation::GapDetected(Box::new(
        IntegrationGapSignalCandidate {
            signal,
            attempt: observation.attempt,
            event: observation.event,
            expected_sequence: observation.expected_sequence,
            observed_sequence: observation.observed_sequence,
            skipped_sequence_count,
            state_fence: observation.state_fence,
            competent_coverage: observation.signal_context.coverage,
        },
    )))
}

fn prove_sequence_gap(
    observation: &IntegrationGapObservation,
) -> Result<u64, IntegrationGapUnknown> {
    if observation.attempt.0.trim().is_empty() {
        return Err(IntegrationGapUnknown::EmptyAttemptIdentity);
    }
    if observation.event.0.trim().is_empty() {
        return Err(IntegrationGapUnknown::EmptyEventIdentity);
    }
    if observation.signal_context.target.subject_id != observation.attempt.0 {
        return Err(IntegrationGapUnknown::AttemptMismatch);
    }
    if observation.state_fence.resource_generation == 0 {
        return Err(IntegrationGapUnknown::ZeroFenceGeneration);
    }
    if observation
        .state_fence
        .authority_lineage_id
        .trim()
        .is_empty()
        || observation.state_fence.authority_sequence == 0
    {
        return Err(IntegrationGapUnknown::EmptyFenceIdentity);
    }
    if observation.expected_sequence == 0 {
        return Err(IntegrationGapUnknown::ZeroExpectedSequence);
    }
    let Some(skipped_sequence_count) = observation
        .observed_sequence
        .checked_sub(observation.expected_sequence)
        .filter(|count| *count > 0)
    else {
        return Err(IntegrationGapUnknown::InvalidSequenceOrder);
    };
    Ok(skipped_sequence_count)
}

fn build_signal(
    observation: &IntegrationGapObservation,
    rule: &WatchdogRule,
) -> Result<Signal, crate::signals::SignalValidationError> {
    // I8.3: the failure episode is keyed on owner-issued facts only — the rule
    // revision, the exact scope, the actual attempt identity and its observed
    // generation, and the discriminating failure class. The source event
    // identity is deliberately **not** part of the key, so a second distinct
    // host event observed under the same attempt, scope, generation and class
    // appends evidence to this same Signal instead of opening a parallel one,
    // and a retransmission of one event is recognised against the episode's
    // separate source-event index rather than as a new episode.
    let episode_key = FailureEpisodeKey::derive(&FailureEpisodeIdentity {
        rule: RuleRevision {
            rule_id: rule.rule_id.to_owned(),
            revision: rule.revision,
        },
        target: observation.signal_context.target.clone(),
        failure_class: FailureClass::ProviderHostEventSequenceGap,
    })?;
    let signal_id = episode_key.as_str().to_owned();
    // Evidence stays per-observation: it names the exact event that was
    // observed and the exact sequence skip that was proved, so distinct
    // evidence remains distinguishable inside one episode while a
    // retransmission of the same event re-derives the same evidence identity.
    let evidence_id = encode_identity(&[
        signal_id.clone(),
        observation.attempt.0.clone(),
        observation.event.0.clone(),
        observation.expected_sequence.to_string(),
        observation.observed_sequence.to_string(),
        observation.state_fence.authority_lineage_id.clone(),
        observation.state_fence.authority_sequence.to_string(),
        observation.state_fence.resource_generation.to_string(),
        fence_optional_identity(observation.state_fence.task_revision.as_deref()),
        fence_optional_identity(observation.state_fence.policy_revision.as_deref()),
        fence_optional_identity(observation.state_fence.integration_revision.as_deref()),
    ]);
    Signal::new(SignalRevision {
        signal_id: SignalId(signal_id.clone()),
        revision: 1,
        rule: RuleRevision {
            rule_id: rule.rule_id.to_owned(),
            revision: rule.revision,
        },
        profile: observation.signal_context.profile.clone(),
        severity: SignalSeverity::Warning,
        target: observation.signal_context.target.clone(),
        observed_at: RecordedValue::Known(observation.signal_context.observed_at.clone()),
        source_events: SignalReferences::Known(vec![SourceEventRef {
            event_id: observation.event.0.clone(),
            payload_digest: RecordedValue::Unknown {
                limitation: "ProviderHostEventGap supplies event identity and sequence only; no payload digest is present".to_owned(),
            },
        }]),
        evidence: SignalReferences::Known(vec![EvidenceRef { evidence_id }]),
        coverage: SignalReferences::Known(vec![crate::signals::CoverageRef {
            coverage_id: observation.signal_context.coverage.coverage_id.clone(),
        }]),
        attribution: SignalAttribution::Unknown {
            limitation: "ProviderHostEventGap identifies the attempt and missing sequence, not a principal responsible for the gap".to_owned(),
        },
        processing: SignalProcessing::Observed,
        delivery: SignalDelivery::Pending,
        disposition: SignalDisposition::Informational,
        acknowledgement: AcknowledgementFact::NotAcknowledged,
        resolution: crate::signals::ResolutionFact::Unresolved,
        dedup_key: RecordedValue::Known(signal_id.clone()),
        reopen_condition: ReopenCondition::RecurrenceWithNewSourceEvent,
        expected_context_revision: observation.signal_context.expected_context_revision.clone(),
        expected_authority_revision: observation.signal_context.expected_authority_revision.clone(),
    })
}

/// Encodes one optional fence revision as an unambiguous presence-tagged field.
///
/// A bare value would be ambiguous against the length-prefixed encoding of a
/// neighbouring field, so the presence itself is part of the material: an absent
/// revision and a revision whose text happens to read like another field's can
/// never derive the same evidence identity.
fn fence_optional_identity(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("some:{value}"),
        None => "none".to_owned(),
    }
}

/// Length-prefixes each field into one unambiguous identity string.
///
/// A separator alone would be ambiguous: two different field splits can
/// produce the same joined text. Prefixing every field with its own length
/// makes the encoding injective, so an identity derived from these fields
/// cannot collide with an identity derived from a different field list.
pub(crate) fn encode_identity(fields: &[String]) -> String {
    let mut encoded = String::new();
    for field in fields {
        encoded.push_str(&field.len().to_string());
        encoded.push(':');
        encoded.push_str(field);
    }
    encoded
}
