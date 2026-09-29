//! Bounded deterministic Watchdog rule evaluations.
//!
//! This module owns the finite Watchdog rule table and the pure applicability
//! decision that guards it. Every table entry names the subject/invariant it
//! governs, the observation classes it requires, its correlation, bound,
//! threshold, resulting Signal and its permissible proposed action. A rule whose
//! required observations are absent or unusable is inapplicable and fails
//! closed: it never fires, and it is never treated as having passed.
//!
//! Inapplicability is not one fact, and this module never collapses it into
//! one. [`RuleApplicability`] separates the two causes a caller must never
//! conflate. A required owner-issued observation that was never established is
//! a [`RuleApplicability::CoverageGap`]: coverage was expected, its absence is
//! itself the reportable supervision gap, and it is never proof that a bypass
//! class did not occur and never an accusation against an unknown principal. A
//! projection that is present but structurally unusable is a
//! [`RuleApplicability::Malformed`]: the rule could not be evaluated at all, so
//! the fault reaches the caller instead of being recorded as an absence. Only an
//! applicable rule that evaluates cleanly and finds nothing is an absence.
//!
//! Only the coordinator's typed provider host-event sequence-gap rule has a
//! typed projection and evaluation entrypoint in this revision. The coordinator
//! package is deliberately not a dependency of this pure core: STITCH projects
//! the fields only after matching `CoordinatorEvent::ProviderHostEventGap`, and
//! supplies the owner-issued `SignalTarget`, profile, clock, coverage and
//! revisions that the event itself does not carry. The remaining table entries
//! are declared, bounded and applicability-checked, and retain their missing
//! sensor/owner join as an explicit obligation rather than a blanket
//! `Unsupported` result.

use crate::health_detectors::HealthNoSignalReason;
use crate::signals::{
    AcknowledgementFact, ClockDomain, CoverageRef, EvidenceRef, ExpectedRevision, ObservedTime,
    ProfileRevision, RecordedValue, ReopenCondition, RuleRevision, Signal, SignalAttribution,
    SignalDelivery, SignalDisposition, SignalId, SignalProcessing, SignalReferences,
    SignalRevision, SignalSeverity, SignalTarget, SourceEventRef,
};

/// The bounded class of supervision question one table entry answers.
///
/// The classes are the rule families named by the interaction-heartbeat
/// contextual rules and the named bypass-detection classes. A class names the
/// question; a [`RuleDescriptor`] names the exact subject, requirements and
/// threshold for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleClass {
    /// A required observation from an owner is missing or arrives out of order.
    IntegrationGap,
    /// The observed workspace or worktree differs from the bound instance.
    ScopeDrift,
    /// Material work continues on a context that was already invalidated.
    StaleContext,
    /// The same discriminating failure signature repeats without new evidence.
    RepeatedFailure,
    /// A child exists without an admitted attempt or parent lineage.
    OrphanDescendant,
    /// Admitted child envelope usage reaches or exceeds its bound.
    EnvelopeOverrun,
    /// Material activity continues with no agent observation for a window.
    AgentObservationGap,
    /// A required hook or plugin step produced no competent result.
    HookFailure,
    /// An effect appeared outside its declared owner or write path.
    Bypass,
}

/// One bounded observation class a rule requires before it may fire.
///
/// Each class names an owner-issued fact. A value of this type is a
/// requirement, never a fact: the fact is present only when the owning agent
/// projected it into an [`ApplicabilitySubject`].
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RequiredObservation {
    /// The `WorkspaceInstance` identity the subject is bound to.
    WorkspaceInstanceIdentity,
    /// The admitted attempt identity the subject belongs to.
    AttemptIdentity,
    /// The context fence for the subject's generation.
    StateFence,
    /// The owner-issued source event identity and its observed sequence.
    SourceEventObservation,
    /// The owner-supplied correlation interval for the subject.
    CorrelationInterval,
    /// The owner-issued signature discriminating this failure class.
    FailureSignature,
    /// The owner-issued child/parent lineage reference.
    DescendantLineage,
    /// The admitted envelope bound and the measured usage against it.
    EnvelopeMeasurement,
    /// The exact hook-chain evidence handle from the hook owner.
    HookChainEvidence,
    /// The canonical-path access evidence from a competent source sensor.
    CanonicalPathEvidence,
    /// The competent `IntegrationCoverageProfile` reference for this rule.
    CompetentCoverage,
}

/// One immutable entry of the finite Watchdog rule table.
///
/// The prose fields are the audit surface; `required` is the machine-checked
/// form the applicability decision consumes, and `class` locates the entry in
/// the rule families the architecture names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleDescriptor {
    /// Stable rule identity, also the `Signal`'s `rule_id`.
    pub rule_id: &'static str,
    /// Positive immutable rule revision.
    pub revision: u64,
    /// The bounded rule family this entry belongs to.
    pub class: RuleClass,
    /// The exact subject or invariant this rule governs.
    pub subject: &'static str,
    /// The owner-issued observations this rule requires, in prose.
    pub required_observations: &'static str,
    /// The owner-issued observation classes this rule requires.
    pub required: &'static [RequiredObservation],
    /// How subject, interval and identity correlate within one evaluation.
    pub correlation: &'static str,
    /// The bound this rule places on one evaluation.
    pub bound: &'static str,
    /// The exact threshold this rule tests.
    pub threshold: &'static str,
    /// The resulting evidence-only Signal this rule can produce.
    pub result: &'static str,
    /// The only proposed action this rule's evidence may support.
    pub permissible_proposal: &'static str,
    /// Identity of the health detector that already answers this exact
    /// condition, when one exists.
    ///
    /// This is a merge obligation, not an alias. `build_signal` seeds a
    /// candidate's `dedup_key` and `signal_id` from `rule_id`, so a table
    /// entry that mints a second identity for a condition the detector
    /// already detects would key the same episode twice. When this is
    /// `Some`, `rule_id` is required to equal it, and a compile-time
    /// assertion below enforces that equality for every entry.
    pub merged_detector_rule_id: Option<&'static str>,
}

/// Position of the provider host-event sequence-gap rule in [`RULE_TABLE`].
///
/// The table is the single source of rule descriptors; this index is the only
/// way a caller reaches one of its entries by name. It is a positional alias,
/// so it is not trusted on its own: a compile-time assertion below binds this
/// position to [`PROVIDER_HOST_EVENT_GAP_RULE_ID`], and reordering the table
/// without moving the entry fails the build instead of silently re-pointing
/// [`provider_host_event_gap_rule`] at a different rule.
pub const PROVIDER_HOST_EVENT_GAP_RULE_INDEX: usize = 0;

/// Stable rule identity of the provider host-event sequence-gap rule.
const PROVIDER_HOST_EVENT_GAP_RULE_ID: &str = "provider_host_event_sequence_gap";

/// The finite, enumerated Watchdog rule table.
///
/// The table is closed: adding a class requires adding an entry here, and no
/// dynamic registry, plugin scan or configuration load can extend it at run
/// time. Every entry is applicability-checked through
/// [`evaluate_rule_applicability`] before any rule may fire.
pub const RULE_TABLE: &[RuleDescriptor] = &[
    RuleDescriptor {
        rule_id: "provider_host_event_sequence_gap",
        revision: 1,
        class: RuleClass::IntegrationGap,
        subject: "the coordinator provider host-event stream of one admitted attempt",
        required_observations: "owner-supplied attempt, event, sequence pair, SignalTarget, state fence, and competent coverage",
        required: &[
            RequiredObservation::AttemptIdentity,
            RequiredObservation::StateFence,
            RequiredObservation::SourceEventObservation,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one provider event within one attempt and owner-supplied SignalTarget; preserve the context StateFence separately",
        bound: "one source event per evaluation; no recurrence accumulation",
        threshold: "observed_sequence is greater than expected_sequence; the proven skip count is the difference",
        result: "warning Signal candidate for a provider host-event sequence supervision gap",
        permissible_proposal: "candidate-only signal routing or coverage inspection; no effect authority",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "workspace_change_without_post_tool_observation",
        revision: 1,
        class: RuleClass::IntegrationGap,
        subject: "the material workspace change interval of one bound WorkspaceInstance",
        required_observations: "owner-issued WorkspaceInstance, attempt, state fence, correlation interval, and competent PostTool/observe coverage",
        required: &[
            RequiredObservation::WorkspaceInstanceIdentity,
            RequiredObservation::AttemptIdentity,
            RequiredObservation::StateFence,
            RequiredObservation::CorrelationInterval,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one owner-declared interval bound to one WorkspaceInstance and attempt; an idle agent with no external change satisfies nothing here and is not a violation",
        bound: "one declared interval per evaluation; intervals never accumulate into one running total",
        threshold: "workspace change count is greater than zero while the PostTool/observe observation count for the same interval is zero",
        result: "warning Signal candidate for an unobserved material workspace change",
        permissible_proposal: "candidate-only signal routing, a resync request, or coverage inspection; no effect authority",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "scope_drift",
        revision: 1,
        class: RuleClass::ScopeDrift,
        subject: "the owner-issued WorkspaceInstance binding of one attempt's observed work location",
        required_observations: "owner-issued WorkspaceInstance, attempt, state fence, and competent work-location coverage",
        required: &[
            RequiredObservation::WorkspaceInstanceIdentity,
            RequiredObservation::AttemptIdentity,
            RequiredObservation::StateFence,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "the observed instance identity compares against the instance the owner bound to this attempt; a cwd string, free-form path or hook text is not a comparable identity",
        bound: "one attempt and one bound instance per evaluation",
        threshold: "the observed instance identity is not the bound instance identity for the same attempt and generation",
        result: "blocking-scope Signal candidate for a scope drift; dependent context and effects are frozen by their own owner",
        permissible_proposal: "a request to the existing guard/rebind owner to freeze only dependent scope or effects and request a rebind",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "stale_context_after_invalidation",
        revision: 1,
        class: RuleClass::StaleContext,
        subject: "the context packet of one attempt after its bound revision was invalidated",
        required_observations: "owner-issued attempt, invalidation fence, correlation interval, and competent packet/state-refresh coverage",
        required: &[
            RequiredObservation::AttemptIdentity,
            RequiredObservation::StateFence,
            RequiredObservation::CorrelationInterval,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "material tool events and the invalidation both fall inside one owner-declared interval for the same attempt and generation",
        bound: "one interval and one invalidation revision per evaluation",
        threshold: "the material tool count after the invalidation reaches the profile bound while the packet/state refresh count is zero",
        result: "warning Signal candidate for stale context continuing after invalidation",
        permissible_proposal: "a bounded refresh requirement or candidate-only signal routing; no direct context mutation",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "agent_loop_signal",
        revision: 1,
        class: RuleClass::RepeatedFailure,
        subject: "the discriminating failure signature of one attempt within one interval",
        required_observations: "owner-issued attempt, state fence, failure signature, correlation interval, and competent failure coverage",
        required: &[
            RequiredObservation::AttemptIdentity,
            RequiredObservation::StateFence,
            RequiredObservation::FailureSignature,
            RequiredObservation::CorrelationInterval,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "occurrences share one owner-issued failure signature and fall in one declared interval; a retransmitted source event is not a new occurrence; this entry is the same condition as the health detector rule agent_loop_signal and shares its one rule identity, so one episode is keyed once",
        bound: "occurrences are counted by distinct source event identity only, never by delivery count",
        threshold: "distinct occurrences of the same signature reach the profile bound while the distinct-evidence count stays at zero",
        result: "warning Signal candidate for repeated failure without new evidence",
        permissible_proposal: "candidate-only attention routing or an evidence-bound diagnosis request; no repair authority",
        merged_detector_rule_id: Some("agent_loop_signal"),
    },
    RuleDescriptor {
        rule_id: "orphan_descendant_without_admitted_attempt",
        revision: 1,
        class: RuleClass::OrphanDescendant,
        subject: "one observed child process and its admitted attempt or parent lineage",
        required_observations: "owner-issued descendant lineage and competent process-tree coverage; an admitted attempt or parent lineage is deliberately not required, because their absence is the finding",
        required: &[
            RequiredObservation::DescendantLineage,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed descendant compared against the admitted attempts and parent lineages the owner recorded for the same generation",
        bound: "one descendant identity per evaluation",
        threshold: "the observed descendant is not a member of any admitted attempt lineage and has no owner-recorded parent lineage",
        result: "warning Signal candidate for an orphan descendant; no proof or effect admission follows",
        permissible_proposal: "candidate-only lineage inspection; no process stop, kill or restart authority",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "envelope_overrun",
        revision: 1,
        class: RuleClass::EnvelopeOverrun,
        subject: "one admitted child envelope of context, token, tool or descendant usage",
        required_observations: "owner-issued attempt, admitted envelope bound with measured usage, and competent usage coverage",
        required: &[
            RequiredObservation::AttemptIdentity,
            RequiredObservation::EnvelopeMeasurement,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "the measured usage is compared against the envelope bound its own owner admitted for the same attempt and generation",
        bound: "one admitted envelope per evaluation; the overrun narrows or cancels only its own admitted subtree",
        threshold: "measured usage is greater than or equal to the admitted bound",
        result: "warning Signal candidate for an envelope overrun",
        permissible_proposal: "a request to narrow or cancel only the admitted subtree; unrelated attempts stay available",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "observation_coverage_gap",
        revision: 1,
        class: RuleClass::AgentObservationGap,
        subject: "one configured observation window over an active attempt",
        required_observations: "owner-issued attempt, configured correlation interval, and competent agent-observation coverage",
        required: &[
            RequiredObservation::AttemptIdentity,
            RequiredObservation::CorrelationInterval,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "both the activity count and the observation count come from one owner-declared window for the same attempt; an idle agent with no external change is outside this rule entirely; this entry is the same condition as the health detector rule observation_coverage_gap and shares its one rule identity, so one episode is keyed once",
        bound: "one configured window per evaluation; window lengths never accumulate",
        threshold: "the activity count is greater than zero while the ELIOT observation count for the same window is zero for the whole configured window",
        result: "warning Signal candidate for a persistent agent-observation gap; persistence lowers the governance profile through its own owner",
        permissible_proposal: "a bounded resync request to the agent or a governance-profile review; no profile mutation here",
        merged_detector_rule_id: Some("observation_coverage_gap"),
    },
    RuleDescriptor {
        rule_id: "hook_chain_failure",
        revision: 1,
        class: RuleClass::HookFailure,
        subject: "one required hook or plugin step in the admitted chain",
        required_observations: "exact hook-chain evidence handle from the hook owner and competent hook coverage; hook text is not itself a comparable identity",
        required: &[
            RequiredObservation::HookChainEvidence,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed step compared against the steps the hook owner admitted for the same chain and generation",
        bound: "one step per evaluation",
        threshold: "the owner recorded no competent result for a step the chain admitted as required",
        result: "warning Signal candidate for a hook-chain failure",
        permissible_proposal: "candidate-only hook inspection or re-admission through the hook owner; no direct hook execution",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "bypass_canonical_endpoint_access",
        revision: 1,
        class: RuleClass::Bypass,
        subject: "a process accessing the canonical database endpoint or credentials outside the storage bridge",
        required_observations: "canonical-path access evidence from a competent source-assurance sensor and its competent coverage reference",
        required: &[
            RequiredObservation::CanonicalPathEvidence,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed access compared against the storage-bridge lineage the owner recorded for the same generation",
        bound: "one access identity per evaluation",
        threshold: "the access resolves outside the active Host-managed storage-bridge lineage",
        result: "blocking Signal candidate for bypassed canonical endpoint access; the observation remains evidence",
        permissible_proposal: "candidate-only routing to the security owner; no process control here",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "bypass_protected_database_path_access",
        revision: 1,
        class: RuleClass::Bypass,
        subject: "a process touching the protected database path outside the active Host-managed lineage",
        required_observations: "canonical-path access evidence from a competent source-assurance sensor and its competent coverage reference",
        required: &[
            RequiredObservation::CanonicalPathEvidence,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed path access compared against the active Host-managed database process lineage",
        bound: "one access identity per evaluation",
        threshold: "the touching process is not a member of the active Host-managed lineage for that path",
        result: "blocking Signal candidate for bypassed protected database path access",
        permissible_proposal: "candidate-only routing to the security owner; no process control here",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "bypass_unregistered_canonical_export_import",
        revision: 1,
        class: RuleClass::Bypass,
        subject: "a canonical export or import that no owner admitted",
        required_observations: "canonical-path access evidence naming the export or import and competent coverage",
        required: &[
            RequiredObservation::CanonicalPathEvidence,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed export/import compared against the registration its owner recorded for the same generation",
        bound: "one export/import identity per evaluation",
        threshold: "no owner recorded a registration for the observed canonical export or import",
        result: "blocking Signal candidate for an unregistered canonical export or import",
        permissible_proposal: "candidate-only routing to the security owner; rejection of the content is the receiving owner's decision",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "bypass_known_db_cli_query_path",
        revision: 1,
        class: RuleClass::Bypass,
        subject: "an agent executing a known database CLI or query path",
        required_observations: "exact hook-chain or process-execution evidence from a competent sensor and its competent coverage reference",
        required: &[
            RequiredObservation::HookChainEvidence,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed execution compared against the known CLI/query path set its owner published for the same generation",
        bound: "one execution identity per evaluation",
        threshold: "the observed execution path is a known database CLI or query path",
        result: "blocking Signal candidate for an agent-executed database path",
        permissible_proposal: "candidate-only routing to the security owner; no process control here",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "bypass_undeclared_effect_set_write",
        revision: 1,
        class: RuleClass::Bypass,
        subject: "one module write outside its declared effect set",
        required_observations: "owner-issued attempt, its declared effect set fence, and competent effect coverage",
        required: &[
            RequiredObservation::AttemptIdentity,
            RequiredObservation::StateFence,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed write compared against the effect set declared for the same attempt and generation",
        bound: "one write identity per evaluation",
        threshold: "the observed effect is not a member of the effect set declared for the same attempt and generation",
        result: "blocking Signal candidate for a write outside the declared effect set",
        permissible_proposal: "candidate-only routing to the security owner; no direct effect reversal here",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "bypass_unknown_protected_registry_mutation",
        revision: 1,
        class: RuleClass::Bypass,
        subject: "an unknown process changing protected configuration or registry state",
        required_observations: "canonical-path access evidence naming the protected target and competent coverage",
        required: &[
            RequiredObservation::CanonicalPathEvidence,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed mutation compared against the owner lineage the owner recorded for that protected target",
        bound: "one mutation identity per evaluation",
        threshold: "the mutating process has no owner-recorded lineage for the protected configuration, Module Catalog, Generation Registry or Capability Registry state it changed",
        result: "blocking Signal candidate for an unknown protected-state mutation; no principal is named without evidence",
        permissible_proposal: "candidate-only routing to the security owner; no accusation against an unknown principal",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "bypass_post_fence_generation_emission",
        revision: 1,
        class: RuleClass::Bypass,
        subject: "one emission from a generation its owner has already fenced",
        required_observations: "owner-issued fence naming the fenced generation and competent emission coverage",
        required: &[RequiredObservation::StateFence, RequiredObservation::CompetentCoverage],
        correlation: "the emitting generation is compared against the fencing owner record for the same lineage",
        bound: "one emission identity per evaluation",
        threshold: "the emitting generation is lower than the generation the owner already fenced for that lineage",
        result: "blocking Signal candidate for a post-fence emission",
        permissible_proposal: "candidate-only routing to the security owner; no generation replacement here",
        merged_detector_rule_id: None,
    },
    RuleDescriptor {
        rule_id: "bypass_unattributed_external_effect",
        revision: 1,
        class: RuleClass::Bypass,
        subject: "an external effect with no action or receipt lineage",
        required_observations: "owner-issued descendant/process lineage for the effect and competent effect coverage",
        required: &[
            RequiredObservation::DescendantLineage,
            RequiredObservation::CompetentCoverage,
        ],
        correlation: "one observed effect compared against the action and receipt lineage the owner recorded for the same generation",
        bound: "one effect identity per evaluation",
        threshold: "no admitted action and no receipt matches the observed effect",
        result: "warning Signal candidate for an external effect without lineage; the effect itself remains evidence",
        permissible_proposal: "candidate-only lineage inspection or routing to the security owner; no effect reversal here",
        merged_detector_rule_id: None,
    },
];

/// Byte-wise equality usable in a const context.
///
/// `&str` equality is not a const operation, so the compile-time identity
/// checks below cannot use `==` on a rule identity.
const fn rule_id_is(actual: &str, expected: &str) -> bool {
    let (actual, expected) = (actual.as_bytes(), expected.as_bytes());
    if actual.len() != expected.len() {
        return false;
    }
    let mut index = 0;
    while index < actual.len() {
        if actual[index] != expected[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Position of the entry carrying `rule_id`, or `usize::MAX` when absent.
const fn rule_index(rule_id: &str) -> usize {
    let mut index = 0;
    while index < RULE_TABLE.len() {
        if rule_id_is(RULE_TABLE[index].rule_id, rule_id) {
            return index;
        }
        index += 1;
    }
    usize::MAX
}

/// True when one condition can never be keyed under two rule identities.
///
/// Two conditions collide when two entries share one `rule_id`, because
/// `build_signal` seeds `dedup_key` and `signal_id` from it; and a merge
/// obligation is unmet when an entry declares a detector that owns the
/// condition but keeps a different identity of its own.
const fn rule_table_has_one_identity_per_condition() -> bool {
    let mut index = 0;
    while index < RULE_TABLE.len() {
        if let Some(merged) = RULE_TABLE[index].merged_detector_rule_id {
            if !rule_id_is(RULE_TABLE[index].rule_id, merged) {
                return false;
            }
        }
        let mut other = index + 1;
        while other < RULE_TABLE.len() {
            if rule_id_is(RULE_TABLE[index].rule_id, RULE_TABLE[other].rule_id) {
                return false;
            }
            other += 1;
        }
        index += 1;
    }
    true
}

const _: () = assert!(
    rule_id_is(
        RULE_TABLE[PROVIDER_HOST_EVENT_GAP_RULE_INDEX].rule_id,
        PROVIDER_HOST_EVENT_GAP_RULE_ID
    ),
    "RULE_TABLE was reordered: PROVIDER_HOST_EVENT_GAP_RULE_INDEX no longer names the provider host-event sequence-gap rule"
);

const _: () = assert!(
    rule_index(PROVIDER_HOST_EVENT_GAP_RULE_ID) == PROVIDER_HOST_EVENT_GAP_RULE_INDEX,
    "RULE_TABLE was reordered: the provider host-event sequence-gap rule is no longer at PROVIDER_HOST_EVENT_GAP_RULE_INDEX"
);

const _: () = assert!(
    rule_table_has_one_identity_per_condition(),
    "two RULE_TABLE entries share one rule identity, or an entry keeps a second identity for a condition its health detector already owns"
);

/// Returns the finite rule descriptor used by the public evaluation entrypoint.
///
/// The positional alias is bound to [`PROVIDER_HOST_EVENT_GAP_RULE_ID`] by the
/// compile-time assertions above, so a reordered table cannot make this
/// function return a different rule.
#[must_use]
pub const fn provider_host_event_gap_rule() -> &'static RuleDescriptor {
    &RULE_TABLE[PROVIDER_HOST_EVENT_GAP_RULE_INDEX]
}

/// Looks up one table entry by its stable rule identity.
///
/// The search is over the closed [`RULE_TABLE`] only. An identity that is not
/// in the table has no applicability and is reported as such; it is never
/// treated as an applicable rule with no requirements.
#[must_use]
pub fn rule_by_id(rule_id: &str) -> Option<&'static RuleDescriptor> {
    RULE_TABLE.iter().find(|rule| rule.rule_id == rule_id)
}

/// Owner-declared correlation interval for one subject.
///
/// Both ends are owner-supplied and must share one clock domain and unit so
/// that the interval is comparable at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationInterval {
    /// Inclusive start of the interval, as the owner recorded it.
    pub start: ObservedTime,
    /// Inclusive end of the interval, as the owner recorded it.
    pub end: ObservedTime,
}

/// One admitted envelope bound and the usage measured against it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeMeasurement {
    /// Identity of the envelope its owner admitted.
    pub envelope_id: String,
    /// The admitted bound. Zero is not an evaluable bound.
    pub admitted_limit: u64,
    /// The usage the owner measured for this envelope.
    pub measured_usage: u64,
}

/// Bounded projection of the owner-issued facts a rule may consult.
///
/// Every slot is an owner-issued identity or measurement. Nothing here can be
/// synthesised from a cwd string, a free-form path, hook text or model output:
/// a slot is either populated by the owning agent or absent, and an absent slot
/// makes every rule that requires it inapplicable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicabilitySubject {
    /// Exact owner-issued subject, scope and generation under evaluation.
    pub target: SignalTarget,
    /// `WorkspaceInstance` identity the owner bound to this target.
    pub workspace_instance: Option<String>,
    /// Admitted attempt identity the owner recorded for this target.
    pub attempt: Option<String>,
    /// Context fence projected by its owner for this target.
    pub fence: Option<StateFenceProjection>,
    /// Owner-issued source event identity for this evaluation.
    pub source_event: Option<String>,
    /// Owner-supplied correlation interval for this evaluation.
    pub interval: Option<CorrelationInterval>,
    /// Owner-issued signature discriminating this failure class.
    pub failure_signature: Option<String>,
    /// Owner-issued child or parent lineage reference.
    pub descendant_lineage: Option<String>,
    /// Admitted envelope bound with the measured usage against it.
    pub envelope: Option<EnvelopeMeasurement>,
    /// Exact hook-chain evidence handle from the hook owner.
    pub hook_evidence: Option<String>,
    /// Canonical-path access evidence from a competent source sensor.
    pub canonical_access: Option<String>,
    /// Competent `IntegrationCoverageProfile` reference for the rule under test.
    pub competent_coverage: Option<CoverageRef>,
}

/// A required owner-issued observation that was never established.
///
/// This is the reportable supervision gap. The owning agent did not project the
/// observation, so no rule requiring it could be evaluated at all; the absence
/// of the coverage is the finding. It is never proof that the governed
/// condition did not occur, and it never accuses a principal of anything.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisionGap {
    /// Identity of the rule whose required coverage is missing.
    pub rule_id: &'static str,
    /// The observation class that was never projected by its owner.
    pub missing_observation: RequiredObservation,
    /// The established no-signal reason for a never-projected observation.
    ///
    /// This reuses the health detector's vocabulary rather than a parallel
    /// one: `evaluate_observation_coverage` reports absent handles as
    /// `IncompleteEvidence`, and a never-projected observation is the same
    /// fact.
    pub no_signal_reason: HealthNoSignalReason,
}

/// A projection that is present but structurally unusable.
///
/// Every variant is a fault in the input, not an observation about the world.
/// None of them permits the rule to fire, none of them is evidence that the
/// governed condition did not occur, and none of them may be reported as an
/// ordinary absence: the rule was not evaluated, so a caller must raise the
/// fault rather than record a clean no-signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MalformedProjection {
    /// The rule identity is not in the finite table.
    UnknownRule,
    /// The owner-issued subject, scope or generation is blank or non-positive.
    AbsentSubjectIdentity,
    /// A required owner-issued identity was projected but is blank.
    BlankObservation(RequiredObservation),
    /// The projected fence carries no positive resource generation.
    FenceWithoutGeneration,
    /// The projected interval is unordered, spans more than one clock domain,
    /// or is expressed in an unrecorded clock domain.
    UnorderedCorrelationInterval,
    /// The projected envelope measurement admits no bound to compare against.
    UnboundedEnvelope,
}

/// The pure applicability decision for one bounded rule.
///
/// The decision is evidence about observability only. It does not decide that
/// the governed condition occurred, and it confers no effect authority.
///
/// The two inapplicable variants are deliberately not one variant. A
/// [`Self::CoverageGap`] is a reportable fact about absent coverage; a
/// [`Self::Malformed`] is a fault in the projection that reached the evaluator.
/// Collapsing them would let a malformed input be recorded as though the
/// governed condition had been checked and found absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleApplicability {
    /// Every observation the rule requires is present and usable.
    Applicable,
    /// A required observation was never established, so the rule could not be
    /// evaluated and the missing coverage is itself the reportable gap.
    CoverageGap(SupervisionGap),
    /// The projection is structurally unusable, so the rule could not be
    /// evaluated and the fault must be raised to the caller.
    Malformed(MalformedProjection),
}

/// The coverage gap for one required observation that was never projected.
const fn coverage_gap(
    rule_id: &'static str,
    missing_observation: RequiredObservation,
) -> RuleApplicability {
    RuleApplicability::CoverageGap(SupervisionGap {
        rule_id,
        missing_observation,
        no_signal_reason: HealthNoSignalReason::IncompleteEvidence,
    })
}

/// Decides whether one table entry may be evaluated against one projection.
///
/// This is a pure function over the closed table and the owner-issued
/// projection. It reads no store, consults no clock, infers nothing and grants
/// no authority. A rule whose requirements are unsatisfied never fires, and it
/// is never a default-open pass: the caller receives either the reportable
/// [`RuleApplicability::CoverageGap`] or the [`RuleApplicability::Malformed`]
/// fault, and in neither case an ordinary absence.
#[must_use]
pub fn evaluate_rule_applicability(
    rule_id: &str,
    subject: &ApplicabilitySubject,
) -> RuleApplicability {
    let Some(rule) = rule_by_id(rule_id) else {
        return RuleApplicability::Malformed(MalformedProjection::UnknownRule);
    };
    let target = &subject.target;
    if target.subject_id.trim().is_empty()
        || target.scope_id.trim().is_empty()
        || target.generation == 0
    {
        return RuleApplicability::Malformed(MalformedProjection::AbsentSubjectIdentity);
    }
    for required in rule.required {
        if let Some(unusable) = unusable_observation(rule.rule_id, *required, subject) {
            return unusable;
        }
    }
    RuleApplicability::Applicable
}

fn unusable_observation(
    rule_id: &'static str,
    required: RequiredObservation,
    subject: &ApplicabilitySubject,
) -> Option<RuleApplicability> {
    match required {
        RequiredObservation::WorkspaceInstanceIdentity => {
            unusable_identity(rule_id, subject.workspace_instance.as_ref(), required)
        }
        RequiredObservation::AttemptIdentity => {
            unusable_identity(rule_id, subject.attempt.as_ref(), required)
        }
        RequiredObservation::SourceEventObservation => {
            unusable_identity(rule_id, subject.source_event.as_ref(), required)
        }
        RequiredObservation::FailureSignature => {
            unusable_identity(rule_id, subject.failure_signature.as_ref(), required)
        }
        RequiredObservation::DescendantLineage => {
            unusable_identity(rule_id, subject.descendant_lineage.as_ref(), required)
        }
        RequiredObservation::HookChainEvidence => {
            unusable_identity(rule_id, subject.hook_evidence.as_ref(), required)
        }
        RequiredObservation::CanonicalPathEvidence => {
            unusable_identity(rule_id, subject.canonical_access.as_ref(), required)
        }
        RequiredObservation::StateFence => match &subject.fence {
            None => Some(coverage_gap(rule_id, required)),
            Some(fence) => {
                if fence.resource_generation == 0 {
                    Some(RuleApplicability::Malformed(
                        MalformedProjection::FenceWithoutGeneration,
                    ))
                } else if fence.authority_lineage_id.trim().is_empty()
                    || fence.authority_sequence == 0
                {
                    Some(RuleApplicability::Malformed(
                        MalformedProjection::BlankObservation(required),
                    ))
                } else {
                    None
                }
            }
        },
        RequiredObservation::CorrelationInterval => match &subject.interval {
            None => Some(coverage_gap(rule_id, required)),
            Some(interval) => {
                if comparable_interval(interval) {
                    None
                } else {
                    Some(RuleApplicability::Malformed(
                        MalformedProjection::UnorderedCorrelationInterval,
                    ))
                }
            }
        },
        RequiredObservation::EnvelopeMeasurement => match &subject.envelope {
            None => Some(coverage_gap(rule_id, required)),
            Some(measurement) => {
                if measurement.envelope_id.trim().is_empty() {
                    Some(RuleApplicability::Malformed(
                        MalformedProjection::BlankObservation(required),
                    ))
                } else if measurement.admitted_limit == 0 {
                    Some(RuleApplicability::Malformed(
                        MalformedProjection::UnboundedEnvelope,
                    ))
                } else {
                    None
                }
            }
        },
        RequiredObservation::CompetentCoverage => match &subject.competent_coverage {
            None => Some(coverage_gap(rule_id, required)),
            Some(coverage) if coverage.coverage_id.trim().is_empty() => {
                Some(RuleApplicability::Malformed(
                    MalformedProjection::BlankObservation(required),
                ))
            }
            Some(_) => None,
        },
    }
}

/// Classifies one owner-issued identity slot as never projected or blank.
fn unusable_identity(
    rule_id: &'static str,
    identity: Option<&String>,
    required: RequiredObservation,
) -> Option<RuleApplicability> {
    match identity {
        None => Some(coverage_gap(rule_id, required)),
        Some(identity) if identity.trim().is_empty() => Some(RuleApplicability::Malformed(
            MalformedProjection::BlankObservation(required),
        )),
        Some(_) => None,
    }
}

/// True only when both ends of the interval share one recorded clock domain.
///
/// `ClockDomain::Unknown` is rejected on either end. An unrecorded clock domain
/// is not a shared clock domain: two `Unknown` ends compare equal, so accepting
/// them would let an interval whose ticks share no clock be treated as
/// comparable, and an ordered-by-accident unknown interval is still not
/// evidence ordered in time.
fn comparable_interval(interval: &CorrelationInterval) -> bool {
    known_clock_domain(&interval.start.domain)
        && known_clock_domain(&interval.end.domain)
        && interval.start.domain == interval.end.domain
        && interval.start.unit == interval.end.unit
        && interval.end.ticks >= interval.start.ticks
}

/// True when the domain names a clock the reading is actually expressed in.
fn known_clock_domain(domain: &ClockDomain) -> bool {
    !matches!(domain, ClockDomain::Unknown { .. })
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

/// Why an applicable rule evaluated cleanly and proved no sequence gap.
///
/// Each variant names a check the rule passed. None of them is a statement
/// about coverage: a caller that reaches this type has already proved the rule
/// was applicable, so the absence is an ordinary one and nothing more.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoGapReason {
    /// The owner-issued source event does not bind the owner-issued attempt.
    AttemptMismatch,
    /// A provider event sequence cannot start at zero.
    ZeroExpectedSequence,
    /// The observed sequence did not skip ahead of the expected sequence.
    InvalidSequenceOrder,
}

/// Why one provider host-event projection could not be evaluated at all.
///
/// A malformed projection is never reported as an absence. The rule did not
/// evaluate cleanly, so no conclusion may be drawn from this evaluation in
/// either direction, and the caller must raise the fault rather than record it
/// as a no-signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrationGapError {
    /// The projection is structurally unusable for this rule.
    MalformedProjection(MalformedProjection),
    /// The assembled candidate failed the signal layer's own validation.
    MalformedSignal(crate::signals::SignalValidationError),
}

/// Evidence-only result from evaluating the provider host-event gap rule.
///
/// The three cases are kept apart at the type level. A
/// [`Self::SupervisionGap`] reports missing coverage, which is a finding. A
/// [`Self::NoGap`] is the only ordinary absence. A projection that could not be
/// evaluated is not here at all; it is an [`IntegrationGapError`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntegrationGapEvaluation {
    /// One forward sequence skip is proved by the owner-supplied observation.
    GapDetected(Box<IntegrationGapSignalCandidate>),
    /// A required observation was never established, so no gap could be
    /// evaluated and the missing coverage is itself the reportable fact.
    SupervisionGap(SupervisionGap),
    /// The rule was applicable and the source projection did not prove a
    /// forward gap.
    NoGap(NoGapReason),
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
/// The rule first proves its own applicability, passing the identity of the
/// very descriptor it later builds its Signal from; the compile-time
/// assertions above make that lookup resolve back to the same entry. An
/// observation that was never projected yields
/// [`IntegrationGapEvaluation::SupervisionGap`], which is the reportable
/// finding: the rule could not be evaluated, and that is never proof that the
/// gap did not occur. A structurally unusable projection yields
/// [`IntegrationGapError`], because a malformed input is not an absence. Only
/// an applicable rule that finds nothing yields
/// [`IntegrationGapEvaluation::NoGap`].
pub fn evaluate_provider_host_event_gap(
    observation: IntegrationGapObservation,
) -> Result<IntegrationGapEvaluation, IntegrationGapError> {
    let rule = provider_host_event_gap_rule();
    match evaluate_rule_applicability(rule.rule_id, &applicability_subject(&observation)) {
        RuleApplicability::Applicable => {}
        RuleApplicability::CoverageGap(gap) => {
            return Ok(IntegrationGapEvaluation::SupervisionGap(gap));
        }
        RuleApplicability::Malformed(malformed) => {
            return Err(IntegrationGapError::MalformedProjection(malformed));
        }
    }
    let skipped_sequence_count = match prove_sequence_gap(&observation) {
        Ok(count) => count,
        Err(reason) => return Ok(IntegrationGapEvaluation::NoGap(reason)),
    };
    let signal = build_signal(&observation).map_err(IntegrationGapError::MalformedSignal)?;

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

/// Projects one provider-gap observation into the shared applicability subject.
///
/// Only the slots the provider rule requires are populated here; the remaining
/// slots stay absent, so a rule that requires them cannot be evaluated from a
/// provider observation by accident.
fn applicability_subject(observation: &IntegrationGapObservation) -> ApplicabilitySubject {
    let context = &observation.signal_context;
    ApplicabilitySubject {
        target: context.target.clone(),
        workspace_instance: None,
        attempt: Some(observation.attempt.0.clone()),
        fence: Some(observation.state_fence.clone()),
        source_event: Some(observation.event.0.clone()),
        interval: None,
        failure_signature: None,
        descendant_lineage: None,
        envelope: None,
        hook_evidence: None,
        canonical_access: None,
        competent_coverage: Some(CoverageRef {
            coverage_id: context.coverage.coverage_id.clone(),
        }),
    }
}

/// Proves the forward skip, or names the check the pair did not satisfy.
///
/// This runs only after the rule is applicable, so every failure here is an
/// ordinary absence rather than a coverage or malformed-input fault.
fn prove_sequence_gap(observation: &IntegrationGapObservation) -> Result<u64, NoGapReason> {
    if observation.signal_context.target.subject_id != observation.attempt.0 {
        return Err(NoGapReason::AttemptMismatch);
    }
    if observation.expected_sequence == 0 {
        return Err(NoGapReason::ZeroExpectedSequence);
    }
    let Some(skipped_sequence_count) = observation
        .observed_sequence
        .checked_sub(observation.expected_sequence)
        .filter(|count| *count > 0)
    else {
        return Err(NoGapReason::InvalidSequenceOrder);
    };
    Ok(skipped_sequence_count)
}

fn build_signal(
    observation: &IntegrationGapObservation,
) -> Result<Signal, crate::signals::SignalValidationError> {
    let rule = provider_host_event_gap_rule();
    let mut identity_fields = vec![
        rule.rule_id.to_owned(),
        rule.revision.to_string(),
        observation.attempt.0.clone(),
        observation.event.0.clone(),
        observation.signal_context.target.scope_id.clone(),
        observation.signal_context.target.generation.to_string(),
        observation.state_fence.authority_lineage_id.clone(),
        observation.state_fence.authority_sequence.to_string(),
        observation.state_fence.resource_generation.to_string(),
    ];
    append_optional_identity(
        &mut identity_fields,
        observation.state_fence.task_revision.as_deref(),
    );
    append_optional_identity(
        &mut identity_fields,
        observation.state_fence.policy_revision.as_deref(),
    );
    append_optional_identity(
        &mut identity_fields,
        observation.state_fence.integration_revision.as_deref(),
    );
    let dedup_key = encode_identity(&identity_fields);
    let signal_id = dedup_key.clone();
    let mut evidence_fields = identity_fields;
    evidence_fields.extend([
        observation.expected_sequence.to_string(),
        observation.observed_sequence.to_string(),
    ]);
    let evidence_id = encode_identity(&evidence_fields);
    Signal::new(SignalRevision {
        signal_id: SignalId(signal_id),
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
        dedup_key: RecordedValue::Known(dedup_key),
        reopen_condition: ReopenCondition::RecurrenceWithNewSourceEvent,
        expected_context_revision: observation.signal_context.expected_context_revision.clone(),
        expected_authority_revision: observation.signal_context.expected_authority_revision.clone(),
    })
}

fn append_optional_identity(fields: &mut Vec<String>, value: Option<&str>) {
    match value {
        Some(value) => {
            fields.push("some".to_owned());
            fields.push(value.to_owned());
        }
        None => fields.push("none".to_owned()),
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
