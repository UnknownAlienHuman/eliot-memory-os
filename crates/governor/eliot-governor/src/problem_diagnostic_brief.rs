//! The Problem Diagnostic Brief (issue #1759 I7; I13.11, A13.10, I16.7).
//!
//! A Diagnostic Brief is a *read model over one canonical Problem record*, not a
//! second Problem model and not an authority. It is compiled from exactly two
//! things, both already owned by someone else:
//!
//! 1. the canonical [`Problem`] record, decoded out of the candidate
//!    `record_json` of a committed `ApplyProblemOwnerState` transition; and
//! 2. the ordered committed transitions of that Problem, read back through the
//!    bounded `GetAttentionAndProblems` attention role
//!    ([`crate::context_inputs`]).
//!
//! Nothing here interprets, re-derives or decides. Every member is projected
//! from a field the record or the read page already carries, and every member
//! the record does *not* carry is reported as an explicit
//! [`ProblemBriefCoverage`] gap or an explicit [`ProblemBriefUnknown`] rather
//! than filled in. A brief can therefore never be a verified explanation, a
//! closure, a promotion or a repair permission:
//!
//! * it reports the record's `hypotheses` in the record's own separate field, so
//!   a candidate explanation can never be read as an observation;
//! * it carries the record's `next_probe` and the I13.8 accountable route, and
//!   nothing that could act as a grant;
//! * it carries the record's `Ownership` verbatim, so an unassigned Problem
//!   still shows its outstanding obligation and its fenced owner.
//!
//! Persistence and ownership stay where they are: this crate prepares and
//! composes, the store commits canonical history, and this brief is rebuilt from
//! that history on every read. It is revision/fence keyed
//! ([`ProblemBriefSource`]) and holds no cached state, so it cannot make state
//! fresh, preserve authority across a generation change, or act as an
//! unreceipted write.
//!
//! Where the two existing `DiagnosticBrief` types are not, deliberately:
//! `eliot_doctor_core::DiagnosticBrief` is a *repair-request input* keyed by
//! recipe selectors, and `bins/eliot-kernel`'s I16.7 brief is compiled from the
//! Kernel's own audit chain and retained in memory. Neither reads the canonical
//! Problem record, so neither can answer a controller or operator read of a
//! named Problem, and neither survives a restart.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_context_candidates::ProjectionState;
use eliot_contracts::{ArtifactId, StateFence};
use eliot_problem::{
    OwnerRoute, Ownership, Problem, ProblemClass, ProblemHypothesis, ProblemId, ProblemState,
    RepairRecord, ReopenRecord, SignalSeverity,
};
use eliot_store_api::{
    PROBLEM_OWNER_STATE_MUTATION_NAME, PROBLEM_PARAM_PROBLEM_ID, ProblemOwnerTransition,
    decode_problem_owner_state_mutation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::context_inputs::RoleAcquisition;

/// Closed required-observation gap codes for a Problem brief.
///
/// I13.11 requires missing coverage to be reported, and A13.10/I16.7 require a
/// brief whose telemetry is insufficient to return the gap *and the exact
/// observation that would close it* rather than a guess. Every code below names
/// something the canonical Problem record and the `GetAttentionAndProblems`
/// page genuinely do not carry; none of them is a placeholder for a value that
/// exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProblemBriefCoverageCode {
    /// The Problem record carries a scope identity and the exact dependencies
    /// it hit, but no task identity, so the affected tasks are unattributed.
    TaskScopeUnattributed,
    /// The Problem record carries no Module identity, so the affected Modules
    /// are unattributed.
    ModuleScopeUnattributed,
    /// The bounded attention read page carries committed Problem transitions
    /// and their evidence handles, but no bounded operational log window, so
    /// the brief points at handles rather than at log ranges.
    LogWindowUnreachable,
    /// The Problem record retains no configuration or module-generation
    /// change, so no change can be correlated with the symptom.
    ConfigurationChangeAbsent,
    /// The Problem record retains no Incident link, so the brief cannot say
    /// whether this Problem was promoted.
    IncidentLinkAbsent,
    /// The attention page was truncated at its declared bound, so the revisions
    /// it returned are a prefix of the Problem's committed history and the
    /// newest one is not established as the head.
    PriorRevisionsTruncated,
}

impl ProblemBriefCoverageCode {
    /// The exact observation that would close this gap.
    #[must_use]
    pub const fn required_observation(self) -> &'static str {
        match self {
            Self::TaskScopeUnattributed => {
                "the task identity this Problem was raised under, recorded on the Problem record"
            }
            Self::ModuleScopeUnattributed => {
                "the Module identity this Problem was raised against, recorded on the Problem record"
            }
            Self::LogWindowUnreachable => {
                "a bounded operational log window for the Problem's source and process generation"
            }
            Self::ConfigurationChangeAbsent => {
                "the configuration or module-generation change correlated with the symptom"
            }
            Self::IncidentLinkAbsent => {
                "the Incident this Problem was promoted to, or the decision that it was not"
            }
            Self::PriorRevisionsTruncated => {
                "a complete attention page for this problem_id, at a bound covering its whole history"
            }
        }
    }
}

/// One required observation the brief could not satisfy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemBriefCoverage {
    /// Closed gap code.
    pub code: ProblemBriefCoverageCode,
    /// The exact observation that would close this gap, always in step with
    /// `code` so a reader is never handed a gap and a mismatched remedy.
    pub required_observation: String,
}

impl ProblemBriefCoverage {
    /// Builds one gap with its required observation kept in step with `code`.
    #[must_use]
    pub fn new(code: ProblemBriefCoverageCode) -> Self {
        Self {
            code,
            required_observation: code.required_observation().to_owned(),
        }
    }
}

/// What is undetermined on the canonical Problem record.
///
/// This is deliberately separate from [`ProblemBriefCoverage`]: a coverage gap is
/// telemetry the record never held, while an unknown is a question the record
/// itself leaves open. Both are closed so a reader can tell "nobody recorded
/// this" apart from "this is not established".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProblemBriefUnknown {
    /// No verified cause. The record retains candidate explanations in
    /// `hypotheses`, which the Problem model keeps separate from
    /// `observed_evidence` precisely so a guess is never counted as an
    /// observation; the brief preserves that separation and therefore cannot
    /// report a cause.
    CauseUndetermined,
    /// The record names the accountable I13.8 route but no eligible successor
    /// holder. Assignment eligibility comes from an externally issued ownership
    /// lease, which the record does not carry and the brief does not invent.
    EligibleSuccessorUnnamed,
}

/// Closed privacy disposition of the evidence a Problem brief points at.
///
/// I7 requires privacy limits to be *carried*, not inferred. Nothing on the
/// canonical Problem record or on the `GetAttentionAndProblems` page classifies
/// the evidence it returns, so the only disposition that exists today is
/// "unestablished". It is modelled as a closed enum with that single arm so a
/// later owner has to add a real classification before a brief can state
/// anything else: there is no way to write "clean" here without inventing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProblemEvidenceVisibility {
    /// No privacy or redaction classification is established for the evidence
    /// this brief points at.
    Unestablished,
}

impl ProblemEvidenceVisibility {
    /// The limit this places on a reader of the referenced evidence handles.
    #[must_use]
    pub const fn read_limit(self) -> &'static str {
        match self {
            Self::Unestablished => {
                "privacy classification unestablished: resolve the classification at the evidence \
                 owner before treating these handles as readable or shareable"
            }
        }
    }
}

/// Privacy limits the brief carries about the evidence it points at.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemBriefPrivacy {
    /// The disposition the record and the read page actually establish.
    pub classification: ProblemEvidenceVisibility,
    /// The limit that disposition places on a reader, always in step with it.
    pub read_limit: String,
}

/// The exact source revision this brief was compiled from.
///
/// Source revisions are carried, never inferred: the revision, the State Fence
/// and the record digest all come from the committed transition the brief was
/// read back through, so a reader can tell which record it is looking at and a
/// brief can never be served for a revision that moved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemBriefSource {
    /// The committed record revision this brief describes.
    pub revision: u64,
    /// The State Fence that record was committed under.
    pub state_fence: StateFence,
    /// Lowercase SHA-256 over the exact canonical bytes of that record. This is
    /// the brief's exact evidence handle for the record itself; the record body
    /// stays in the store.
    pub record_digest: String,
    /// Whether the attention page returned *every* committed transition of this
    /// Problem. When false, `revision` is the newest revision this page
    /// returned and is not established as the head, which the
    /// [`ProblemBriefCoverageCode::PriorRevisionsTruncated`] gap states.
    pub history_complete: bool,
}

/// One committed revision of the Problem, in the order the read page returned it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemBriefRevision {
    /// The closed I13.9 owner-transition wire verb that produced this revision
    /// ([`ProblemOwnerTransition::as_str`]). The verb was resolved through the
    /// closed name table while decoding, so an unknown verb is refused rather
    /// than carried.
    pub transition: String,
    /// The record revision this transition expected to replace, or `None` for
    /// `CREATE`, which replaces no predecessor.
    pub replaced_revision: Option<u64>,
    /// The record revision this transition produced.
    pub revision: u64,
    /// Lowercase SHA-256 over the exact canonical bytes of the record this
    /// transition committed. One digest per committed revision is the brief's
    /// ordered, verifiable handle on the history it reports.
    pub record_digest: String,
}

/// The single next step the brief reports, and what it does not permit.
///
/// A brief is a read model: it reports the record's own next discriminative
/// probe and the I13.8 route accountable for it, and it permits nothing. There
/// is no repair, closure, promotion or authority member here, and one cannot be
/// added without turning the brief into a decision — which is what I13.11's "do
/// not turn raw logs or a model summary into verified explanation" and A13.10's
/// "an elegant report does not prove a transition" forbid.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemBriefNextStep {
    /// The record's own `next_probe`, verbatim.
    pub probe: String,
    /// The I13.8 route accountable for this Problem: the record's own recorded
    /// route while it is unassigned, otherwise the route its class maps to. A
    /// route is a role, never a name, and it carries no lease.
    pub escalation_route: OwnerRoute,
}

/// One compiled Problem Diagnostic Brief (I13.11).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemDiagnosticBrief {
    /// The Problem this brief describes.
    pub problem_id: ProblemId,
    /// I13.9 `class`, which also selects the I13.8 accountable route.
    pub class: ProblemClass,
    /// I13.9 `severity`, taken from the record's admitting Signal.
    pub severity: SignalSeverity,
    /// The committed lifecycle state of the record.
    pub state: ProblemState,
    /// I13.9 `symptom`, verbatim.
    pub symptom: String,
    /// I13.9 `scope`, verbatim.
    pub scope_id: String,
    /// I13.9 `affected_dependencies`: the exact dependencies the Problem hit.
    pub affected_dependencies: Vec<String>,
    /// The committed record this brief was read back through, revision by
    /// revision, in commit order.
    pub timeline: Vec<ProblemBriefRevision>,
    /// I13.9 `evidence`: exactly what the record observed. The record's
    /// hypotheses stay in `hypotheses` and are never merged in here, so no
    /// candidate explanation can be read as an observation.
    pub evidence: Vec<ArtifactId>,
    /// I13.9 `hypotheses`, each with its own supporting evidence and
    /// discriminating probe, kept separate from `evidence` on purpose.
    pub hypotheses: Vec<ProblemHypothesis>,
    /// I13.9 `repair_history`: one retained entry per committed repair, bound to
    /// the revision it was attempted at. Empty is a fact, not a gap.
    pub prior_repairs: Vec<RepairRecord>,
    /// I13.9 `reopen_history`: the retained evidence that the Problem actually
    /// recurred, one entry per reopen revision. This is the evidence a reopen
    /// count alone could never stand in for.
    pub reopens: Vec<ReopenRecord>,
    /// The record's ownership verbatim: a live lease-bound holder, or the
    /// fenced holder, the loss reason and the outstanding reassignment or
    /// escalation obligation.
    pub ownership: Ownership,
    /// What is undetermined on the record itself.
    pub unknowns: Vec<ProblemBriefUnknown>,
    /// Required observations this brief could not satisfy, each with the exact
    /// observation that would close it.
    pub coverage: Vec<ProblemBriefCoverage>,
    /// Privacy limits for the evidence handles in `evidence`.
    pub privacy: ProblemBriefPrivacy,
    /// The next discriminative probe and the accountable escalation route.
    pub next_step: ProblemBriefNextStep,
    /// The source revision this brief was compiled from.
    pub source: ProblemBriefSource,
}

/// Typed refusals of the Problem brief decoder.
///
/// A refusal means the page does not describe a decodable, ordered history of
/// canonical Problem revisions. No partial brief is emitted: a timeline with a
/// hole in it is exactly the "elegant report" A13.10 warns proves nothing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProblemBriefError {
    /// The attention page is not the records array its provenance describes.
    #[error("attention page is not a records array: {0}")]
    PageShape(String),
    /// One committed transition on the page is not a decodable owner-state
    /// mutation for this Problem.
    #[error("committed transition at page position {page_position} is not a decodable problem owner transition: {reason}")]
    TransitionUndecodable {
        /// The page position the decoder stopped at.
        page_position: u64,
        /// Why the transition could not be decoded.
        reason: String,
    },
    /// A committed revision does not replace the revision the page presented
    /// before it, so the page does not describe one Problem's history in commit
    /// order. Reordered, repeated and interleaved pages all land here.
    #[error("committed revision {revision} does not replace the preceding committed revision {replaced}")]
    HistoryBroken {
        /// The revision the page claims to have produced.
        revision: u64,
        /// The revision the preceding transition produced.
        replaced: u64,
    },
}

/// Compiles the Diagnostic Brief for one named Problem from the bounded
/// attention read page.
///
/// `role` is the `GetAttentionAndProblems` acquisition the seven-role
/// reconstruction already performed, and `problem_id` is the exact identity that
/// read was asked for. `Ok(None)` is an honest outcome, not a failure: it means
/// the read produced no committed Problem to describe —
///
/// * the role was not `Complete` (unavailable, stale, unknown, blocked or
///   missing), so no record was read; or
/// * the role was an authoritative `KnownEmpty` for the requested identity, so
///   the source itself states that nothing is committed; or
/// * the page carried no committed owner transition for this identity.
///
/// A page truncated at its declared bound still produces a brief, carrying
/// `history_complete: false` and the
/// [`ProblemBriefCoverageCode::PriorRevisionsTruncated`] gap, because a prefix of
/// a history is still evidence: it is labelled as a prefix rather than presented
/// as the whole history.
pub fn compile_problem_diagnostic_brief(
    role: &RoleAcquisition,
    problem_id: &str,
) -> Result<Option<ProblemDiagnosticBrief>, ProblemBriefError> {
    let history_complete = match &role.state {
        ProjectionState::Complete => true,
        ProjectionState::Partial { .. } => false,
        _ => return Ok(None),
    };
    let Some(payload) = role.payload.as_ref() else {
        return Ok(None);
    };
    let Some(records) = payload.get("records").and_then(Value::as_array) else {
        return Err(ProblemBriefError::PageShape(
            "no records array".to_owned(),
        ));
    };
    let Some(CommittedProblemHistory {
        head: CommittedTransition { problem, revision: head_revision },
        timeline,
    }) = committed_history(records, problem_id)?
    else {
        return Ok(None);
    };
    let ownership = problem.ownership.clone();
    let escalation_route = match &problem.obligation {
        Some(obligation) => obligation.route,
        None => problem.default_owner_route(),
    };
    Ok(Some(ProblemDiagnosticBrief {
        problem_id: problem.problem_id.clone(),
        class: problem.class,
        severity: problem.severity,
        state: problem.state,
        symptom: problem.symptom.clone(),
        scope_id: problem.scope_id.clone(),
        affected_dependencies: problem.affected_dependencies.clone(),
        timeline,
        evidence: observed_evidence(&problem),
        hypotheses: problem.hypotheses.clone(),
        prior_repairs: problem.repair_history.clone(),
        reopens: problem.reopen_history.clone(),
        ownership,
        unknowns: unknowns(&problem),
        coverage: coverage(history_complete),
        privacy: ProblemBriefPrivacy {
            classification: ProblemEvidenceVisibility::Unestablished,
            read_limit: ProblemEvidenceVisibility::Unestablished.read_limit().to_owned(),
        },
        next_step: ProblemBriefNextStep {
            probe: problem.next_probe.clone(),
            escalation_route,
        },
        source: ProblemBriefSource {
            revision: head_revision.revision,
            state_fence: problem.state_fence.clone(),
            record_digest: head_revision.record_digest,
            history_complete,
        },
    }))
}

/// One committed transition: the canonical record and the brief's handle on it.
struct CommittedTransition {
    problem: Problem,
    revision: ProblemBriefRevision,
}

/// The Problem's committed history as the attention page presents it: the newest
/// committed record plus the ordered timeline that led to it.
struct CommittedProblemHistory {
    head: CommittedTransition,
    timeline: Vec<ProblemBriefRevision>,
}

/// Decodes this Problem's committed owner transitions, in the order the page
/// returned them.
///
/// Each page entry is checked to be the `ApplyProblemOwnerState` operation for
/// the requested identity and is then decoded by the store's own
/// [`decode_problem_owner_state_mutation`], which re-proves the transition's
/// four bindings and the candidate record against them before the record is
/// accepted. The record is additionally validated by the Problem model, so a
/// structurally intact but semantically invalid revision is refused here rather
/// than briefed. `None` means the page held no committed transition for this
/// identity.
fn committed_history(
    records: &[Value],
    problem_id: &str,
) -> Result<Option<CommittedProblemHistory>, ProblemBriefError> {
    let mut committed: Vec<CommittedTransition> = Vec::new();
    for (position, record) in records.iter().enumerate() {
        let position = u64::try_from(position).unwrap_or(u64::MAX);
        let Some(parameters) = owner_transition_parameters(record, problem_id) else {
            continue;
        };
        committed.push(decode_history_entry(
            &parameters,
            position,
            committed.last().map(|entry| entry.revision.revision),
        )?);
    }
    let Some(head) = committed.pop() else {
        return Ok(None);
    };
    let timeline = committed
        .into_iter()
        .map(|entry| entry.revision)
        .chain(std::iter::once(head.revision.clone()))
        .collect();
    Ok(Some(CommittedProblemHistory { head, timeline }))
}

/// Decodes one committed transition and checks that it continues the history.
fn decode_history_entry(
    parameters: &BTreeMap<String, Value>,
    page_position: u64,
    preceding_revision: Option<u64>,
) -> Result<CommittedTransition, ProblemBriefError> {
    let undecodable = |reason: String| ProblemBriefError::TransitionUndecodable {
        page_position,
        reason,
    };
    let decoded = decode_problem_owner_state_mutation(parameters)
        .map_err(|error| undecodable(error.to_string()))?;
    let problem: Problem =
        serde_json::from_value(decoded.record_json).map_err(|error| {
            undecodable(format!("candidate record is not a Problem: {error}"))
        })?;
    problem
        .validate()
        .map_err(|error| undecodable(format!("candidate record is not a valid Problem: {error}")))?;
    let replaced_revision = match decoded.transition {
        ProblemOwnerTransition::Create => None,
        _ => Some(decoded.expected_revision),
    };
    // The page must present one Problem's history in commit order, and each
    // revision must replace the one before it. A broken chain means the page
    // does not describe this Problem's history, and an ordered timeline is
    // refused rather than reconstructed from what happens to be there.
    if let (Some(expected), Some(replaced)) = (preceding_revision, replaced_revision)
        && replaced != expected
    {
        return Err(ProblemBriefError::HistoryBroken {
            revision: problem.revision,
            replaced: expected,
        });
    }
    let revision = problem.revision;
    Ok(CommittedTransition {
        problem,
        revision: ProblemBriefRevision {
            transition: decoded.transition.as_str().to_owned(),
            replaced_revision,
            revision,
            record_digest: decoded.record_digest,
        },
    })
}

/// The parameter map of one page entry, when it is this Problem's committed
/// owner transition.
///
/// Entries belonging to another Problem, and entries for any other named
/// operation, are not this brief's history and are skipped: the attention page
/// is a scope-wide committed-operation projection, not a per-Problem one, and
/// its page order is the store's commit order.
fn owner_transition_parameters(
    record: &Value,
    problem_id: &str,
) -> Option<BTreeMap<String, Value>> {
    if record.get("operation").and_then(Value::as_str) != Some(PROBLEM_OWNER_STATE_MUTATION_NAME) {
        return None;
    }
    let parameters = record.get("parameters")?;
    if parameters.get(PROBLEM_PARAM_PROBLEM_ID).and_then(Value::as_str) != Some(problem_id) {
        return None;
    }
    serde_json::from_value(parameters.clone()).ok()
}

/// Merges the exact evidence the record observed, append-only.
///
/// Observations, containment in force, repair evidence and reopen recurrence
/// evidence are all observations the record actually holds. A handle already
/// retained keeps its first position, so the brief never reorders what the
/// record recorded.
fn observed_evidence(problem: &Problem) -> Vec<ArtifactId> {
    let mut merged: Vec<ArtifactId> = Vec::new();
    for handle in problem
        .observed_evidence
        .iter()
        .chain(problem.containment.iter())
        .chain(problem.repair_history.iter().flat_map(|repair| repair.evidence.iter()))
        .chain(problem.reopen_history.iter().flat_map(|reopen| reopen.evidence.iter()))
    {
        if !merged.contains(handle) {
            merged.push(handle.clone());
        }
    }
    merged
}

/// Derives what the record leaves undetermined.
fn unknowns(problem: &Problem) -> Vec<ProblemBriefUnknown> {
    // Always: the record separates hypotheses from observations, so it holds no
    // verified cause and this brief cannot report one.
    let mut open = vec![ProblemBriefUnknown::CauseUndetermined];
    // While unassigned: the record names the accountable route and the fenced
    // holder, never an eligible successor. Assignment eligibility comes from an
    // externally issued ownership lease the record does not carry, so the
    // successor is reported as unnamed rather than guessed.
    if !problem.ownership.is_assigned() {
        open.push(ProblemBriefUnknown::EligibleSuccessorUnnamed);
    }
    open
}

/// Derives the required observations this brief cannot satisfy.
///
/// Every entry is a fact about what the record and the read page hold, not about
/// the problem's subject, and none of them is filled in: a member the record
/// does not carry is named as absent together with the observation that would
/// supply it.
fn coverage(history_complete: bool) -> Vec<ProblemBriefCoverage> {
    let mut gaps = vec![
        // The record's scope identity and affected dependencies are exact, but
        // it carries no task identity, so the affected tasks stay unattributed
        // rather than being inferred from the scope text.
        ProblemBriefCoverage::new(ProblemBriefCoverageCode::TaskScopeUnattributed),
        // Likewise no Module identity, so the affected Modules are unattributed.
        ProblemBriefCoverage::new(ProblemBriefCoverageCode::ModuleScopeUnattributed),
        // The bounded attention page returns committed transitions and their
        // evidence handles. It returns no bounded operational log window, so the
        // brief points at handles and never at log content.
        ProblemBriefCoverage::new(ProblemBriefCoverageCode::LogWindowUnreachable),
        // The record retains no configuration or module-generation change, so
        // there is nothing to correlate with the symptom and no correlation is
        // asserted.
        ProblemBriefCoverage::new(ProblemBriefCoverageCode::ConfigurationChangeAbsent),
        // The record retains no Incident link, so the brief cannot say whether
        // this Problem was promoted.
        ProblemBriefCoverage::new(ProblemBriefCoverageCode::IncidentLinkAbsent),
    ];
    if !history_complete {
        // The page was truncated at its declared bound, so the revisions it
        // returned are a prefix: the newest one is not established as the head.
        gaps.push(ProblemBriefCoverage::new(
            ProblemBriefCoverageCode::PriorRevisionsTruncated,
        ));
    }
    gaps
}
