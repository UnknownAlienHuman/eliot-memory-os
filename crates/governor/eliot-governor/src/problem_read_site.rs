//! The production read site for committed canonical Problem records
//! (issue #1759 I2 readback, I13.9).
//!
//! # The gap this owner closes
//!
//! The nine named owner transitions commit a canonical `Problem` record as the
//! `record_json` member of an `ApplyProblemOwnerState` mutation
//! (`PROBLEM_PARAM_RECORD_JSON`), and the committed-only
//! `GetAttentionAndProblems` named read returns exactly those committed
//! transitions back. Before this module existed, **nothing in production
//! decoded that page into a [`Problem`]**: the read existed, the write existed,
//! and the record that both produced was never turned back into the typed model
//! that owns it. Every consumer of a Problem therefore had to be handed one by a
//! caller, which is the same unattributed-record seam the owner-lease work exists
//! to close.
//!
//! # What this owner does, and what it refuses to do
//!
//! It is a **read model over committed history**, not a second Problem model and
//! not an authority:
//!
//! - every served transition is decoded through the store's own
//!   [`decode_problem_owner_state_mutation`], which re-proves the transition's
//!   four bindings — candidate `record_digest`, `authorization_digest`, expected
//!   record revision and source Signal — against the **original recorded
//!   values** before the record is accepted. Nothing here re-derives a digest to
//!   validate itself and no second binding scheme is introduced;
//! - the candidate is then decoded into [`Problem`] and run through the Problem
//!   model's own [`Problem::validate`], so a structurally intact but semantically
//!   invalid committed revision is refused at the read boundary rather than
//!   served;
//! - the served revisions must form one Problem's **unbroken** history in commit
//!   order, each replacing the revision the transition before it produced. A
//!   page that interleaves, repeats or reorders is refused, because a reader
//!   handed a spliced history would be reading a record that was never committed.
//!
//! # Truncation is reported, never stood in for
//!
//! A page the store truncated at its declared bound is still real evidence, so it
//! is read; but [`ProblemReadback::history_complete`] is then `false` and the
//! reader is told, in the type, that the revision it holds is the newest the page
//! returned and **not** established as the record's head.
//!
//! # Why `None` is an honest outcome
//!
//! `Ok(None)` means the read genuinely established that no committed Problem
//! exists for the requested identity: either no `problem_id` was requested, or
//! the attention role was not readable enough to hold one (`Unavailable`,
//! `Stale`, `Blocked`, `Unknown`, `Missing`), or the page carried no committed
//! owner transition for that identity. It is never a decode failure and never a
//! truncated-away record presented as absence.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_context_candidates::ProjectionState;
use eliot_problem::Problem;
use eliot_store_api::{
    PROBLEM_OWNER_STATE_MUTATION_NAME, PROBLEM_PARAM_PROBLEM_ID, ProblemOwnerTransition,
    decode_problem_owner_state_mutation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::context_inputs::RoleAcquisition;

/// One committed revision of a Problem, in the order the read page returned it.
///
/// Every member is a handle the store already committed: the closed wire verb that
/// produced the revision, the revision it replaced, the revision it produced, and
/// the digest over the exact canonical bytes of the record it committed. A reader
/// can therefore re-verify any revision it is shown against the store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemReadbackRevision {
    /// The closed I13.9 owner-transition wire verb that produced this revision
    /// ([`ProblemOwnerTransition::as_str`]). Resolved through the closed name
    /// table while decoding, so an unknown verb is refused rather than carried.
    pub transition: String,
    /// The record revision this transition expected to replace, or `None` for
    /// `CREATE`, which replaces no predecessor.
    pub replaced_revision: Option<u64>,
    /// The record revision this transition produced.
    pub revision: u64,
    /// Lowercase SHA-256 over the exact canonical bytes of the committed record.
    pub record_digest: String,
}

/// The canonical Problem a bounded committed read resolved to.
///
/// `head` is the newest committed record the page returned for the requested
/// identity. It is the record's head only when [`Self::history_complete`] is
/// `true`; on a truncated page the newest returned revision is a prefix's end and
/// is deliberately not presented as the head.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProblemReadback {
    /// The newest committed canonical record the page returned for the requested
    /// identity. Its own `problem_id`, `revision` and `state_fence` are the
    /// record's, not restatements of the request.
    pub head: Problem,
    /// Every committed revision of that Problem the page returned, in commit
    /// order, genesis first.
    pub timeline: Vec<ProblemReadbackRevision>,
    /// Whether the page returned *every* committed transition of this Problem.
    /// When `false`, [`Self::head`] is the newest revision this page returned and
    /// is not established as the record's head.
    pub history_complete: bool,
}

/// Typed refusals of the committed Problem read site.
///
/// A refusal means the page does not describe a decodable, ordered history of
/// canonical Problem revisions. No partial readback is emitted: a timeline with a
/// hole in it is exactly the "elegant report" that proves nothing.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProblemReadbackError {
    /// The attention page is not the records array its own disposition describes.
    #[error("attention page is not a records array: {0}")]
    PageShape(&'static str),
    /// One committed transition on the page is not a decodable owner-state
    /// mutation, or its candidate record is not a valid canonical Problem.
    #[error(
        "committed transition at page {page_position} is not a decodable Problem record: {reason}"
    )]
    TransitionUndecodable {
        /// The page position the decoder refused at.
        page_position: u64,
        /// Why that transition could not be decoded.
        reason: String,
    },
    /// A committed revision does not replace the revision the page presented
    /// before it, so the page does not describe one Problem's history in commit
    /// order.
    #[error(
        "committed revision {revision} does not replace the preceding committed revision {replaced}"
    )]
    HistoryBroken {
        /// The revision the page claims to have produced.
        revision: u64,
        /// The revision the preceding committed transition produced.
        replaced: u64,
    },
}

/// Reads the committed canonical Problem for one exact identity out of the
/// bounded `GetAttentionAndProblems` attention role.
///
/// `role` is the acquisition the seven-role reconstruction already performed and
/// `problem_id` the exact identity that read was asked for, so this owner adds no
/// read, no store operation and no second Problem model.
///
/// `Ok(None)` is an honest outcome rather than a failure — see the module docs.
/// A page that is readable but does not decode to one Problem's ordered committed
/// history is [`ProblemReadbackError`], never a partial readback.
pub fn read_committed_problem(
    role: &RoleAcquisition,
    problem_id: Option<&str>,
) -> Result<Option<ProblemReadback>, ProblemReadbackError> {
    let Some(problem_id) = problem_id else {
        return Ok(None);
    };
    // A role that was not read to a state that can hold a record holds none.
    // `Complete` returned every matched row and `Partial` returned a bounded
    // prefix of them; both are real evidence, and the second is labelled as a
    // prefix below rather than dropped.
    let history_complete = match &role.state {
        ProjectionState::Complete => true,
        ProjectionState::Partial { .. } => false,
        _ => return Ok(None),
    };
    let Some(payload) = role.payload.as_ref() else {
        return Ok(None);
    };
    let Some(records) = payload.get("records").and_then(Value::as_array) else {
        return Err(ProblemReadbackError::PageShape(
            "page carries no records array",
        ));
    };
    let mut committed: Vec<(Problem, ProblemReadbackRevision)> = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let page_position = u64::try_from(index).unwrap_or(u64::MAX);
        let Some(parameters) = owner_transition_parameters(record, problem_id) else {
            continue;
        };
        let (problem, revision) = decode_history_entry(
            &parameters,
            page_position,
            committed.last().map(|(_, revision)| revision.revision),
        )?;
        committed.push((problem, revision));
    }
    let Some((head, head_revision)) = committed.pop() else {
        return Ok(None);
    };
    let timeline = committed
        .into_iter()
        .map(|(_, revision)| revision)
        .chain(std::iter::once(head_revision))
        .collect();
    Ok(Some(ProblemReadback {
        head,
        timeline,
        history_complete,
    }))
}

/// Decodes one committed transition and checks that it continues the history.
fn decode_history_entry(
    parameters: &BTreeMap<String, Value>,
    page_position: u64,
    preceding_revision: Option<u64>,
) -> Result<(Problem, ProblemReadbackRevision), ProblemReadbackError> {
    let undecodable = |reason: String| ProblemReadbackError::TransitionUndecodable {
        page_position,
        reason,
    };
    let decoded = decode_problem_owner_state_mutation(parameters)
        .map_err(|error| undecodable(error.to_string()))?;
    let problem: Problem = serde_json::from_value(decoded.record_json)
        .map_err(|error| undecodable(format!("committed record is not a Problem: {error}")))?;
    problem
        .validate()
        .map_err(|error| undecodable(format!("committed record is not a valid Problem: {error}")))?;
    let replaced_revision = match decoded.transition {
        ProblemOwnerTransition::Create => None,
        _ => Some(decoded.expected_revision),
    };
    // The page must present one Problem's history in commit order, and every
    // revision after the first must replace the one before it. A broken chain
    // means the page does not describe this Problem's committed history, and a
    // spliced timeline is refused rather than assembled from what is there.
    if let (Some(expected), Some(replaced)) = (preceding_revision, replaced_revision)
        && replaced != expected
    {
        return Err(ProblemReadbackError::HistoryBroken {
            revision: problem.revision,
            replaced: expected,
        });
    }
    let revision = problem.revision;
    Ok((
        problem,
        ProblemReadbackRevision {
            transition: decoded.transition.as_str().to_owned(),
            replaced_revision,
            revision,
            record_digest: decoded.record_digest,
        },
    ))
}

/// The parameter map of one page entry, when it is this Problem's committed owner
/// transition.
///
/// Entries for another Problem and entries of any other named operation are not
/// this readback's history and are skipped: the attention page is a scope-wide
/// committed-operation projection — it carries the pre-existing
/// `ReconcileRecovery` problem leg beside these transitions — and its page order
/// is the store's commit order.
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
